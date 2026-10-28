"""ShieldPipeline: the framework-agnostic core that every transport (ASGI middleware,
FastAPI routes, LangGraph/CrewAI/AutoGen adapters) calls.

Responsibilities
----------------
* ``check_input``        normalize -> signatures/secrets -> multi-turn hunters -> self-heal -> verdict
* ``check_rag``          gate retrieved chunks before they reach agent context
* ``check_image``        multi-modal scan (OCR / stego / QR / CNN) + purification
* ``authorize_tool_call`` registry + schema + RBAC/ABAC + hunters + risk + self-heal + HITL
* ``execute_python``     sandboxed code execution (policy-checked first)
* every decision is appended to the Merkle ledger (digests + verdict metadata only).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .audit_merkle_ledger import AuditLedger, JsonlSink
from .config import ShieldSettings
from .hitl import ApprovalGateway, ApprovalOutcome, InMemoryNotifier, Notifier
from .observability import FINDINGS, HITL_OUTCOMES, HITL_PENDING, LEDGER_SIZE, REQUESTS, SANDBOX_RUNS, SCAN_SECONDS
from .policy_engine import PolicyEngine, ToolRegistry, default_registry
from .risk import RiskAssessment, RiskEngine
from .sandbox_manager import NetworkMode, SandboxManager, SandboxResult, make_sandbox_manager
from .self_heal import heal_args, remediate
from .shield_types import Finding, TextScan, ThreatCategory as C, TrustLevel, Verdict, noisy_or
from .signatures import scan_instructions, scan_secrets
from .text_normalizer import normalize
from .threat_hunter import (HuntContext, IntentDivergenceHunter, JailbreakHunter, PrivilegedToolHunter, RagSanitizer, RagChunk,
                            ChunkVerdict, SessionStore, ThreatHuntingOrchestrator, ToolCall, iter_strings)
from .text_classifier import SyncTextClassifier
from .vision_cnn_scanner import VisionReport, VisionScanner
from .zk_identity import Principal


@dataclass
class ToolDecision:
    verdict: Verdict
    risk: RiskAssessment | None
    args: dict[str, Any]  # arguments that may be executed (healed); {} when blocked
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)  # self-healing actions taken
    approval_id: str | None = None
    approver: str = ""
    audit_seq: int = -1

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "risk": round(self.risk.value, 4) if self.risk else None,
                "level": self.risk.level if self.risk else None, "args": self.args, "reasons": self.reasons,
                "actions": self.actions, "approval_id": self.approval_id, "audit_seq": self.audit_seq,
                "findings": [f.as_dict() for f in self.findings]}


def _is_remediated(f: Finding) -> bool:
    """Normalization findings describe what was *already stripped*; they need no further healing."""
    return f.rule.startswith("norm.")


class ShieldPipeline:
    def __init__(self, settings: ShieldSettings | None = None, *, registry: ToolRegistry | None = None,
                 ledger: AuditLedger | None = None, notifier: Notifier | None = None, policy: PolicyEngine | None = None,
                 sandbox: SandboxManager | None = None, vision: VisionScanner | None = None, rag: RagSanitizer | None = None,
                 extra_hunters: list | None = None, approval_key: bytes | None = None,
                 text_classifier: SyncTextClassifier | None = None, require_classifier: bool = False) -> None:
        self.s = settings or ShieldSettings()
        sinks = [JsonlSink(self.s.audit_path)] if self.s.audit_path else []
        self.ledger = ledger or AuditLedger(sinks=sinks)
        self.registry = registry or default_registry()
        self.policy = policy or PolicyEngine(self.registry)
        self.risk = RiskEngine(self.s)
        self.text_clf = text_classifier
        self.require_clf = require_classifier
        self.sessions = SessionStore()
        self.jailbreak = JailbreakHunter(self.sessions)
        self.hunters = ThreatHuntingOrchestrator(
            [IntentDivergenceHunter(), self.jailbreak, PrivilegedToolHunter(), *(extra_hunters or [])], self.s.hunter_timeout_s)
        self.rag = rag or RagSanitizer(self.s)
        self.vision = vision or VisionScanner(self.s)
        self.sandbox = sandbox or make_sandbox_manager(self.s, egress_network=self.s.sandbox_egress_network, egress_proxy=self.s.sandbox_egress_proxy)
        self.notifier = notifier or InMemoryNotifier()
        self.hitl = ApprovalGateway(self.notifier, approval_key, self.s.hitl_timeout_s)

    # ---------------------------------------------------------------- audit helpers
    def _audit(self, kind: str, actor: str, payload: Any, **meta: Any) -> int:
        e = self.ledger.append(kind, actor, payload, meta)
        LEDGER_SIZE.set(self.ledger.size)
        return e.seq

    def _count(self, route: str, verdict: Verdict, findings: list[Finding]) -> None:
        REQUESTS.inc(route, verdict.value)
        for cat in {f.category.value for f in findings}:
            FINDINGS.inc(cat)

    # ---------------------------------------------------------------- text
    def _scan_normalized(self, text: str, trust: TrustLevel, source: str) -> list[Finding]:
        return scan_instructions(text, trust, source=source) + scan_secrets(text, source=source)

    def _classify(self, text: str, source: str) -> list[Finding]:
        """Optional learned-classifier verdict. Unavailable/erroring + ``require_classifier`` => fail closed."""
        if self.text_clf is None:
            return [Finding(C.INTERNAL, "clf.required_missing", 0.95, "no classifier configured", source=source)] if self.require_clf else []
        if not self.text_clf.available:
            return [Finding(C.INTERNAL, "clf.unavailable", 0.95, "classifier model not loaded (fail closed)", source=source)] if self.require_clf else []
        try:
            p = self.text_clf.score_sync(text[:4000])
        except Exception as e:  # noqa: BLE001
            return [Finding(C.INTERNAL, "clf.error", 0.95 if self.require_clf else 0.0, f"{type(e).__name__}", source=source)] if self.require_clf else []
        # classifier evidence is *not* locally rewritable: a flagged paraphrase has no span to cut
        return [Finding(C.DIRECT_INJECTION, "clf.injection", p, f"p={p:.2f}", None, False, source)] if p >= 0.5 else []

    def check_input(self, text: str, *, trust: TrustLevel = TrustLevel.USER, session_id: str = "anon", actor: str = "anon",
                    source: str = "user", multi_turn: bool = True, audit: bool = True) -> TextScan:
        """Full text defence. Returned ``text`` is the only version that may be forwarded."""
        t0 = time.perf_counter()
        norm = normalize(text, max_chars=self.s.max_text_chars, source=source)
        clean = norm.text
        findings: list[Finding] = list(norm.findings)
        findings += self._scan_normalized(clean, trust, source)
        if norm.hidden_text:  # smuggled payloads are never benign: scan as untrusted, spans are *not* usable on `clean`
            hid = scan_instructions(norm.hidden_text, TrustLevel.UNTRUSTED, source=source + ":hidden")
            findings += [Finding(f.category, "hidden." + f.rule, max(f.score, 0.9), f.detail, None, False, f.source) for f in hid]
        findings += self._classify(clean, source)
        if multi_turn and trust >= TrustLevel.USER:
            findings += self.jailbreak.observe(session_id, clean, [f for f in findings if not _is_remediated(f)])

        score = noisy_or(f.score for f in findings)
        verdict, healed = Verdict.ALLOW, False
        if score >= self.s.heal_threshold:
            pending = [f for f in findings if f.score >= 0.3 and not _is_remediated(f)]
            fixable = pending and all(f.rewritable and f.span for f in pending)
            if fixable:
                cleaned, n = remediate(clean, findings)
                recheck = self._scan_normalized(cleaned, trust, source)
                residual = noisy_or(f.score for f in recheck)
                if residual < self.s.heal_threshold and n:
                    clean, healed, verdict = cleaned, True, Verdict.SANITIZED
                    score = max(residual, noisy_or(f.score * 0.5 for f in findings if _is_remediated(f)))
                else:
                    verdict = Verdict.BLOCK
            elif score >= self.s.block_threshold:
                verdict = Verdict.BLOCK
            # medium-risk but not locally fixable: forwarded with findings attached; tool calls stay gated by policy
        if verdict is Verdict.BLOCK:
            clean = ""
        elif trust >= TrustLevel.USER and verdict is not Verdict.BLOCK:
            self.sessions.get(session_id).intent.append(clean)
        scan = TextScan(clean, findings, score, verdict, healed)
        SCAN_SECONDS.observe(time.perf_counter() - t0, "text")
        self._count("input", verdict, findings)
        if audit:
            self._audit("input", actor, text.encode("utf-8", "ignore"),
                        verdict=verdict.value, score=round(score, 3), session=session_id, trust=int(trust),
                        rules=sorted({f.rule for f in findings})[:12])
        return scan

    # ---------------------------------------------------------------- RAG
    def check_rag(self, chunks: list[RagChunk], query: str = "", *, actor: str = "rag", session_id: str = "anon") -> list[ChunkVerdict]:
        t0 = time.perf_counter()
        out = self.rag.inspect_batch(chunks, query)
        SCAN_SECONDS.observe(time.perf_counter() - t0, "rag")
        for ch, v in zip(chunks, out):
            self._count("rag", Verdict.BLOCK if v.action == "quarantined" else Verdict.SANITIZED if v.action == "sanitized" else Verdict.ALLOW, v.findings)
            self._audit("rag_chunk", actor, ch.text.encode("utf-8", "ignore"), chunk=ch.id, action=v.action, score=round(v.score, 3),
                        source=ch.source_uri[:120], session=session_id, rules=sorted({f.rule for f in v.findings})[:8])
        return out

    # ---------------------------------------------------------------- images
    async def check_image(self, data: bytes, *, actor: str = "anon", session_id: str = "anon") -> VisionReport:
        t0 = time.perf_counter()
        rep = await self.vision.scan_async(data)
        SCAN_SECONDS.observe(time.perf_counter() - t0, "image")
        self._count("image", rep.verdict, rep.findings)
        self._audit("image", actor, data, verdict=rep.verdict.value, score=round(rep.score, 3), session=session_id,
                    rules=sorted({f.rule for f in rep.findings})[:12])
        return rep

    # ---------------------------------------------------------------- tools
    def user_intent(self, session_id: str) -> str:
        return "\n".join(self.sessions.get(session_id).intent)

    async def authorize_tool_call(self, principal: Principal | None, tool: str, args: Mapping[str, Any], *, session_id: str = "anon",
                                  user_intent: str | None = None, context: Mapping[str, Any] | None = None,
                                  wait_for_approval: bool = False, approval_timeout_s: float | None = None,
                                  enforce_intent: bool = True) -> ToolDecision:
        """Decide whether an agent-proposed tool call may run, and with which (healed) arguments."""
        t0 = time.perf_counter()
        actor = principal.subject if principal else "anon"
        intent = user_intent if user_intent is not None else self.user_intent(session_id)
        decision = await self._authorize(principal, tool, dict(args), session_id, intent, context or {}, wait_for_approval, approval_timeout_s, enforce_intent)
        decision.audit_seq = self._audit("tool_call", actor, {"tool": tool, "args": dict(args)}, tool=tool, verdict=decision.verdict.value,
                                         risk=round(decision.risk.value, 3) if decision.risk else None, session=session_id,
                                         actions=decision.actions, reasons=decision.reasons[:6], approval=decision.approval_id or "",
                                         rules=sorted({f.rule for f in decision.findings})[:12])
        SCAN_SECONDS.observe(time.perf_counter() - t0, "tool")
        self._count("tool", decision.verdict, decision.findings)
        return decision

    async def _authorize(self, principal, tool, args, session_id, intent, context, wait, timeout, enforce_intent=True) -> ToolDecision:
        pol = await self.policy.evaluate(principal, tool, args, context)
        if not pol.allowed or pol.spec is None:
            return ToolDecision(Verdict.BLOCK, None, {}, pol.findings, pol.reasons)
        spec = pol.spec
        actor = principal.subject if principal else "anon"

        findings: list[Finding] = []
        clean_args: dict[str, Any] = {}
        for path, s in iter_strings(args):
            if path == f"$.{spec.code_param}":
                continue  # code is judged by the sandbox pre-flight (AST), not by prose signatures
            n = normalize(s, max_chars=self.s.max_text_chars, source=f"arg{path}")
            findings += [f for f in n.findings if f.score >= 0.4]
            findings += scan_instructions(n.text, TrustLevel.USER, source=f"arg{path}")
            findings += scan_secrets(n.text, source=f"arg{path}")
        ctx = HuntContext(session_id, principal, intent, ToolCall(tool, args), spec)
        findings += await self.hunters.run(ctx)
        if not enforce_intent:  # e.g. an MCP proxy that cannot observe the user's prompt: intent checks would be noise, not signal
            findings = [f for f in findings if f.category is not C.INTENT_DIVERGENCE]

        risk = self.risk.assess_tool_call(spec, findings)
        reasons = list(risk.reasons)
        if risk.value >= self.s.block_threshold:
            return ToolDecision(Verdict.BLOCK, risk, {}, findings, ["risk above block threshold", *reasons])

        risky = risk.evidence >= self.s.heal_threshold  # evidence, not tool/effect priors, triggers rewriting
        new_args, actions = heal_args(spec, args, risky=risky)
        verdict = Verdict.SANITIZED if actions else Verdict.ALLOW
        dry = bool(spec.dry_run_param and new_args.get(spec.dry_run_param) is True)
        if risk.needs_approval and not (dry and "forced dry-run mode" in actions):
            rid = await self.hitl.open(tool, new_args, risk.value, actor, reasons, timeout_s=timeout)
            HITL_PENDING.set(self.hitl.pending)
            if not wait:
                return ToolDecision(Verdict.PENDING_APPROVAL, risk, new_args, findings, ["human approval required", *reasons], actions, rid)
            out = await self.hitl.wait(rid, timeout)
            return self._after_approval(out, risk, new_args, findings, reasons, actions, rid)
        return ToolDecision(verdict, risk, new_args, findings, reasons, actions)

    def _after_approval(self, out: ApprovalOutcome, risk, args, findings, reasons, actions, rid) -> ToolDecision:
        HITL_OUTCOMES.inc(out.status)
        HITL_PENDING.set(self.hitl.pending)
        if out.approved:
            return ToolDecision(Verdict.ALLOW, risk, args, findings, ["approved by human", *reasons], actions, rid, out.approver)
        return ToolDecision(Verdict.BLOCK, risk, {}, findings, [f"approval {out.status}: {out.note}".strip(), *reasons], actions, rid)

    async def resolve_approval(self, rid: str, approver: str, approve: bool, sig: str) -> ApprovalOutcome:
        """Signed webhook callback entry point. Records the human decision in the ledger."""
        try:
            out = self.hitl.decide(rid, approver, approve, sig)
        except PermissionError as e:
            self._audit("hitl_rejected", approver, rid, request=rid, reason=str(e))
            raise
        HITL_OUTCOMES.inc(out.status)
        HITL_PENDING.set(self.hitl.pending)
        self._audit("hitl_decision", approver, rid, request=rid, status=out.status)
        return out

    # ---------------------------------------------------------------- sandbox
    async def execute_python(self, principal: Principal | None, code: str, *, session_id: str = "anon",
                             user_intent: str | None = None, context: Mapping[str, Any] | None = None,
                             wait_for_approval: bool = False, network: NetworkMode = NetworkMode.NONE) -> tuple[ToolDecision, SandboxResult | None]:
        """Authorize ``run_python`` and, only if allowed, run it in a fresh container."""
        dec = await self.authorize_tool_call(principal, "run_python", {"code": code}, session_id=session_id, user_intent=user_intent,
                                             context=context, wait_for_approval=wait_for_approval)
        if dec.verdict not in (Verdict.ALLOW, Verdict.SANITIZED):
            return dec, None
        res = await self.sandbox.run_python(code, network=network)
        SANDBOX_RUNS.inc("refused" if res.refused else "ok" if res.ok else "timeout" if res.timed_out else "failed")
        self._audit("sandbox_run", principal.subject if principal else "anon", code, ok=res.ok, refused=res.refused, timed_out=res.timed_out,
                    exit=res.exit_code, reason=res.reason[:120], container=res.container, duration=round(res.duration_s, 3))
        return dec, res
