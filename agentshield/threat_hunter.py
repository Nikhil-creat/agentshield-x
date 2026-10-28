"""Autonomous threat-hunting micro-agents and the RAG sanitizer.

Each hunter is a small async evaluator with one job. The orchestrator runs them
concurrently with a per-hunter timeout; a hunter that crashes or times out is
itself reported as a finding (fail closed) rather than silently skipped.

Hunters
-------
IntentDivergenceHunter   user intent vs. planned tool call (effect class, novel
                         recipients/hosts/amounts, weak semantic similarity)
JailbreakHunter          multi-turn: split payloads, escalation, boundary probing,
                         "write a prompt that makes another agent ..." recursion
PrivilegedToolHunter     path traversal, SSRF targets, secrets in args, mass ops,
                         risky code (AST) headed for the sandbox
ClassifierHunter         adapter for any learned classifier (e.g. Prompt-Guard)
RagSanitizer             indirect injection, hidden payloads, entropy and
                         embedding-drift analysis on retrieved chunks
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import zlib
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from math import log2
from typing import Any, Iterable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urlparse

import numpy as np

from .config import ShieldSettings
from .embeddings import Embedder, HashingEmbedder, RunningCentroid, cosine
from .policy_engine import Effect, ToolSpec
from .sandbox_manager import analyze_python
from .self_heal import remediate, spotlight
from .shield_types import Finding, ThreatCategory as C, TrustLevel, noisy_or
from .signatures import scan_instructions, scan_secrets
from .text_normalizer import normalize
from .zk_identity import Principal


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    call_id: str = ""


@dataclass
class HuntContext:
    session_id: str
    principal: Principal | None
    user_intent: str  # concatenated *user-authored* text only (never tool/RAG output)
    tool_call: ToolCall | None = None
    spec: ToolSpec | None = None
    current_turn: str = ""


class Hunter(Protocol):
    name: str

    async def evaluate(self, ctx: HuntContext) -> list[Finding]: ...


def iter_strings(obj: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield (path, string) for every string nested anywhere in ``obj``."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            yield from iter_strings(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from iter_strings(v, f"{path}[{i}]")


# =====================================================================================
# Session memory (multi-step attack tracking)
# =====================================================================================
@dataclass
class SessionState:
    turns: deque[str] = field(default_factory=lambda: deque(maxlen=6))
    turn_rules: deque[frozenset[str]] = field(default_factory=lambda: deque(maxlen=6))  # rules that fired on each single turn
    escalation: float = 0.0
    flagged_turns: int = 0
    intent: deque[str] = field(default_factory=lambda: deque(maxlen=20))  # user-authored text only


class SessionStore:
    """Bounded LRU. Swap for a Redis-backed store when running multiple replicas."""

    def __init__(self, max_sessions: int = 10_000) -> None:
        self._d: OrderedDict[str, SessionState] = OrderedDict()
        self._max = max_sessions

    def get(self, sid: str) -> SessionState:
        st = self._d.get(sid)
        if st is None:
            st = self._d[sid] = SessionState()
            while len(self._d) > self._max:
                self._d.popitem(last=False)
        else:
            self._d.move_to_end(sid)
        return st


# =====================================================================================
# Intent divergence
# =====================================================================================
_EFFECT_LEXICON: dict[Effect, re.Pattern[str]] = {
    Effect.EXTERNAL_COMMS: re.compile(r"\b(?:send|e-?mail|mail|notify|message|share|post|forward|reply|tell|inform|publish|dm)\b", re.I),
    Effect.FINANCIAL: re.compile(r"\b(?:pay|payment|transfer|refund|purchase|buy|invoice|wire|reimburse|remit|deposit|withdraw|charge)\b", re.I),
    Effect.DELETE: re.compile(r"\b(?:delete|remove|drop|erase|purge|discard|wipe|clear|destroy)\b", re.I),
    Effect.EXEC: re.compile(r"\b(?:run|execute|calculate|compute|script|code|python|analy[sz]e|plot|chart|simulate|evaluate)\b", re.I),
    Effect.WRITE: re.compile(r"\b(?:save|create|update|add|write|insert|edit|modify|record|log|store|file|change|open\s+a\s+ticket)\b", re.I),
}
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)
_NUM_RE = re.compile(r"\d[\d,]*(?:\.\d+)?\s*[kKmM]?")


def infer_effects(text: str) -> set[Effect]:
    """Effect classes the *user* plausibly authorised. READ is always implied."""
    out = {Effect.READ}
    for eff, rx in _EFFECT_LEXICON.items():
        if rx.search(text):
            out.add(eff)
    return out


def _numbers(text: str) -> set[float]:
    vals: set[float] = set()
    for m in _NUM_RE.finditer(text):
        raw = m.group(0).strip().replace(",", "")
        mult = 1.0
        if raw and raw[-1] in "kK":
            mult, raw = 1e3, raw[:-1]
        elif raw and raw[-1] in "mM":
            mult, raw = 1e6, raw[:-1]
        try:
            vals.add(float(raw) * mult)
        except ValueError:
            pass
    return vals


class IntentDivergenceHunter:
    name = "intent_divergence"

    def __init__(self, embedder: Embedder | None = None) -> None:
        self.embedder = embedder or HashingEmbedder()

    async def evaluate(self, ctx: HuntContext) -> list[Finding]:
        if ctx.tool_call is None or ctx.spec is None:
            return []
        spec, call, intent = ctx.spec, ctx.tool_call, ctx.user_intent
        out: list[Finding] = []
        low = intent.lower()
        allowed = infer_effects(intent)
        if spec.effect not in allowed:
            sc = 0.55 if spec.effect is Effect.WRITE else 0.80
            out.append(Finding(C.INTENT_DIVERGENCE, "intent.effect_not_requested", sc,
                               f"tool effect '{spec.effect.value}' not implied by user request", source=self.name))
        novel: list[str] = []
        for _, s in iter_strings(call.args):
            for e in _EMAIL_RE.findall(s):
                if e.lower() not in low:
                    novel.append(e)
            for u in _URL_RE.findall(s):
                host = (urlparse(u).hostname or "").lower()
                if host and host not in low:
                    novel.append(u)
        if novel:
            out.append(Finding(C.INTENT_DIVERGENCE, "intent.novel_target", min(0.5 + 0.1 * len(novel), 0.85),
                               f"target(s) never mentioned by user: {novel[:3]}", source=self.name))
        amount = call.args.get("amount")
        if isinstance(amount, (int, float)) and not isinstance(amount, bool) and spec.effect is Effect.FINANCIAL:
            if not any(abs(amount - n) < 0.01 for n in _numbers(intent)):
                out.append(Finding(C.INTENT_DIVERGENCE, "intent.novel_amount", 0.6,
                                   "amount does not appear in user request", source=self.name))
        if spec.effect is not Effect.READ:
            action = f"{spec.name} {spec.description} " + " ".join(v for _, v in iter_strings(call.args))[:500]
            sim = cosine(self.embedder.embed(intent), self.embedder.embed(action))
            if sim < 0.03:
                out.append(Finding(C.INTENT_DIVERGENCE, "intent.low_similarity", 0.25,
                                   f"cosine(intent, action)={sim:.3f}", source=self.name))
        return out


# =====================================================================================
# Multi-step jailbreak / context poisoning
# =====================================================================================
_PROBE_RE = re.compile(
    r"\b(?:hypothetically|in\s+theory|for\s+a\s+(?:story|novel|movie|game)|let'?s\s+play\s+a\s+game|role-?play|pretend|imagine\s+you\s+(?:are|were|have)"
    r"|thought\s+experiment|purely\s+academic|for\s+research\s+purposes|no\s+one\s+will\s+know|just\s+this\s+once|you\s+can\s+trust\s+me"
    r"|i\s+am\s+(?:your|the)\s+(?:developer|admin|administrator|creator|owner)|i\s+have\s+(?:root|admin)\s+(?:access|permission)s?"
    r"|authorized\s+by|this\s+is\s+an\s+emergency)\b", re.I)
_RECURSIVE_RE = re.compile(
    r"\b(?:write|generate|create|craft|draft)\s+(?:me\s+)?(?:a|an|the)\s+(?:prompt|instruction|message)\s+(?:that|which|to)\s+(?:makes?|tell|instruct|force|cause|get)\s+(?:the\s+|another\s+|a\s+)?(?:ai|assistant|model|agent|llm|chatbot)"
    r"|\b(?:tell|instruct|ask|command|order)\s+(?:the\s+|your\s+|another\s+|all\s+)?(?:other\s+|sub-?|child\s+|downstream\s+)?(?:agents?|assistants?|models?)\s+to\s+(?:ignore|bypass|disable|override|disregard|reveal|forward|send)", re.I)


class JailbreakHunter:
    name = "jailbreak"

    def __init__(self, store: SessionStore | None = None, decay: float = 0.8) -> None:
        self.store = store or SessionStore()
        self.decay = decay

    def observe(self, session_id: str, turn: str, current: Sequence[Finding]) -> list[Finding]:
        """Ingest one *user* turn (already normalized). Returns multi-step findings."""
        st = self.store.get(session_id)
        out: list[Finding] = []
        base = noisy_or(f.score for f in current)
        probes = len(_PROBE_RE.findall(turn))
        bump = base + 0.15 * probes
        if _RECURSIVE_RE.search(turn):
            out.append(Finding(C.JAILBREAK, "jb.recursive_prompt", 0.60, "asks for prompts/agents that override rules", source=self.name))
            bump += 0.6
        if st.turns:  # payload splitting: scan the joined recent turns
            joined = " ".join([*st.turns, turn])
            joined_hits = {f.rule for f in scan_instructions(joined, TrustLevel.USER)}
            single_hits = {f.rule for f in current}
            prior = set().union(*st.turn_rules) if st.turn_rules else set()
            split = joined_hits - single_hits - prior  # only rules that exist *solely* in the concatenation
            if split:
                out.append(Finding(C.JAILBREAK, "jb.split_payload", 0.88,
                                   f"instruction assembled across turns: {sorted(split)[:2]}", source=self.name))
                bump += 0.88
        st.escalation = st.escalation * self.decay + bump
        st.turns.append(turn)
        st.turn_rules.append(frozenset(f.rule for f in scan_instructions(turn, TrustLevel.USER)))
        if bump >= 0.35:
            st.flagged_turns += 1
        if st.escalation >= 1.2 and st.flagged_turns >= 2:
            out.append(Finding(C.JAILBREAK, "jb.multi_step_escalation", min(0.5 + 0.1 * st.escalation, 0.9),
                               f"session escalation={st.escalation:.2f} over {st.flagged_turns} flagged turns", source=self.name))
        return out

    async def evaluate(self, ctx: HuntContext) -> list[Finding]:
        st = self.store.get(ctx.session_id)
        if st.escalation >= 0.6 and ctx.spec is not None and ctx.spec.effect is not Effect.READ:
            return [Finding(C.JAILBREAK, "jb.suspicious_session", min(0.3 + 0.2 * st.escalation, 0.85),
                            f"side-effecting tool requested in session with escalation={st.escalation:.2f}", source=self.name)]
        return []


# =====================================================================================
# Privileged tool invocation
# =====================================================================================
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[\\/])(?:etc[\\/](?:passwd|shadow|sudoers)|proc[\\/]|sys[\\/]|root[\\/]|\.ssh[\\/]|\.aws[\\/]|\.env\b|id_rsa|\.git[\\/]config|var[\\/]run[\\/]docker\.sock)", re.I)
_TRAVERSAL_RE = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)|%2e%2e|\.\.%2f", re.I)
_INTERNAL_HOSTS = re.compile(r"^(?:localhost|.*\.localhost|.*\.internal|.*\.local|instance-data|metadata\.google\.internal|kubernetes\.default.*)$", re.I)
_MASS_RE = re.compile(r"(?:\bwhere\s+1\s*=\s*1\b|\bdelete\s+from\s+\w+\s*;?\s*$|^\s*\*\s*$|^\s*all\s*$)", re.I)


def ssrf_reason(url: str) -> str | None:
    """Return a reason if the URL's host is internal/metadata/loopback/odd-encoded."""
    host = (urlparse(url).hostname or "").strip("[]")
    if not host:
        return None
    if _INTERNAL_HOSTS.match(host):
        return f"internal hostname '{host}'"
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(int(host, 0))  # decimal / hex integer form
        except ValueError:
            if re.fullmatch(r"[0-9a-fx.]+", host, re.I) and re.search(r"\d", host):
                return f"obfuscated IP literal '{host}'"
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return f"non-public address {ip}"
    return None


class PrivilegedToolHunter:
    name = "privileged_tool"

    async def evaluate(self, ctx: HuntContext) -> list[Finding]:
        if ctx.tool_call is None or ctx.spec is None:
            return []
        spec, call = ctx.spec, ctx.tool_call
        out: list[Finding] = []
        for path, s in iter_strings(call.args):
            if path == f"$.{spec.code_param}":
                for f in analyze_python(s):
                    out.append(Finding(f.category, f.rule, f.score, f.detail, source=self.name))
                continue
            if _TRAVERSAL_RE.search(s) or _SENSITIVE_PATH_RE.search(s):
                out.append(Finding(C.PRIVILEGE, "priv.sensitive_path", 0.85, f"{path}: sensitive path / traversal", source=self.name))
            for u in _URL_RE.findall(s):
                why = ssrf_reason(u)
                if why:
                    out.append(Finding(C.PRIVILEGE, "priv.ssrf", 0.9, f"{path}: {why}", source=self.name))
            if _MASS_RE.search(s) and spec.effect in (Effect.DELETE, Effect.WRITE):
                out.append(Finding(C.PRIVILEGE, "priv.mass_operation", 0.7, f"{path}: wildcard/mass operation", source=self.name))
            for f in scan_secrets(s):
                out.append(Finding(C.SECRET_LEAK, "priv.secret_in_args", 0.9, f"{path}: {f.detail}", source=self.name))
        return out


class TextClassifier(Protocol):
    async def score(self, text: str) -> float: ...


class ClassifierHunter:
    """Adapter for a learned injection classifier. Scores >= 0.5 become findings."""

    name = "classifier"

    def __init__(self, clf: TextClassifier) -> None:
        self.clf = clf

    async def evaluate(self, ctx: HuntContext) -> list[Finding]:
        if ctx.tool_call is None:
            return []
        text = " ".join(v for _, v in iter_strings(ctx.tool_call.args))[:4000]
        sc = await self.clf.score(text)
        return [Finding(C.DIRECT_INJECTION, "clf.injection", sc, "classifier verdict", source=self.name)] if sc >= 0.5 else []


# =====================================================================================
# Orchestrator
# =====================================================================================
class ThreatHuntingOrchestrator:
    def __init__(self, hunters: Sequence[Hunter], timeout_s: float = 0.25) -> None:
        self.hunters = list(hunters)
        self.timeout_s = timeout_s

    async def _one(self, h: Hunter, ctx: HuntContext) -> list[Finding]:
        try:
            return await asyncio.wait_for(h.evaluate(ctx), self.timeout_s)
        except asyncio.TimeoutError:
            return [Finding(C.INTERNAL, f"hunter.timeout.{h.name}", 0.6, "hunter exceeded time budget (fail closed)", source=h.name)]
        except Exception as e:  # noqa: BLE001
            return [Finding(C.INTERNAL, f"hunter.error.{h.name}", 0.6, f"{type(e).__name__} (fail closed)", source=h.name)]

    async def run(self, ctx: HuntContext) -> list[Finding]:
        results = await asyncio.gather(*(self._one(h, ctx) for h in self.hunters))
        return [f for r in results for f in r]


# =====================================================================================
# RAG sanitizer
# =====================================================================================
def shannon_entropy(s: str) -> float:
    """Bits per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * log2(c / n) for c in counts.values())


@dataclass
class RagChunk:
    id: str
    text: str
    source_uri: str = ""
    collection: str = "default"
    embedding: Sequence[float] | None = None


@dataclass
class ChunkVerdict:
    chunk_id: str
    action: str  # "pass" | "sanitized" | "quarantined"
    text: str  # spotlighted, safe-to-forward text ("" when quarantined)
    score: float
    findings: list[Finding] = field(default_factory=list)
    drift_z: float = 0.0
    relevance: float = 0.0


class RagSanitizer:
    """Gate between the vector store and the agent context.

    ``semantic entropy`` here is a cheap *proxy* (character entropy, compressibility,
    whitespace density). For true semantic entropy (sampling-based) plug a model into
    a :class:`ClassifierHunter`. Embedding drift is measured per collection against a
    running centroid that only learns from chunks that passed every check.
    """

    def __init__(self, settings: ShieldSettings, embedder: Embedder | None = None, trusted_sources: Iterable[str] = ()) -> None:
        self.s = settings
        self.embedder = embedder or HashingEmbedder()
        self.trusted = frozenset(trusted_sources)
        self._centroids: dict[str, RunningCentroid] = {}

    def _centroid(self, collection: str) -> RunningCentroid:
        c = self._centroids.get(collection)
        if c is None:
            c = self._centroids[collection] = RunningCentroid(self.embedder.dim)
        return c

    def _statistical(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        if len(text) >= 200:
            ent = shannon_entropy(text)
            ws = sum(c.isspace() for c in text) / len(text)
            if ent > 5.2:
                out.append(Finding(C.ENCODED_PAYLOAD, "rag.high_entropy", 0.45, f"entropy={ent:.2f} bits/char", source="rag"))
            elif ws < 0.03:
                out.append(Finding(C.ENCODED_PAYLOAD, "rag.dense_blob", 0.40, f"whitespace ratio {ws:.3f}", source="rag"))
        if len(text) >= 400:
            ratio = len(zlib.compress(text.encode("utf-8", "ignore"))) / max(len(text.encode("utf-8", "ignore")), 1)
            if ratio < 0.15:
                out.append(Finding(C.CONTEXT_POISONING, "rag.repetition_stuffing", 0.35, f"compression ratio {ratio:.2f}", source="rag"))
        if text:
            npr = sum(not (c.isprintable() or c in "\n\t\r") for c in text) / len(text)
            if npr > 0.1:
                out.append(Finding(C.ENCODED_PAYLOAD, "rag.non_printable", 0.5, f"{npr:.0%} non-printable", source="rag"))
        return out

    def _analyze(self, text: str, hidden: str, norm_findings: list[Finding], src: str) -> list[Finding]:
        findings = list(norm_findings)
        findings += scan_instructions(text, TrustLevel.UNTRUSTED, source=src)
        findings += scan_secrets(text, source=src)
        findings += self._statistical(text)
        if hidden:
            hits = scan_instructions(hidden, TrustLevel.UNTRUSTED, source=src)
            if hits:
                findings.append(Finding(C.INDIRECT_INJECTION, "rag.hidden_instruction", 0.95,
                                        f"hidden payload contains instructions: {hidden[:60]!r}", source=src))
        return findings

    def inspect(self, chunk: RagChunk, query: str = "") -> ChunkVerdict:
        src = f"rag:{chunk.id}"
        norm = normalize(chunk.text, max_chars=self.s.max_text_chars, source=src)
        text = norm.text
        findings = self._analyze(text, norm.hidden_text, norm.findings, src)
        if self.trusted and chunk.source_uri and not any(chunk.source_uri.startswith(t) for t in self.trusted):
            findings.append(Finding(C.CONTEXT_POISONING, "rag.untrusted_source", 0.2, chunk.source_uri[:120], source=src))

        vec = np.asarray(chunk.embedding, dtype=np.float32) if chunk.embedding is not None else self.embedder.embed(text[:4000])
        cen = self._centroid(chunk.collection)
        z = cen.zscore(vec) if vec.shape[0] == self.embedder.dim else 0.0
        if z > 3.5:
            findings.append(Finding(C.VECTOR_DRIFT, "vector.drift", min(0.3 + 0.1 * (z - 3.5), 0.7), f"z={z:.1f} from collection centroid", source=src))
        rel = cosine(self.embedder.embed(query), vec) if query and vec.shape[0] == self.embedder.dim else 0.0

        score = noisy_or(f.score for f in findings)
        action = "pass"
        if score >= self.s.heal_threshold:
            heavy = [f for f in findings if f.score >= self.s.heal_threshold]
            if all(f.rewritable and f.span for f in heavy) and score < 1.0:
                cleaned, _ = remediate(text, findings)
                re_findings = self._analyze(cleaned, "", [], src)
                re_score = noisy_or(f.score for f in re_findings)
                if re_score < self.s.heal_threshold:
                    text, action, score = cleaned, "sanitized", re_score
                else:
                    action = "quarantined"
            elif score >= self.s.block_threshold:
                action = "quarantined"
        if action == "quarantined" or (score >= self.s.block_threshold and action == "pass"):
            return ChunkVerdict(chunk.id, "quarantined", "", score, findings, z, rel)
        if action == "pass" and score < self.s.heal_threshold and vec.shape[0] == self.embedder.dim:
            cen.update(vec)  # learn only from clean chunks
        return ChunkVerdict(chunk.id, action, spotlight(text, chunk.source_uri or chunk.collection, chunk.id), score, findings, z, rel)

    def inspect_batch(self, chunks: Sequence[RagChunk], query: str = "") -> list[ChunkVerdict]:
        out: list[ChunkVerdict] = []
        for i, ch in enumerate(chunks):
            if i >= self.s.max_rag_chunks:
                out.append(ChunkVerdict(ch.id, "quarantined", "", 1.0,
                                        [Finding(C.RESOURCE, "rag.too_many_chunks", 1.0, "chunk cap exceeded", source="rag")]))
            else:
                out.append(self.inspect(ch, query))
        return out
