"""FastAPI application: the AgentShield-X control plane + guard API.

    uvicorn agentshield.app:app --host 0.0.0.0 --port 8080

Every route except /healthz, /metrics and /v1/identity/* sits behind :class:`AgentShieldMiddleware`
(bearer capability token required). Routes are deliberately thin: all logic lives in
``ShieldPipeline`` so it is identical for HTTP, LangGraph/CrewAI/AutoGen adapters and tests.
"""

from __future__ import annotations

import base64
import binascii
import asyncio
import contextlib
import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import __version__
from .agent_shield_middleware import AgentShieldMiddleware
from .audit_merkle_ledger import JsonlSink, PostgresSink, RedisStreamSink
from .bootstrap import build_pipeline
from .web import HardeningMiddleware, configure_logging
from .hitl import InMemoryNotifier, WebhookNotifier
from .ai_bom import AIBOM
from .config import ShieldSettings
from .console import console_html, recent_entries, stats_payload
from .observability import REGISTRY
from .pipeline import ShieldPipeline
from .redteam import ContinuousRedTeam, run_redteam
from .sandbox_manager import NetworkMode
from .shield_types import TrustLevel, Verdict
from .threat_hunter import RagChunk
from .zk_identity import Entitlement, Principal, SchnorrProof, TokenAuthority, TokenError, ZKIdentityService


class ChallengeOut(BaseModel):
    nonce: str
    audience: str
    ttl_s: int


class TokenIn(BaseModel):
    public_key: str = Field(min_length=130, max_length=130, description="uncompressed secp256k1 point, hex")
    nonce: str = Field(min_length=32, max_length=32)
    scopes: list[str] = Field(max_length=32)
    proof_R: str = Field(min_length=130, max_length=130)
    proof_s: str = Field(min_length=64, max_length=64)


class TextIn(BaseModel):
    text: str = Field(max_length=200_000)
    trust: int = Field(default=TrustLevel.USER.value, ge=0, le=1, description="0=untrusted data, 1=user (2=system is not accepted over HTTP)")
    session_id: str = Field(default="", max_length=64)


class RagChunkIn(BaseModel):
    id: str = Field(max_length=128)
    text: str = Field(max_length=200_000)
    source_uri: str = Field(default="", max_length=512)
    collection: str = Field(default="default", max_length=64)


class RagIn(BaseModel):
    query: str = Field(default="", max_length=2000)
    chunks: list[RagChunkIn] = Field(max_length=256)


class ImageIn(BaseModel):
    image_b64: str = Field(max_length=12_000_000)


class ToolIn(BaseModel):
    tool: str = Field(max_length=64)
    args: dict[str, Any]
    session_id: str = Field(default="", max_length=64)
    user_intent: str | None = Field(default=None, max_length=20_000)
    wait_for_approval: bool = False


class ExecIn(BaseModel):
    code: str = Field(max_length=100_000)
    session_id: str = Field(default="", max_length=64)
    wait_for_approval: bool = False


def create_app(settings: ShieldSettings | None = None, pipeline: ShieldPipeline | None = None,
               authority: TokenAuthority | None = None, identity: ZKIdentityService | None = None) -> FastAPI:
    s = settings or ShieldSettings.from_env()
    configure_logging(os.environ.get("SHIELD_LOG_LEVEL", "INFO"))
    bg: list[Any] = []  # background sink runners started in lifespan
    if pipeline is None:
        sinks: list[Any] = [JsonlSink(s.audit_path)] if s.audit_path else []
        if os.environ.get("SHIELD_DATABASE_URL"):
            pg = PostgresSink(os.environ["SHIELD_DATABASE_URL"])
            sinks.append(pg), bg.append(pg)
        if os.environ.get("SHIELD_REDIS_URL"):
            rs = RedisStreamSink(os.environ["SHIELD_REDIS_URL"])
            sinks.append(rs), bg.append(rs)
        hook = os.environ.get("SHIELD_HITL_WEBHOOK_URL", "")
        notifier = WebhookNotifier(hook, os.environ.get("SHIELD_HITL_CALLBACK_BASE", "http://localhost:8080")) if hook else InMemoryNotifier()
        pipeline, anchor = build_pipeline(s, sinks=sinks, notifier=notifier)
        if anchor is not None:
            bg.append(anchor)
    pipe = pipeline
    auth = authority or TokenAuthority(audience=s.audience, ttl_s=s.token_ttl_s)
    idsvc = identity or ZKIdentityService(auth, s.challenge_ttl_s)
    redteam = ContinuousRedTeam(pipe, interval_s=float(os.environ.get("SHIELD_REDTEAM_INTERVAL_S", "900")))

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        tasks = [asyncio.create_task(sink.run()) for sink in bg]
        if os.environ.get("SHIELD_REDTEAM_BACKGROUND", "1") == "1":
            redteam.start()
        yield
        await redteam.stop()
        for t in tasks:
            t.cancel()

    app = FastAPI(title="AgentShield-X", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(AgentShieldMiddleware, pipeline=pipe, authority=auth, exempt_paths=("/healthz", "/readyz", "/version", "/metrics", "/console"))
    app.add_middleware(HardeningMiddleware)  # outermost: also decorates the shield's own 401/413/429 responses
    app.state.pipeline, app.state.identity, app.state.authority = pipe, idsvc, auth

    def principal(request: Request) -> Principal:
        p = request.scope.get("state", {}).get("shield_principal")
        if p is None:
            raise HTTPException(401, "unauthorized")
        return p

    def require_role(role: str):
        def dep(p: Principal = Depends(principal)) -> Principal:
            if role not in p.roles:
                raise HTTPException(403, f"role '{role}' required")
            return p
        return dep

    # ---------------------------------------------------------------- ops
    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "ledger_entries": pipe.ledger.size, "ocr": pipe.vision.ocr.available, "cnn": pipe.vision.guard.available}

    @app.get("/readyz")
    async def readyz(response: Response) -> dict[str, Any]:
        ready = pipe.ledger.size >= 0 and (pipe.vision.ocr.available or not s.require_ocr)
        if not ready:
            response.status_code = 503
        return {"ready": ready, "ocr": pipe.vision.ocr.available}

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {"name": "agentshield-x", "version": __version__}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(REGISTRY.render(), media_type="text/plain; version=0.0.4")

    # ---------------------------------------------------------------- identity (public)
    @app.post("/v1/identity/challenge", response_model=ChallengeOut)
    async def challenge() -> ChallengeOut:
        return ChallengeOut(nonce=idsvc.issue_challenge(), audience=auth.audience, ttl_s=s.challenge_ttl_s)

    @app.post("/v1/identity/token")
    async def token(body: TokenIn) -> dict[str, Any]:
        try:
            t = idsvc.verify_and_issue(body.public_key, SchnorrProof(body.proof_R, body.proof_s), body.nonce, body.scopes)
        except TokenError as e:
            pipe._audit("identity_denied", "anon", body.public_key.encode(), reason=str(e))
            raise HTTPException(401, str(e)) from e
        p = auth.verify(t)
        pipe._audit("identity_issued", p.subject, t.encode(), scopes=sorted(p.scopes))
        return {"token": t, "subject": p.subject, "expires_in": s.token_ttl_s, "llm_view": p.llm_view()}

    # ---------------------------------------------------------------- guard API
    @app.post("/v1/scan/text")
    async def scan_text(body: TextIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        r = pipe.check_input(body.text, trust=TrustLevel(body.trust), session_id=body.session_id or p.subject, actor=p.subject)
        return {**r.as_dict(), "text": r.text}

    @app.post("/v1/scan/rag")
    async def scan_rag(body: RagIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        chunks = [RagChunk(c.id, c.text, c.source_uri, c.collection) for c in body.chunks]
        out = pipe.check_rag(chunks, body.query, actor=p.subject)
        return {"chunks": [{"id": v.chunk_id, "action": v.action, "score": round(v.score, 4), "text": v.text,
                            "findings": [f.as_dict() for f in v.findings]} for v in out]}

    @app.post("/v1/scan/image")
    async def scan_image(body: ImageIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        try:
            raw = base64.b64decode(body.image_b64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise HTTPException(400, "invalid base64") from e
        rep = await pipe.check_image(raw, actor=p.subject)
        out = rep.as_dict()
        if rep.sanitized_png is not None and rep.verdict is not Verdict.BLOCK:
            out["sanitized_png_b64"] = base64.b64encode(rep.sanitized_png).decode()
        return out

    @app.post("/v1/tools/authorize")
    async def authorize(body: ToolIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        d = await pipe.authorize_tool_call(p, body.tool, body.args, session_id=body.session_id or p.subject,
                                           user_intent=body.user_intent, wait_for_approval=body.wait_for_approval)
        return d.as_dict()

    @app.post("/v1/tools/execute-python")
    async def execute_python(body: ExecIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        dec, res = await pipe.execute_python(p, body.code, session_id=body.session_id or p.subject, wait_for_approval=body.wait_for_approval,
                                             network=NetworkMode.NONE)  # networking is never client-selectable
        out: dict[str, Any] = {"decision": dec.as_dict()}
        if res is not None:
            out["result"] = {"ok": res.ok, "exit_code": res.exit_code, "stdout": res.stdout, "stderr": res.stderr, "timed_out": res.timed_out,
                             "truncated": res.truncated, "refused": res.refused, "reason": res.reason, "duration_s": round(res.duration_s, 3)}
        return out

    # ---------------------------------------------------------------- HITL callback
    @app.get("/v1/hitl/{rid}")
    async def hitl_get(rid: str, p: Principal = Depends(require_role("approver"))) -> dict[str, Any]:
        req = pipe.hitl.get(rid)
        if req is None:
            raise HTTPException(404, "unknown request")
        return {"id": req.id, "tool": req.tool, "args": req.args_preview, "risk": req.risk, "requester": req.requester, "reasons": req.reasons, "expires": req.expires,
                "approve_sig": pipe.hitl.sign(rid, True), "deny_sig": pipe.hitl.sign(rid, False)}

    @app.post("/v1/hitl/{rid}/decision")
    async def hitl_decide(rid: str, approve: bool, sig: str, p: Principal = Depends(require_role("approver"))) -> dict[str, Any]:
        try:
            out = await pipe.resolve_approval(rid, p.subject, approve, sig)
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        return {"status": out.status, "approver": out.approver}

    # ---------------------------------------------------------------- console (static page is public and holds no data)
    @app.get("/console", include_in_schema=False)
    async def console() -> Response:
        html, csp = console_html()
        return Response(html, media_type="text/html; charset=utf-8", headers={
            "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})

    @app.get("/v1/stats")
    async def stats(p: Principal = Depends(require_role("auditor"))) -> dict[str, Any]:
        return stats_payload(pipe)

    @app.get("/v1/ledger/recent")
    async def ledger_recent(n: int = 40, p: Principal = Depends(require_role("auditor"))) -> list[dict[str, Any]]:
        return recent_entries(pipe, n)

    # ---------------------------------------------------------------- audit / compliance
    @app.get("/v1/audit/checkpoint")
    async def checkpoint(p: Principal = Depends(require_role("auditor"))) -> dict[str, Any]:
        cp = pipe.ledger.checkpoint()
        return {"size": cp.size, "root": cp.root, "ts": cp.ts, "signature": cp.signature, "public_key_pem": pipe.ledger.public_key_pem.decode()}

    @app.get("/v1/audit/proof/{seq}")
    async def proof(seq: int, p: Principal = Depends(require_role("auditor"))) -> dict[str, Any]:
        try:
            return pipe.ledger.inclusion_proof(seq)
        except IndexError as e:
            raise HTTPException(404, "no such entry") from e

    @app.get("/v1/aibom")
    async def aibom(p: Principal = Depends(require_role("auditor"))) -> dict[str, Any]:
        bom = AIBOM()
        bom.add_tools(pipe.registry)
        bom.add_python_dependencies(["fastapi", "pydantic", "numpy", "onnxruntime", "pillow", "opencv-python-headless", "cryptography", "starlette", "uvicorn"])
        if s.visual_model_path:
            bom.add_model("visual-guard", s.visual_model_path, version="1")
        return bom.snapshot(pipe.ledger, p.subject)

    @app.post("/v1/redteam/run")
    async def run_rt(p: Principal = Depends(require_role("security"))) -> dict[str, Any]:
        rep = await redteam.run_once()
        return {"detection_rate": rep.detection_rate, "false_positive_rate": rep.fp_rate, "attacks": rep.attacks,
                "by_mutator": rep.by_mutator, "misses": [m.__dict__ for m in rep.misses[:20]], "seed": rep.seed}

    return app


app = create_app()
