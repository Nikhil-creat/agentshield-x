"""ASGI interceptor: zero-trust gate in front of any FastAPI / Starlette agent service.

    app = FastAPI()
    app.add_middleware(AgentShieldMiddleware, pipeline=ShieldPipeline(settings))

Request path (all steps fail closed; nothing reaches the app unless it passes):
  1. Exempt only ``/healthz`` and ``/metrics`` (+ configured public prefixes). Everything else
     requires ``Authorization: Bearer <capability token>`` (see ``zk_identity``) -> 401.
  2. Per-principal token-bucket rate limit -> 429.
  3. Content-Type must be JSON for body-bearing methods -> 415; streaming size cap -> 413.
  4. Every string in the JSON body is run through ``ShieldPipeline.check_input``
     (fields named in ``untrusted_keys`` are scanned as UNTRUSTED data, e.g. RAG chunks).
     BLOCK -> 403 with finding *rules* (never the payload). SANITIZED/normalized strings are
     rewritten in place so the app only ever sees the healed body.
  5. Response bodies of ``application/json`` are scanned for secrets/PII and redacted
     (egress DLP). Streaming/non-JSON responses pass through untouched (documented limit).

Threat score exposed to callers: ``X-Shield-Score`` (max over strings) and ``X-Shield-Verdict``.
The authenticated principal is placed at ``scope["state"]["shield_principal"]`` for downstream use.
"""

from __future__ import annotations

import json
import time
from typing import Any, Awaitable, Callable, Iterable

from .pipeline import ShieldPipeline
from .shield_types import TrustLevel, Verdict
from .signatures import scan_secrets
from .self_heal import remediate
from .zk_identity import Principal, TokenAuthority, TokenError

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class TokenBucket:
    """Per-key token bucket. Memory bounded by ``max_keys`` (oldest evicted)."""

    def __init__(self, per_minute: int, burst: int | None = None, max_keys: int = 50_000) -> None:
        self.rate = per_minute / 60.0
        self.burst = float(burst or per_minute)
        self._b: dict[str, tuple[float, float]] = {}
        self._max = max_keys

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        tokens, last = self._b.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        ok = tokens >= 1.0
        self._b[key] = (tokens - 1.0 if ok else tokens, now)
        if len(self._b) > self._max:
            self._b.pop(next(iter(self._b)))
        return ok


class BodyTooLarge(Exception):
    pass


async def _json_response(send: Send, status: int, body: dict[str, Any], headers: Iterable[tuple[bytes, bytes]] = ()) -> None:
    raw = json.dumps(body, separators=(",", ":")).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode()),
                            (b"cache-control", b"no-store"), *headers]})
    await send({"type": "http.response.body", "body": raw})


class AgentShieldMiddleware:
    def __init__(self, app: Callable[..., Awaitable[None]], *, pipeline: ShieldPipeline, authority: TokenAuthority | None = None,
                 exempt_paths: Iterable[str] = ("/healthz", "/metrics"), public_prefixes: Iterable[str] = ("/v1/identity/",),
                 untrusted_keys: Iterable[str] = ("rag_chunks", "documents", "retrieved", "tool_output", "tool_result", "web_content", "context_docs"),
                 scan_responses: bool = True, rewrite_clean: bool = True, require_auth: bool = True) -> None:
        self.app = app
        self.p = pipeline
        self.authority = authority
        self.exempt = frozenset(exempt_paths)
        self.public_prefixes = tuple(public_prefixes)
        self.untrusted = frozenset(k.lower() for k in untrusted_keys)
        self.scan_responses = scan_responses
        self.rewrite_clean = rewrite_clean
        self.require_auth = require_auth
        self.bucket = TokenBucket(pipeline.s.rate_limit_per_min)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _header(scope: Scope, name: bytes) -> str:
        for k, v in scope["headers"]:
            if k.lower() == name:
                return v.decode("latin-1")
        return ""

    def _authenticate(self, scope: Scope) -> tuple[Principal | None, str | None]:
        if self.authority is None:
            return None, "no token authority configured (deny)"
        auth = self._header(scope, b"authorization")
        if not auth.lower().startswith("bearer "):
            return None, "missing bearer token"
        try:
            return self.authority.verify(auth[7:].strip()), None
        except TokenError as e:
            return None, str(e)

    async def _read_body(self, receive: Receive) -> bytes:
        limit = self.p.s.max_body_bytes
        chunks: list[bytes] = []
        total = 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                raise ConnectionError("client disconnected")
            part = msg.get("body", b"")
            total += len(part)
            if total > limit:
                raise BodyTooLarge
            chunks.append(part)
            if not msg.get("more_body"):
                return b"".join(chunks)

    def _scan_json(self, node: Any, *, untrusted: bool, actor: str, session: str, stats: dict[str, Any], path: str = "$") -> Any:
        """Walk the JSON tree; return the (possibly rewritten) tree. Records worst verdict in ``stats``."""
        if isinstance(node, str):
            if not node.strip():
                return node
            trust = TrustLevel.UNTRUSTED if untrusted else TrustLevel.USER
            r = self.p.check_input(node, trust=trust, session_id=session, actor=actor, source=path, multi_turn=not untrusted)
            stats["score"] = max(stats["score"], r.score)
            if r.verdict is Verdict.BLOCK:
                stats["blocked"] = True
                stats["rules"].update(f.rule for f in r.findings if f.score >= 0.3)
                stats["paths"].append(path)
                return node
            if r.verdict is Verdict.SANITIZED:
                stats["sanitized"] = True
            return r.text if (self.rewrite_clean or r.verdict is Verdict.SANITIZED) else node
        if isinstance(node, dict):
            return {k: self._scan_json(v, untrusted=untrusted or str(k).lower() in self.untrusted, actor=actor, session=session,
                                       stats=stats, path=f"{path}.{k}") for k, v in node.items()}
        if isinstance(node, list):
            return [self._scan_json(v, untrusted=untrusted, actor=actor, session=session, stats=stats, path=f"{path}[{i}]") for i, v in enumerate(node)]
        return node

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":  # not inspectable here: deny rather than bypass
                await send({"type": "websocket.close", "code": 1008})
                return
            await self.app(scope, receive, send)
            return
        path, method = scope["path"], scope["method"].upper()
        if path in self.exempt:
            await self.app(scope, receive, send)
            return

        principal: Principal | None = None
        public = path.startswith(self.public_prefixes)
        if not public and self.require_auth:
            principal, err = self._authenticate(scope)
            if principal is None:
                self.p._audit("auth_denied", "anon", path.encode(), path=path, reason=err or "")
                await _json_response(send, 401, {"error": "unauthorized", "detail": err}, [(b"www-authenticate", b"Bearer")])
                return
        client = (scope.get("client") or ("?", 0))[0]
        key = principal.subject if principal else client
        if not self.bucket.allow(key):
            await _json_response(send, 429, {"error": "rate_limited"}, [(b"retry-after", b"1")])
            return
        actor = principal.subject if principal else f"ip:{client}"
        scope.setdefault("state", {})["shield_principal"] = principal
        scope["state"]["shield_pipeline"] = self.p
        session = self._header(scope, b"x-session-id")[:64] or actor

        stats: dict[str, Any] = {"score": 0.0, "blocked": False, "sanitized": False, "rules": set(), "paths": []}
        replay: Receive = receive
        if method in _BODY_METHODS:
            ctype = self._header(scope, b"content-type").split(";")[0].strip().lower()
            clen = self._header(scope, b"content-length")
            if clen.isdigit() and int(clen) > self.p.s.max_body_bytes:
                await _json_response(send, 413, {"error": "payload_too_large"})
                return
            try:
                raw = await self._read_body(receive)
            except BodyTooLarge:
                await _json_response(send, 413, {"error": "payload_too_large"})
                return
            except ConnectionError:
                return
            if raw:
                if ctype not in ("application/json", "application/ld+json") and not ctype.endswith("+json"):
                    await _json_response(send, 415, {"error": "unsupported_media_type", "detail": "JSON required"})
                    return
                try:
                    doc = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                    await _json_response(send, 400, {"error": "invalid_json"})
                    return
                try:
                    doc = self._scan_json(doc, untrusted=False, actor=actor, session=session, stats=stats)
                except RecursionError:
                    await _json_response(send, 400, {"error": "json_too_deep"})
                    return
                if stats["blocked"]:
                    await _json_response(send, 403, {"error": "blocked_by_agentshield", "score": round(stats["score"], 3),
                                                     "rules": sorted(stats["rules"])[:10], "paths": stats["paths"][:10]},
                                         [(b"x-shield-verdict", b"block"), (b"x-shield-score", f"{stats['score']:.3f}".encode())])
                    return
                raw = json.dumps(doc, separators=(",", ":")).encode()
            sent = False

            async def replay() -> dict[str, Any]:  # type: ignore[no-redef]
                nonlocal sent
                if sent:
                    return await receive()
                sent = True
                return {"type": "http.request", "body": raw, "more_body": False}

            scope = {**scope, "headers": [(k, (str(len(raw)).encode() if k.lower() == b"content-length" else v)) for k, v in scope["headers"]]}

        verdict = b"sanitized" if stats["sanitized"] else b"allow"
        extra = [(b"x-shield-verdict", verdict), (b"x-shield-score", f"{stats['score']:.3f}".encode())]
        await self.app(scope, replay, self._wrap_send(send, extra, actor))

    def _wrap_send(self, send: Send, extra: list[tuple[bytes, bytes]], actor: str) -> Send:
        start: dict[str, Any] | None = None
        buf: list[bytes] = []
        passthrough = False

        async def wrapped(msg: dict[str, Any]) -> None:
            nonlocal start, passthrough
            if msg["type"] == "http.response.start":
                hdrs = dict((k.lower(), v) for k, v in msg.get("headers", []))
                is_json = hdrs.get(b"content-type", b"").split(b";")[0].strip() == b"application/json"
                if not (self.scan_responses and is_json):
                    passthrough = True
                    await send({**msg, "headers": [*msg.get("headers", []), *extra]})
                else:
                    start = msg  # hold until the body is complete so we can redact + fix content-length
                return
            if msg["type"] != "http.response.body" or passthrough:
                await send(msg)
                return
            buf.append(msg.get("body", b""))
            if msg.get("more_body"):
                return
            body = b"".join(buf)
            body, redactions = self._redact_response(body)
            assert start is not None
            headers = [(k, v) for k, v in start.get("headers", []) if k.lower() != b"content-length"]
            headers += [(b"content-length", str(len(body)).encode()), *extra]
            if redactions:
                headers.append((b"x-shield-redactions", str(redactions).encode()))
                self.p._audit("egress_redaction", actor, body, count=redactions)
            await send({**start, "headers": headers})
            await send({"type": "http.response.body", "body": body})

        return wrapped

    def _redact_response(self, body: bytes) -> tuple[bytes, int]:
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body, 0
        count = 0

        def walk(n: Any) -> Any:
            nonlocal count
            if isinstance(n, str):
                fs = scan_secrets(n)
                if fs:
                    out, k = remediate(n, fs)
                    count += k
                    return out
                return n
            if isinstance(n, dict):
                return {k: walk(v) for k, v in n.items()}
            if isinstance(n, list):
                return [walk(v) for v in n]
            return n

        new = walk(doc)
        return (json.dumps(new, separators=(",", ":")).encode(), count) if count else (body, 0)
