"""HTTP hardening shared by every response: security headers, request IDs and structured JSON logs.

Pure-ASGI (no framework dependency), so it wraps the shield middleware and also decorates its 401/413/429 responses.
Existing headers set by a route (for example the console's Content-Security-Policy) are never overridden.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import uuid
from typing import Any, Awaitable, Callable, Iterable

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

_RID_OK = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

DEFAULT_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
)
# API responses are never cacheable; the console sets its own Cache-Control.
API_CACHE = (b"cache-control", b"no-store")


class HardeningMiddleware:
    """Adds security headers + ``X-Request-ID`` and emits one structured log line per request (never bodies or credentials)."""

    def __init__(self, app: Callable[..., Awaitable[None]], *, logger: logging.Logger | None = None, extra_headers: Iterable[tuple[bytes, bytes]] = ()) -> None:
        self.app = app
        self.log = logger or logging.getLogger("agentshield.access")
        self.headers = DEFAULT_HEADERS + tuple(extra_headers)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = next((v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"x-request-id" and _RID_OK.match(v.decode("latin-1"))), None) or uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        t0, status = time.perf_counter(), 0

        async def send_wrapped(msg: dict[str, Any]) -> None:
            nonlocal status
            if msg["type"] == "http.response.start":
                status = msg["status"]
                have = {k.lower() for k, _ in msg.get("headers", [])}
                hdrs = list(msg.get("headers", []))
                for k, v in self.headers + (API_CACHE,):
                    if k not in have:
                        if k == b"cache-control" and not scope["path"].startswith("/v1/"):
                            continue
                        hdrs.append((k, v))
                hdrs.append((b"x-request-id", rid.encode()))
                msg = {**msg, "headers": hdrs}
            await send(msg)

        try:
            await self.app(scope, receive, send_wrapped)
        finally:
            self.log.info("request", extra={"fields": {"request_id": rid, "method": scope["method"], "path": scope["path"], "status": status,
                                                         "ms": round((time.perf_counter() - t0) * 1000, 2)}})


class JsonFormatter(logging.Formatter):
    """One JSON object per line (stdout), ready for Loki / CloudWatch / ELK. Only whitelisted ``fields`` are emitted."""

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {"ts": round(record.created, 3), "level": record.levelname.lower(), "logger": record.name, "msg": record.getMessage()}
        doc.update(getattr(record, "fields", {}) or {})
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info).splitlines()[-1]  # type + message only; no locals or payloads
        return json.dumps(doc, separators=(",", ":"), default=str)


def configure_logging(level: str = "INFO") -> None:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root = logging.getLogger("agentshield")
    root.handlers[:] = [h]
    root.setLevel(level.upper())
    root.propagate = False
