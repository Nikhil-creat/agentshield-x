"""Adaptive human-in-the-loop approval gateway (Slack / Teams / generic webhook).

Zero-trust properties:
* A timeout, a notifier failure, or a missing approver all resolve to **DENY**.
  There is no auto-approve fallback (``hitl_fallback`` can only be ``"deny"``).
* Four-eyes: the approver may not be the requester.
* Decisions arrive through a signed callback (HMAC over ``id:decision``), so a
  forged webhook cannot approve anything.
* Approval is bound to a digest of the exact arguments shown to the human.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ApprovalRequest:
    id: str
    tool: str
    args_preview: dict[str, Any]
    args_digest: str
    risk: float
    requester: str
    reasons: list[str]
    created: float = field(default_factory=time.time)
    expires: float = 0.0


@dataclass(frozen=True)
class ApprovalOutcome:
    status: str  # "approved" | "denied" | "timeout" | "error"
    approver: str = ""
    note: str = ""

    @property
    def approved(self) -> bool:
        return self.status == "approved"


class Notifier(Protocol):
    async def notify(self, req: ApprovalRequest, approve_sig: str, deny_sig: str) -> None: ...


class InMemoryNotifier:
    """Test/dev notifier: records requests so a test can play the human."""

    def __init__(self) -> None:
        self.sent: list[ApprovalRequest] = []

    async def notify(self, req: ApprovalRequest, approve_sig: str, deny_sig: str) -> None:
        self.sent.append(req)


class WebhookNotifier:
    """POSTs a Slack/Teams-compatible message that links to the authenticated review endpoint."""

    def __init__(self, url: str, callback_base: str, timeout_s: float = 3.0) -> None:
        self.url, self.callback_base, self.timeout_s = url, callback_base.rstrip("/"), timeout_s

    def _post(self, body: dict[str, Any]) -> None:
        req = urllib.request.Request(self.url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=self.timeout_s).read()  # noqa: S310 - operator-configured URL

    async def notify(self, req: ApprovalRequest, approve_sig: str, deny_sig: str) -> None:
        # No decision links and no signatures in the message: a chat link is a GET and must never mutate state.
        # The approver opens the review endpoint (authenticated, role=approver) which returns the signed
        # tokens and accepts the decision via POST.
        review = f"{self.callback_base}/v1/hitl/{req.id}"
        text = (f"*AgentShield-X approval needed* — tool `{req.tool}` risk {req.risk:.2f} requested by `{req.requester}`\n"
                f"reasons: {', '.join(req.reasons)}\nargs: `{json.dumps(req.args_preview)[:500]}`\n"
                f"Review & decide: {review} (expires in {int(req.expires - req.created)}s; no response = deny)")
        await asyncio.to_thread(self._post, {"text": text})


class ApprovalGateway:
    def __init__(self, notifier: Notifier, signing_key: bytes | None = None, default_timeout_s: float = 300.0) -> None:
        self._notifier = notifier
        self._key = signing_key or secrets.token_bytes(32)
        self._timeout = default_timeout_s
        self._futures: dict[str, asyncio.Future[ApprovalOutcome]] = {}
        self._requests: dict[str, ApprovalRequest] = {}

    # --- signing ----------------------------------------------------------------
    def sign(self, request_id: str, approve: bool) -> str:
        return hmac.new(self._key, f"{request_id}:{'approve' if approve else 'deny'}".encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def digest_args(args: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()

    # --- lifecycle --------------------------------------------------------------
    @property
    def pending(self) -> int:
        return sum(1 for f in self._futures.values() if not f.done())

    async def open(self, tool: str, args: dict[str, Any], risk: float, requester: str, reasons: list[str],
                   preview: dict[str, Any] | None = None, timeout_s: float | None = None) -> str:
        """Create + notify. Returns the request id immediately (asynchronous gateway)."""
        rid = secrets.token_hex(8)
        req = ApprovalRequest(rid, tool, preview if preview is not None else args, self.digest_args(args), risk, requester, reasons)
        req.expires = req.created + (timeout_s or self._timeout)
        loop = asyncio.get_running_loop()
        self._futures[rid] = loop.create_future()
        self._requests[rid] = req
        try:
            await self._notifier.notify(req, self.sign(rid, True), self.sign(rid, False))
        except Exception as e:  # noqa: BLE001 - cannot reach a human => deny
            self._resolve(rid, ApprovalOutcome("error", note=f"notifier failed: {type(e).__name__}"))
        return rid

    async def wait(self, rid: str, timeout_s: float | None = None) -> ApprovalOutcome:
        fut = self._futures[rid]
        remaining = (timeout_s if timeout_s is not None else max(self._requests[rid].expires - time.time(), 0.0))
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=remaining)
        except asyncio.TimeoutError:
            out = ApprovalOutcome("timeout", note="no human decision; fallback=deny")
            self._resolve(rid, out)
            return out

    async def request(self, tool: str, args: dict[str, Any], risk: float, requester: str, reasons: list[str],
                      preview: dict[str, Any] | None = None, timeout_s: float | None = None) -> ApprovalOutcome:
        rid = await self.open(tool, args, risk, requester, reasons, preview, timeout_s)
        return await self.wait(rid, timeout_s)

    def decide(self, rid: str, approver: str, approve: bool, sig: str) -> ApprovalOutcome:
        """Signed callback handler. Raises ``PermissionError`` on any irregularity."""
        fut, req = self._futures.get(rid), self._requests.get(rid)
        if fut is None or req is None:
            raise PermissionError("unknown request")
        if fut.done():
            raise PermissionError("already resolved")
        if time.time() > req.expires:
            self._resolve(rid, ApprovalOutcome("timeout", note="expired"))
            raise PermissionError("expired")
        if not hmac.compare_digest(sig, self.sign(rid, approve)):
            raise PermissionError("bad signature")
        if approver == req.requester:
            raise PermissionError("requester cannot approve own request (four-eyes)")
        out = ApprovalOutcome("approved" if approve else "denied", approver)
        self._resolve(rid, out)
        return out

    def _resolve(self, rid: str, out: ApprovalOutcome) -> None:
        fut = self._futures.get(rid)
        if fut and not fut.done():
            fut.set_result(out)

    def get(self, rid: str) -> ApprovalRequest | None:
        return self._requests.get(rid)
