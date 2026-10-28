"""MCP (Model Context Protocol) guard: a policy-enforcing stdio proxy between an agent and an MCP server.

Threats handled (all documented MCP attack classes):
  tool poisoning     instructions hidden in tool names/descriptions/parameter descriptions  -> tool dropped/healed
  rug pull           a tool's description/schema changes after first approval                -> tool dropped until re-pinned
  unauthorized tools tools not in the registry are never shown to the model (deny-by-default)
  malicious results  injection / secrets in ``tools/call`` / ``resources/read`` results       -> healed or replaced by an error
  confused deputy    every ``tools/call`` passes schema + RBAC/ABAC + risk + HITL            -> JSON-RPC error if denied
  server-initiated   ``sampling/*`` and ``elicitation/*`` requests from the server are denied (they let a server steer the
                     client's LLM or phish the user); configurable via ``allow_server_requests``

Transport: newline-delimited JSON-RPC 2.0 (MCP stdio transport). Batches are handled; oversized lines are dropped.
Every decision is recorded in the Merkle ledger by the underlying pipeline.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .pipeline import ShieldPipeline
from .shield_types import Finding, ThreatCategory as C, TrustLevel, Verdict
from .zk_identity import Principal

ERR_BLOCKED = -32001
ERR_METHOD = -32601
ERR_PARSE = -32700
CLIENT_METHODS = frozenset({"initialize", "ping", "tools/list", "tools/call", "resources/list", "resources/templates/list",
                            "resources/read", "prompts/list", "prompts/get", "completion/complete", "logging/setLevel"})
SERVER_REQUESTS_DENIED = frozenset({"sampling/createMessage", "elicitation/create"})
MAX_LINE = 2_000_000


def _canon(o: Any) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def tool_fingerprint(tool: dict[str, Any]) -> str:
    """Hash of everything the model can read about a tool (what a rug pull would change)."""
    return hashlib.sha256(_canon({k: tool.get(k) for k in ("name", "description", "inputSchema", "annotations")})).hexdigest()


class PinStore:
    """Trust-on-first-use pins of tool fingerprints. ``approve`` re-pins after a human reviews a change."""

    def __init__(self, pins: dict[str, str] | None = None) -> None:
        self.pins: dict[str, str] = dict(pins or {})

    def check(self, name: str, fp: str) -> str:
        """Return 'new' (pinned now), 'ok', or 'changed'."""
        old = self.pins.get(name)
        if old is None:
            self.pins[name] = fp
            return "new"
        return "ok" if old == fp else "changed"

    def approve(self, name: str, fp: str) -> None:
        self.pins[name] = fp

    def dumps(self) -> str:
        return json.dumps(self.pins, sort_keys=True, indent=2)

    @classmethod
    def loads(cls, s: str) -> "PinStore":
        return cls(json.loads(s))


@dataclass
class GuardReport:
    dropped: dict[str, str] = field(default_factory=dict)  # tool -> reason
    healed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _walk_strings(node: Any, path: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_strings(v, f"{path}[{i}]")


def _rewrite(node: Any, fn: Callable[[str, str], str], path: str = "$") -> Any:
    if isinstance(node, str):
        return fn(path, node)
    if isinstance(node, dict):
        return {k: _rewrite(v, fn, f"{path}.{k}") for k, v in node.items()}
    if isinstance(node, list):
        return [_rewrite(v, fn, f"{path}[{i}]") for i, v in enumerate(node)]
    return node


class McpGuard:
    def __init__(self, pipeline: ShieldPipeline, principal: Principal, *, session_id: str = "mcp", pins: PinStore | None = None,
                 allow_server_requests: Iterable[str] = (), wait_for_approval: bool = True, approval_timeout_s: float | None = None,
                 strict_metadata: bool = True) -> None:
        """``strict_metadata``: drop a tool whose name/description/schema had *any* instruction-like content (a legitimate
        tool description has none), instead of merely stripping it. Tool-poisoning authors should not get a second try."""
        self.p, self.principal, self.session = pipeline, principal, session_id
        self.pins = pins or PinStore()
        self.allow_server = frozenset(allow_server_requests)
        self.wait, self.timeout = wait_for_approval, approval_timeout_s
        self.strict = strict_metadata
        self._pending: dict[Any, tuple[str, dict[str, Any]]] = {}  # request id -> (method, params)
        self.last_report = GuardReport()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _error(mid: Any, code: int, msg: str, data: Any = None) -> dict[str, Any]:
        e: dict[str, Any] = {"code": code, "message": msg}
        if data is not None:
            e["data"] = data
        return {"jsonrpc": "2.0", "id": mid, "error": e}

    def _audit(self, kind: str, payload: Any, **meta: Any) -> None:
        self.p._audit(kind, self.principal.subject, json.dumps(payload, default=str).encode(), session=self.session, **meta)

    # ------------------------------------------------------------------ client -> server
    async def on_client(self, msg: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Returns (message_to_forward_to_server | None, reply_to_send_back_to_client | None)."""
        method, mid = msg.get("method"), msg.get("id")
        if method is None:  # a response to a server-initiated request: pass through (those requests were vetted in on_server)
            return msg, None
        if method.startswith("notifications/"):
            return msg, None
        if method not in CLIENT_METHODS:
            self._audit("mcp_denied", {"method": method}, reason="method not allowed")
            return None, (self._error(mid, ERR_METHOD, f"method '{method}' is not allowed by AgentShield-X") if mid is not None else None)
        params = msg.get("params") or {}
        if method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(args, dict):
                return None, self._error(mid, -32602, "invalid params")
            dec = await self.p.authorize_tool_call(self.principal, name, args, session_id=self.session, enforce_intent=False,
                                                   wait_for_approval=self.wait, approval_timeout_s=self.timeout)
            if dec.verdict not in (Verdict.ALLOW, Verdict.SANITIZED):
                return None, self._error(mid, ERR_BLOCKED, "blocked by AgentShield-X", {"verdict": dec.verdict.value, "reasons": dec.reasons[:4],
                                                                                          "approval_id": dec.approval_id, "audit_seq": dec.audit_seq})
            msg = {**msg, "params": {**params, "arguments": dec.args}}
        if mid is not None:
            self._pending[mid] = (method, params)
        return msg, None

    # ------------------------------------------------------------------ server -> client
    async def on_server(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Returns the (possibly rewritten) message for the client, or None to drop it."""
        if "method" in msg:  # server-initiated request / notification
            if msg["method"] in SERVER_REQUESTS_DENIED and msg["method"] not in self.allow_server:
                self._audit("mcp_denied", {"method": msg["method"]}, reason="server-initiated request denied")
                return None
            return msg
        mid = msg.get("id")
        method, params = self._pending.pop(mid, ("", {}))
        if "result" not in msg:
            return msg
        if method == "tools/list":
            return {**msg, "result": self._filter_tools(msg["result"])}
        if method in ("tools/call", "resources/read", "prompts/get"):
            return await self._filter_result(msg, method)
        return msg

    def _filter_tools(self, result: dict[str, Any]) -> dict[str, Any]:
        rep = GuardReport()
        keep: list[dict[str, Any]] = []
        for tool in result.get("tools", []):
            name = tool.get("name", "")
            if self.p.registry.get(name) is None:
                rep.dropped[name] = "not in registry (deny-by-default)"
                continue
            fp = tool_fingerprint(tool)
            state = self.pins.check(name, fp)
            if state == "changed":
                rep.dropped[name] = "definition changed since it was pinned (possible rug pull); re-approve to use"
                self._audit("mcp_rug_pull", {"tool": name}, tool=name)
                continue
            blocked = False

            def heal(path: str, text: str) -> str:
                nonlocal blocked
                r = self.p.check_input(text, trust=TrustLevel.UNTRUSTED, session_id=self.session + ":tools", actor="mcp:tool-desc",
                                       source=f"mcp:{name}{path}", multi_turn=False)
                if r.verdict is Verdict.BLOCK or (self.strict and r.verdict is Verdict.SANITIZED):
                    blocked = True
                    return text
                if r.verdict is Verdict.SANITIZED:
                    rep.healed.append(f"{name}{path}")
                return r.text
            clean = _rewrite({k: v for k, v in tool.items() if k in ("name", "description", "inputSchema", "annotations", "title")}, heal)
            if blocked:
                rep.dropped[name] = "poisoned tool metadata (instructions hidden in description/schema)"
                self._audit("mcp_tool_poisoning", {"tool": name}, tool=name)
                continue
            others = [n for n in self.p.registry.names() if n != name and n in json.dumps(clean.get("description", ""))]
            if others:
                rep.warnings.append(f"{name}: description references other tools {others} (shadowing risk)")
            keep.append({**tool, **clean})
        self.last_report = rep
        if rep.dropped or rep.healed:
            self._audit("mcp_tools_filtered", {"dropped": rep.dropped, "healed": rep.healed}, dropped=len(rep.dropped), healed=len(rep.healed))
        return {**result, "tools": keep}

    async def _filter_result(self, msg: dict[str, Any], method: str) -> dict[str, Any]:
        result = msg["result"]
        blocked: list[str] = []

        def heal(path: str, text: str) -> str:
            r = self.p.check_input(text, trust=TrustLevel.UNTRUSTED, session_id=self.session + ":results", actor="mcp:result",
                                   source=f"mcp:{method}{path}", multi_turn=False)
            if r.verdict is Verdict.BLOCK:
                blocked.append(path)
                return ""
            return r.text
        scanned = {k: (_rewrite(v, heal, f"$.{k}") if k in ("content", "contents", "messages", "structuredContent") else v) for k, v in result.items()}
        # images embedded in results get the full multi-modal scan
        import base64, binascii
        for blk in (scanned.get("content") or []) if isinstance(scanned.get("content"), list) else []:
            if isinstance(blk, dict) and blk.get("type") == "image" and isinstance(blk.get("data"), str):
                try:
                    rep = await self.p.check_image(base64.b64decode(blk["data"], validate=True), actor="mcp:result", session_id=self.session)
                except (binascii.Error, ValueError):
                    blocked.append("$.content[image]")
                    blk["data"] = ""
                    continue
                if rep.verdict is Verdict.BLOCK or rep.sanitized_png is None:
                    blocked.append("$.content[image]")
                    blk["data"], blk["mimeType"] = "", "text/plain"
                else:
                    blk["data"], blk["mimeType"] = base64.b64encode(rep.sanitized_png).decode(), "image/png"
        if blocked:
            self._audit("mcp_result_blocked", {"method": method, "paths": blocked}, paths=blocked[:6])
            return {**msg, "result": {"content": [{"type": "text", "text": "[AgentShield-X] tool output withheld: it contained instruction-like or unsafe content."}], "isError": True}}
        return {**msg, "result": scanned}


# ---------------------------------------------------------------------- stdio proxy
async def _readlines(stream: asyncio.StreamReader):
    while True:
        try:
            line = await stream.readuntil(b"\n")
        except asyncio.LimitOverrunError as e:
            await stream.readexactly(e.consumed)  # drop the oversized chunk
            continue
        except asyncio.IncompleteReadError as e:
            if e.partial.strip():
                yield e.partial
            return
        yield line


async def run_stdio_proxy(guard: McpGuard, server_cmd: list[str], *, client_in: asyncio.StreamReader, client_out: Any = None) -> int:
    """Spawn ``server_cmd`` and relay JSON-RPC both ways through ``guard``. ``client_out`` needs ``write``/``flush`` (default stdout)."""
    out = client_out or sys.stdout.buffer
    lock = asyncio.Lock()

    async def emit(m: Any) -> None:
        async with lock:
            out.write(json.dumps(m, separators=(",", ":")).encode() + b"\n")
            out.flush()

    proc = await asyncio.create_subprocess_exec(*server_cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, limit=MAX_LINE)
    assert proc.stdin and proc.stdout

    async def to_server(m: Any) -> None:
        proc.stdin.write(json.dumps(m, separators=(",", ":")).encode() + b"\n")  # type: ignore[union-attr]
        await proc.stdin.drain()  # type: ignore[union-attr]

    async def parse(line: bytes) -> list[Any] | None:
        if len(line) > MAX_LINE:
            return None
        try:
            doc = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return None
        return doc if isinstance(doc, list) else [doc]

    async def client_loop() -> None:
        async for line in _readlines(client_in):
            msgs = await parse(line)
            if msgs is None:
                await emit(guard._error(None, ERR_PARSE, "parse error"))
                continue
            for m in msgs:
                if not isinstance(m, dict):
                    continue
                fwd, reply = await guard.on_client(m)
                if reply:
                    await emit(reply)
                if fwd:
                    await to_server(fwd)
        proc.stdin.close()  # type: ignore[union-attr]

    async def server_loop() -> None:
        async for line in _readlines(proc.stdout):  # type: ignore[arg-type]
            msgs = await parse(line)
            for m in msgs or []:
                if isinstance(m, dict):
                    r = await guard.on_server(m)
                    if r is not None:
                        await emit(r)

    await asyncio.gather(client_loop(), server_loop())
    return await proc.wait()
