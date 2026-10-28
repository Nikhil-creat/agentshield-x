"""Framework-agnostic adapters: put AgentShield-X in front of *any* agent framework's tools, LLM calls and retrievers.

LangGraph / CrewAI / AutoGen / plain function-calling all reduce to three seams, and these wrappers sit on each:

    shield = Shield(pipeline, principal, session_id="s1")

    @shield.tool("search_docs")           # authorize (schema+RBAC/ABAC+risk+HITL) -> run -> scan result as untrusted data
    async def search_docs(query: str) -> str: ...

    llm = shield.guard_llm(raw_llm)        # scan the prompt (block/heal), redact secrets from the completion
    retrieve = shield.guard_retriever(r)   # spotlight + sanitize every chunk before it can reach the context window

The wrappers import no framework, so they work with all of them: pass the wrapped callable wherever the framework
expects a tool/function (e.g. a LangGraph ``ToolNode`` entry or a CrewAI ``@tool``). Tested here against plain callables;
the thin glue for each framework's own tool class is intentionally left to the application.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Awaitable, Callable

from .pipeline import ShieldPipeline, ToolDecision
from .shield_types import TrustLevel, Verdict
from .signatures import scan_secrets
from .self_heal import remediate
from .threat_hunter import RagChunk
from .zk_identity import Principal


class Denied(Exception):
    """Raised when a call is blocked. Carries the decision so callers can show reasons / the approval id."""

    def __init__(self, what: str, decision: ToolDecision | None = None, reasons: list[str] | None = None) -> None:
        self.decision = decision
        self.reasons = reasons or (decision.reasons if decision else [])
        super().__init__(f"{what} denied by AgentShield-X: {'; '.join(self.reasons[:3])}")


class Shield:
    def __init__(self, pipeline: ShieldPipeline, principal: Principal, *, session_id: str = "default", enforce_intent: bool = True,
                 wait_for_approval: bool = True, approval_timeout_s: float | None = None) -> None:
        self.p, self.principal, self.session = pipeline, principal, session_id
        self.enforce_intent, self.wait, self.timeout = enforce_intent, wait_for_approval, approval_timeout_s

    # ---------------------------------------------------------------- user turns
    def observe_user(self, text: str) -> str:
        """Scan a user turn (also records the user's intent for later divergence checks). Returns the safe text."""
        r = self.p.check_input(text, session_id=self.session, actor=self.principal.subject)
        if r.verdict is Verdict.BLOCK:
            raise Denied("input", reasons=[f.rule for f in r.findings if f.score >= 0.5][:3])
        return r.text

    # ---------------------------------------------------------------- tools
    def _sanitize_result(self, value: Any, source: str) -> Any:
        if isinstance(value, str):
            r = self.p.check_input(value, trust=TrustLevel.UNTRUSTED, session_id=self.session + ":tool", actor=self.principal.subject,
                                   source=source, multi_turn=False)
            if r.verdict is Verdict.BLOCK:
                return "[AgentShield-X] tool output withheld: it contained instruction-like or unsafe content."
            return r.text
        if isinstance(value, dict):
            return {k: self._sanitize_result(v, f"{source}.{k}") for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._sanitize_result(v, f"{source}[{i}]") for i, v in enumerate(value)]
        return value

    def tool(self, name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator. Arguments are taken from the call's keyword arguments (positional args are mapped by signature)."""

        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            sig = inspect.signature(fn)

            async def authorize(args: tuple, kwargs: dict) -> dict[str, Any]:
                bound = sig.bind_partial(*args, **kwargs)
                call_args = dict(bound.arguments)
                dec = await self.p.authorize_tool_call(self.principal, tool_name, call_args, session_id=self.session, enforce_intent=self.enforce_intent,
                                                       wait_for_approval=self.wait, approval_timeout_s=self.timeout)
                if dec.verdict not in (Verdict.ALLOW, Verdict.SANITIZED):
                    raise Denied(f"tool '{tool_name}'", dec)
                return dec.args  # healed arguments (unknown keys dropped, values clamped, dry-run forced...)

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def awrapper(*args: Any, **kwargs: Any) -> Any:
                    safe = await authorize(args, kwargs)
                    return self._sanitize_result(await fn(**safe), f"tool:{tool_name}")
                return awrapper

            @functools.wraps(fn)
            def swrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    safe = asyncio.run(authorize(args, kwargs))
                    return self._sanitize_result(fn(**safe), f"tool:{tool_name}")
                raise RuntimeError(f"'{tool_name}' is a sync tool called from a running event loop; make it `async def` or call it from a worker thread")
            return swrapper
        return deco

    # ---------------------------------------------------------------- LLM
    def guard_llm(self, llm: Callable[[str], Any]) -> Callable[[str], Any]:
        """Wrap ``llm(prompt) -> str`` (sync or async). Prompt is scanned (and healed); secrets are redacted from the reply."""

        def redact(text: Any) -> Any:
            if not isinstance(text, str):
                return text
            fs = scan_secrets(text)
            return remediate(text, fs)[0] if fs else text

        if inspect.iscoroutinefunction(llm):
            @functools.wraps(llm)
            async def aw(prompt: str, *a: Any, **k: Any) -> Any:
                return redact(await llm(self.observe_user(prompt), *a, **k))
            return aw

        @functools.wraps(llm)
        def sw(prompt: str, *a: Any, **k: Any) -> Any:
            return redact(llm(self.observe_user(prompt), *a, **k))
        return sw

    # ---------------------------------------------------------------- RAG
    def guard_retriever(self, retrieve: Callable[..., Any], *, collection: str = "default") -> Callable[..., Awaitable[list[str]]] | Callable[..., list[str]]:
        """Wrap ``retrieve(query) -> list[str | {"text":..., "id":..., "source":...}]``; returns spotlighted, sanitized chunks only."""

        def process(query: str, raw: list[Any]) -> list[str]:
            chunks = []
            for i, c in enumerate(raw):
                if isinstance(c, str):
                    chunks.append(RagChunk(str(i), c, collection=collection))
                else:
                    chunks.append(RagChunk(str(c.get("id", i)), str(c.get("text", "")), str(c.get("source", "")), collection))
            verdicts = self.p.check_rag(chunks, query, actor=self.principal.subject, session_id=self.session)
            return [v.text for v in verdicts if v.action != "quarantined"]

        if inspect.iscoroutinefunction(retrieve):
            @functools.wraps(retrieve)
            async def aw(query: str, *a: Any, **k: Any) -> list[str]:
                return process(query, await retrieve(query, *a, **k))
            return aw

        @functools.wraps(retrieve)
        def sw(query: str, *a: Any, **k: Any) -> list[str]:
            return process(query, retrieve(query, *a, **k))
        return sw
