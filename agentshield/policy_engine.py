"""RBAC + ABAC policy enforcement with a deny-by-default tool registry.

Evaluation order (any failing step => DENY, first denial wins):
  1. Tool must be registered (unknown tool => deny).
  2. Arguments must validate against the tool's JSON-schema subset
     (unknown properties are rejected; ``additionalProperties`` defaults to False).
  3. RBAC: principal must hold the tool's capability scope and an allowed role.
  4. ABAC: declarative rules, deny-overrides, over principal/tool/args/context attributes.
  5. Egress allow-list for URL/e-mail parameters.
  6. Optional OPA (Rego) decision; any OPA error => deny.
"""

from __future__ import annotations

import asyncio
import enum
import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlparse

from .shield_types import Finding, ThreatCategory
from .zk_identity import Principal


class Effect(str, enum.Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXTERNAL_COMMS = "external_comms"
    FINANCIAL = "financial"
    EXEC = "exec"


ALWAYS_APPROVE = frozenset({Effect.DELETE, Effect.EXTERNAL_COMMS, Effect.FINANCIAL, Effect.EXEC})
EFFECT_RISK = {
    Effect.READ: 0.0, Effect.WRITE: 0.30, Effect.DELETE: 0.55,
    Effect.EXTERNAL_COMMS: 0.55, Effect.FINANCIAL: 0.60, Effect.EXEC: 0.50,
}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    schema: Mapping[str, Any]
    effect: Effect
    required_scope: str
    allowed_roles: frozenset[str] = frozenset()  # empty => any role holding the scope
    base_risk: float = 0.05
    requires_approval: bool | None = None  # None => derived from effect
    dry_run_param: str | None = None  # boolean arg that makes the call side-effect free
    clamps: Mapping[str, tuple[float, float]] = field(default_factory=dict)
    url_params: frozenset[str] = frozenset()  # args holding URLs / e-mail addresses
    egress_allowlist: frozenset[str] = frozenset()  # allowed hosts / e-mail domains
    code_param: str | None = None  # arg holding code to execute (routes to sandbox)

    @property
    def needs_approval(self) -> bool:
        return self.requires_approval if self.requires_approval is not None else self.effect in ALWAYS_APPROVE


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)


def default_registry() -> ToolRegistry:
    """Reference tool set. Real deployments register their own tools explicitly."""
    r = ToolRegistry()
    r.register(ToolSpec(
        "search_docs", "Search internal documents", {
            "type": "object", "required": ["query"],
            "properties": {"query": {"type": "string", "maxLength": 500}, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}},
        Effect.READ, "tools.search", clamps={"limit": (1, 50)}))
    r.register(ToolSpec(
        "db_query", "Read-only SQL query", {
            "type": "object", "required": ["sql"],
            "properties": {"sql": {"type": "string", "maxLength": 2000, "pattern": r"(?is)^\s*select\b[^;]*;?\s*$"}}},
        Effect.READ, "tools.db.read", base_risk=0.10))
    r.register(ToolSpec(
        "db_write", "Insert/update a record", {
            "type": "object", "required": ["table", "values"],
            "properties": {"table": {"type": "string", "enum": ["notes", "tickets", "tasks"]},
                           "values": {"type": "object", "additionalProperties": True}, "dry_run": {"type": "boolean"}}},
        Effect.WRITE, "tools.db.write", frozenset({"editor", "admin"}), base_risk=0.30,
        requires_approval=True, dry_run_param="dry_run"))
    r.register(ToolSpec(
        "send_email", "Send an e-mail", {
            "type": "object", "required": ["to", "subject", "body"],
            "properties": {"to": {"type": "string", "maxLength": 254}, "subject": {"type": "string", "maxLength": 200},
                           "body": {"type": "string", "maxLength": 10000}}},
        Effect.EXTERNAL_COMMS, "tools.email.send", base_risk=0.20,
        url_params=frozenset({"to"}), egress_allowlist=frozenset({"example.com", "corp.example"})))
    r.register(ToolSpec(
        "transfer_funds", "Move money between accounts", {
            "type": "object", "required": ["from_account", "to_account", "amount"],
            "properties": {"from_account": {"type": "string", "pattern": r"^[A-Z0-9-]{6,34}$"},
                           "to_account": {"type": "string", "pattern": r"^[A-Z0-9-]{6,34}$"},
                           "amount": {"type": "number", "minimum": 0.01, "maximum": 1_000_000}}},
        Effect.FINANCIAL, "tools.finance.transfer", frozenset({"finance", "admin"}), base_risk=0.40))
    r.register(ToolSpec(
        "delete_record", "Delete a record", {
            "type": "object", "required": ["table", "id"],
            "properties": {"table": {"type": "string", "enum": ["notes", "tickets", "tasks"]}, "id": {"type": "integer", "minimum": 1}}},
        Effect.DELETE, "tools.db.delete", frozenset({"admin"}), base_risk=0.30))
    r.register(ToolSpec(
        "run_python", "Run Python in the ephemeral sandbox", {
            "type": "object", "required": ["code"],
            "properties": {"code": {"type": "string", "maxLength": 20000}}},
        Effect.EXEC, "tools.exec.python", base_risk=0.20, code_param="code"))
    return r


# --------------------------------------------------------------------------------------
# Minimal JSON-schema validator (type/required/properties/additionalProperties/enum/
# min/max/maxLength/minLength/pattern/items). Deliberately small and strict.
# --------------------------------------------------------------------------------------
_TYPES = {
    "string": str, "boolean": bool, "object": dict, "array": list,
}


def validate_schema(value: Any, schema: Mapping[str, Any], path: str = "$") -> list[str]:
    errs: list[str] = []
    t = schema.get("type")
    if t == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return [f"{path}: expected integer"]
    elif t == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return [f"{path}: expected number"]
    elif t in _TYPES and not isinstance(value, _TYPES[t]):
        return [f"{path}: expected {t}"]
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: not in enum")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path}: above maximum")
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append(f"{path}: too long")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path}: too short")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path}: pattern mismatch")
    if t == "object" and isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errs.append(f"{path}.{req}: required")
        for k, v in value.items():
            if k in props:
                errs += validate_schema(v, props[k], f"{path}.{k}")
            elif not schema.get("additionalProperties", False):
                errs.append(f"{path}.{k}: unknown property")
    if t == "array" and isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            errs += validate_schema(v, schema["items"], f"{path}[{i}]")
    return errs


# --------------------------------------------------------------------------------------
# ABAC
# --------------------------------------------------------------------------------------
def _resolve(path: str, ctx: Mapping[str, Any]) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


_OPS = {
    "eq": lambda a, b: a == b, "ne": lambda a, b: a != b,
    "in": lambda a, b: a in b, "not_in": lambda a, b: a not in b,
    "lt": lambda a, b: a is not None and a < b, "lte": lambda a, b: a is not None and a <= b,
    "gt": lambda a, b: a is not None and a > b, "gte": lambda a, b: a is not None and a >= b,
    "exists": lambda a, b: (a is not None) == bool(b),
    "matches": lambda a, b: isinstance(a, str) and re.search(b, a) is not None,
    "contains": lambda a, b: a is not None and b in a,
}


@dataclass(frozen=True)
class AbacRule:
    """``deny`` rules fire when *all* conditions hold. (Allow is granted by RBAC.)"""

    id: str
    when: tuple[tuple[str, str, Any], ...]  # (path, op, value) ; value may be {"$ref": "path"}
    reason: str

    def fires(self, ctx: Mapping[str, Any]) -> bool:
        for path, op, val in self.when:
            if isinstance(val, dict) and "$ref" in val:
                val = _resolve(val["$ref"], ctx)
            try:
                if not _OPS[op](_resolve(path, ctx), val):
                    return False
            except TypeError:
                return False  # incomparable => condition not met (rule does not fire)
        return True


DEFAULT_ABAC_RULES: tuple[AbacRule, ...] = (
    AbacRule("fin.limit",
             (("tool.effect", "eq", "financial"), ("args.amount", "gt", 10_000), ("principal.attrs.finance_limit_ok", "ne", True)),
             "transfers over 10,000 require finance_limit_ok attribute"),
    AbacRule("fin.self", (("tool.effect", "eq", "financial"), ("args.from_account", "eq", {"$ref": "args.to_account"})),
             "source and destination accounts must differ"),
    AbacRule("exec.clearance", (("tool.effect", "eq", "exec"), ("principal.attrs.clearance", "lt", 1)),
             "code execution requires clearance >= 1"),
    AbacRule("prod.offhours", (("context.env", "eq", "prod"), ("tool.effect", "in", ["delete", "financial"]), ("context.hour_utc", "lt", 6)),
             "destructive/financial actions are blocked 00:00-06:00 UTC in prod"),
    AbacRule("tenant.mismatch", (("principal.attrs.tenant", "exists", True), ("args.tenant", "exists", True), ("args.tenant", "ne", {"$ref": "principal.attrs.tenant"})),
             "cross-tenant access"),
)


@dataclass
class PolicyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    spec: ToolSpec | None = None
    findings: list[Finding] = field(default_factory=list)


_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+)$")


def host_allowed(value: str, allow: frozenset[str]) -> bool:
    """True if URL host / e-mail domain equals or is a subdomain of an allow-list entry."""
    m = _EMAIL_RE.match(value)
    host = (m.group(1) if m else (urlparse(value).hostname or "")).lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allow)


class OpaClient:
    """Fail-closed client for an OPA sidecar (``POST /v1/data/<path>``)."""

    def __init__(self, base_url: str, path: str = "agentshield/authz/allow", timeout_s: float = 0.2) -> None:
        self.url = f"{base_url.rstrip('/')}/v1/data/{path}"
        self.timeout_s = timeout_s

    def _post(self, payload: dict[str, Any]) -> bool:
        req = urllib.request.Request(self.url, json.dumps({"input": payload}).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310 - operator-configured URL
            return json.load(resp).get("result") is True

    async def allow(self, payload: dict[str, Any]) -> bool:
        try:
            return await asyncio.to_thread(self._post, payload)
        except Exception:  # noqa: BLE001 - any failure denies
            return False


class PolicyEngine:
    def __init__(self, registry: ToolRegistry, rules: tuple[AbacRule, ...] = DEFAULT_ABAC_RULES, opa: OpaClient | None = None) -> None:
        self.registry = registry
        self.rules = rules
        self.opa = opa

    def _deny(self, spec: ToolSpec | None, reason: str) -> PolicyDecision:
        return PolicyDecision(False, [reason], spec, [Finding(ThreatCategory.POLICY, "policy.deny", 1.0, reason)])

    async def evaluate(self, principal: Principal | None, tool: str, args: Mapping[str, Any], context: Mapping[str, Any] | None = None) -> PolicyDecision:
        if principal is None:
            return self._deny(None, "unauthenticated")
        spec = self.registry.get(tool)
        if spec is None:
            return self._deny(None, f"tool '{tool}' is not registered")
        errs = validate_schema(dict(args), spec.schema)
        if errs:
            return self._deny(spec, "schema: " + "; ".join(errs[:5]))
        if spec.required_scope not in principal.scopes:
            return self._deny(spec, f"missing capability '{spec.required_scope}'")
        if spec.allowed_roles and not (spec.allowed_roles & principal.roles):
            return self._deny(spec, "role not permitted for tool")
        ctx = {
            "principal": {"subject": principal.subject, "roles": sorted(principal.roles), "scopes": sorted(principal.scopes), "attrs": principal.attrs},
            "tool": {"name": spec.name, "effect": spec.effect.value}, "args": dict(args), "context": dict(context or {}),
        }
        for rule in self.rules:
            if rule.fires(ctx):
                return self._deny(spec, f"abac:{rule.id}: {rule.reason}")
        for p in spec.url_params:
            v = args.get(p)
            if isinstance(v, str) and not host_allowed(v, spec.egress_allowlist):
                return self._deny(spec, f"egress: '{p}' target not in allow-list")
        if self.opa is not None and not await self.opa.allow(ctx):
            return self._deny(spec, "opa: denied")
        return PolicyDecision(True, ["allowed"], spec)
