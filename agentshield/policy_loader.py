"""Policy-as-code: load the tool registry and ABAC rules from reviewable YAML.

Strictness is the point. A policy file is security configuration, so:
* unknown keys, unknown effects/operators, duplicate tool names, bad risk values and invalid regexes are
  **errors** (a typo like ``requried_scope`` must never silently weaken a policy);
* a tool with no ``required_scope`` is rejected (no tool may be callable by "anyone");
* the loader never executes anything; it only builds the same frozen dataclasses the Python API uses.

Files:  policies/tools.yaml  (registry)   policies/abac.yaml  (deny rules)   policies/rego/*.rego (optional OPA)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

import yaml

from .policy_engine import _OPS, AbacRule, Effect, ToolRegistry, ToolSpec, validate_schema

_TOOL_KEYS = {"name", "description", "schema", "effect", "required_scope", "allowed_roles", "base_risk", "requires_approval",
              "dry_run_param", "clamps", "url_params", "egress_allowlist", "code_param"}
_RULE_KEYS = {"id", "when", "reason"}


class PolicyError(ValueError):
    """Raised for any invalid policy document. Message lists every problem found."""


def _check_schema_regexes(schema: Mapping[str, Any], path: str, errs: list[str]) -> None:
    pat = schema.get("pattern")
    if pat is not None:
        try:
            re.compile(pat)
        except re.error as e:
            errs.append(f"{path}.pattern: invalid regex ({e})")
    for k, v in (schema.get("properties") or {}).items():
        if isinstance(v, Mapping):
            _check_schema_regexes(v, f"{path}.{k}", errs)
    if isinstance(schema.get("items"), Mapping):
        _check_schema_regexes(schema["items"], f"{path}[]", errs)


def parse_tool(raw: Mapping[str, Any], errs: list[str], where: str) -> ToolSpec | None:
    n = len(errs)
    name = raw.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z_][\w.-]{0,63}", name or ""):
        errs.append(f"{where}: invalid or missing 'name'")
        name = "?"
    where = f"tool '{name}'"
    for k in set(raw) - _TOOL_KEYS:
        errs.append(f"{where}: unknown key '{k}'")
    try:
        effect = Effect(raw.get("effect"))
    except ValueError:
        errs.append(f"{where}: effect must be one of {[e.value for e in Effect]}")
        effect = Effect.READ
    scope = raw.get("required_scope")
    if not isinstance(scope, str) or not scope:
        errs.append(f"{where}: 'required_scope' is mandatory (deny-by-default: no unscoped tools)")
    schema = raw.get("schema")
    if not isinstance(schema, Mapping) or schema.get("type") != "object":
        errs.append(f"{where}: 'schema' must be an object schema")
        schema = {"type": "object", "properties": {}}
    else:
        _check_schema_regexes(schema, f"{where}.schema", errs)
    risk = raw.get("base_risk", 0.05)
    if not isinstance(risk, (int, float)) or isinstance(risk, bool) or not 0 <= risk <= 1:
        errs.append(f"{where}: base_risk must be within [0, 1]")
        risk = 0.05
    clamps = {}
    for k, v in (raw.get("clamps") or {}).items():
        if not (isinstance(v, (list, tuple)) and len(v) == 2 and all(isinstance(x, (int, float)) for x in v) and v[0] <= v[1]):
            errs.append(f"{where}: clamps.{k} must be [min, max]")
        elif k not in (schema.get("properties") or {}):
            errs.append(f"{where}: clamps.{k} refers to an undeclared property")
        else:
            clamps[k] = (v[0], v[1])
    for key in ("dry_run_param", "code_param"):
        v = raw.get(key)
        if v is not None and v not in (schema.get("properties") or {}):
            errs.append(f"{where}: {key} '{v}' is not a declared property")
    for key in ("url_params",):
        for v in raw.get(key) or []:
            if v not in (schema.get("properties") or {}):
                errs.append(f"{where}: url_params '{v}' is not a declared property")
    if raw.get("url_params") and not raw.get("egress_allowlist"):
        errs.append(f"{where}: url_params set but egress_allowlist is empty (would deny everything; list the allowed hosts explicitly)")
    ra = raw.get("requires_approval")
    if ra is not None and not isinstance(ra, bool):
        errs.append(f"{where}: requires_approval must be true/false (omit to derive from effect)")
    if len(errs) > n:
        return None
    return ToolSpec(name=name, description=str(raw.get("description", "")), schema=schema, effect=effect, required_scope=scope,
                    allowed_roles=frozenset(raw.get("allowed_roles") or ()), base_risk=float(risk), requires_approval=ra,
                    dry_run_param=raw.get("dry_run_param"), clamps=clamps, url_params=frozenset(raw.get("url_params") or ()),
                    egress_allowlist=frozenset(raw.get("egress_allowlist") or ()), code_param=raw.get("code_param"))


def load_registry(doc: Mapping[str, Any]) -> ToolRegistry:
    """Build a registry from a parsed ``tools.yaml`` document ({"tools": [...]})."""
    errs: list[str] = []
    if set(doc) - {"version", "tools"}:
        errs.append(f"unknown top-level keys: {sorted(set(doc) - {'version', 'tools'})}")
    reg, seen = ToolRegistry(), set()
    for i, raw in enumerate(doc.get("tools") or []):
        spec = parse_tool(raw, errs, f"tools[{i}]")
        if spec is None:
            continue
        if spec.name in seen:
            errs.append(f"duplicate tool '{spec.name}'")
        seen.add(spec.name)
        reg.register(spec)
    if errs:
        raise PolicyError("invalid tool policy:\n  - " + "\n  - ".join(errs))
    return reg


def load_abac(doc: Mapping[str, Any]) -> tuple[AbacRule, ...]:
    errs: list[str] = []
    rules, seen = [], set()
    for i, r in enumerate(doc.get("rules") or []):
        w = f"rules[{i}]"
        for k in set(r) - _RULE_KEYS:
            errs.append(f"{w}: unknown key '{k}'")
        rid = r.get("id")
        if not isinstance(rid, str) or not rid:
            errs.append(f"{w}: missing id")
            continue
        if rid in seen:
            errs.append(f"duplicate rule id '{rid}'")
        seen.add(rid)
        conds = []
        for c in r.get("when") or []:
            if not (isinstance(c, (list, tuple)) and len(c) == 3):
                errs.append(f"rule '{rid}': each condition must be [path, op, value]")
                continue
            if c[1] not in _OPS:
                errs.append(f"rule '{rid}': unknown operator '{c[1]}' (allowed: {sorted(_OPS)})")
                continue
            if c[1] == "matches":
                try:
                    re.compile(c[2])
                except (re.error, TypeError) as e:
                    errs.append(f"rule '{rid}': invalid regex ({e})")
            conds.append((c[0], c[1], c[2]))
        if not conds:
            errs.append(f"rule '{rid}': a deny rule with no conditions would deny everything; add conditions")
        if not r.get("reason"):
            errs.append(f"rule '{rid}': 'reason' is required (it is shown in audit records)")
        rules.append(AbacRule(rid, tuple(conds), str(r.get("reason", ""))))
    if errs:
        raise PolicyError("invalid ABAC policy:\n  - " + "\n  - ".join(errs))
    return tuple(rules)


def load_policy_dir(directory: str | Path) -> tuple[ToolRegistry, tuple[AbacRule, ...]]:
    """Load ``tools.yaml`` and ``abac.yaml`` from ``directory``. ``yaml.safe_load`` only (no object construction)."""
    d = Path(directory)
    tools = yaml.safe_load((d / "tools.yaml").read_text(encoding="utf-8")) or {}
    abac_path = d / "abac.yaml"
    abac = yaml.safe_load(abac_path.read_text(encoding="utf-8")) if abac_path.exists() else {}
    return load_registry(tools), load_abac(abac or {})


def export_registry(reg: ToolRegistry) -> dict[str, Any]:
    """Inverse of :func:`load_registry` (used to generate ``policies/tools.yaml`` from the reference registry)."""
    tools = []
    for n in reg.names():
        t = reg.get(n)
        assert t is not None
        d: dict[str, Any] = {"name": t.name, "description": t.description, "effect": t.effect.value, "required_scope": t.required_scope,
                             "base_risk": t.base_risk, "schema": _plain(t.schema)}
        if t.allowed_roles:
            d["allowed_roles"] = sorted(t.allowed_roles)
        if t.requires_approval is not None:
            d["requires_approval"] = t.requires_approval
        if t.dry_run_param:
            d["dry_run_param"] = t.dry_run_param
        if t.clamps:
            d["clamps"] = {k: list(v) for k, v in t.clamps.items()}
        if t.url_params:
            d["url_params"] = sorted(t.url_params)
        if t.egress_allowlist:
            d["egress_allowlist"] = sorted(t.egress_allowlist)
        if t.code_param:
            d["code_param"] = t.code_param
        tools.append(d)
    return {"version": 1, "tools": tools}


def export_abac(rules: tuple[AbacRule, ...]) -> dict[str, Any]:
    return {"version": 1, "rules": [{"id": r.id, "when": [list(c) for c in r.when], "reason": r.reason} for r in rules]}


def _plain(x: Any) -> Any:
    if isinstance(x, Mapping):
        return {k: _plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_plain(v) for v in x]
    return x


def dry_validate_examples(reg: ToolRegistry, examples: Mapping[str, list[Mapping[str, Any]]]) -> list[str]:
    """CI helper: every documented example call must validate against its tool schema."""
    out = []
    for tool, calls in examples.items():
        spec = reg.get(tool)
        if spec is None:
            out.append(f"{tool}: not registered")
            continue
        for c in calls:
            out += [f"{tool}: {e}" for e in validate_schema(dict(c), spec.schema)]
    return out
