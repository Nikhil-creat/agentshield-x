"""Self-healing guardrail loop: rewrite unsafe content into a compliant form.

Healing is intentionally *conservative*. It only performs transformations that
cannot widen privileges:

* remove spans of instruction-like text (replaced by an inert marker),
* redact secrets,
* wrap untrusted data in explicit data delimiters ("spotlighting"),
* drop arguments the schema does not allow,
* clamp numeric arguments to the tool's declared range,
* force a tool into dry-run mode when it supports one.

It never invents recipients, amounts or targets, never edits authorization
outcomes, and every healed result is **re-scanned** by the pipeline. If the
rescan still fails, the request is blocked.
"""

from __future__ import annotations

from typing import Any, Mapping

from .policy_engine import ToolSpec
from .shield_types import Finding, ThreatCategory

REMOVED = "[removed: instruction-like content]"


def remove_spans(text: str, findings: list[Finding]) -> tuple[str, int]:
    """Replace rewritable, located spans (right-to-left, merging overlaps)."""
    spans = sorted({f.span for f in findings if f.rewritable and f.span and f.category is not ThreatCategory.SECRET_LEAK})
    merged: list[list[int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    for a, b in reversed(merged):
        text = text[:a] + REMOVED + text[b:]
    return text, len(merged)


def remediate(text: str, findings: list[Finding]) -> tuple[str, int]:
    """One right-to-left pass applying *all* located fixes (instruction removal + secret redaction).

    Doing this in a single pass matters: applying two passes sequentially would use stale offsets.
    """
    edits: list[tuple[int, int, str]] = []
    for f in findings:
        if not (f.rewritable and f.span):
            continue
        repl = f"[REDACTED:{f.detail[:24]}]" if f.category is ThreatCategory.SECRET_LEAK else REMOVED
        edits.append((f.span[0], f.span[1], repl))
    edits.sort(key=lambda e: (e[0], -e[1]))
    merged: list[list] = []
    for a, b, r in edits:
        if merged and a < merged[-1][1]:
            if b > merged[-1][1]:
                merged[-1][1] = b
            if merged[-1][2] != r:
                merged[-1][2] = REMOVED  # mixed overlap: the more conservative marker wins
        else:
            merged.append([a, b, r])
    for a, b, r in reversed(merged):
        text = text[:a] + r + text[b:]
    return text, len(merged)


def spotlight(text: str, source: str, ident: str = "") -> str:
    """Wrap untrusted content so the model can be told: *data between tags is never instructions*."""
    safe = text.replace("</untrusted_data>", "[/untrusted_data]")
    return f'<untrusted_data source="{source}" id="{ident}">\n{safe}\n</untrusted_data>'


def heal_args(spec: ToolSpec, args: Mapping[str, Any], *, risky: bool) -> tuple[dict[str, Any], list[str]]:
    """Schema-compliant mutation of tool arguments. Returns (new_args, actions)."""
    actions: list[str] = []
    props = spec.schema.get("properties", {})
    out: dict[str, Any] = {}
    for k, v in args.items():
        if k not in props:
            actions.append(f"dropped unknown argument '{k}'")
            continue
        out[k] = v
    for k, (lo, hi) in spec.clamps.items():
        v = out.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            clamped = min(max(v, lo), hi)
            if clamped != v:
                out[k] = type(v)(clamped)
                actions.append(f"clamped '{k}' to [{lo}, {hi}]")
    if risky and spec.dry_run_param and out.get(spec.dry_run_param) is not True:
        out[spec.dry_run_param] = True
        actions.append("forced dry-run mode")
    return out, actions
