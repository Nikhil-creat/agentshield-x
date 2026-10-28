"""Risk scoring engine: 0.0 (benign) .. 1.0 (critical), with an explainable breakdown."""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import ShieldSettings
from .policy_engine import EFFECT_RISK, ToolSpec
from .shield_types import Finding, ThreatCategory, noisy_or


@dataclass(slots=True)
class RiskAssessment:
    value: float
    level: str
    components: dict[str, float] = field(default_factory=dict)
    needs_approval: bool = False
    reasons: list[str] = field(default_factory=list)
    evidence: float = 0.0  # noisy-OR of *findings only* (no tool/effect priors); drives self-healing


class RiskEngine:
    def __init__(self, settings: ShieldSettings) -> None:
        self.s = settings

    def level(self, v: float) -> str:
        if v >= self.s.block_threshold:
            return "critical"
        if v >= self.s.hitl_threshold:
            return "high"
        if v >= self.s.heal_threshold:
            return "medium"
        return "low"

    def assess_tool_call(self, spec: ToolSpec, findings: list[Finding]) -> RiskAssessment:
        """Combine tool/effect priors with evidence using noisy-OR (independent signals)."""
        comps: dict[str, float] = {"tool": spec.base_risk, "effect": EFFECT_RISK[spec.effect] * 0.5}
        by_cat: dict[ThreatCategory, float] = {}
        for f in findings:
            by_cat[f.category] = max(by_cat.get(f.category, 0.0), f.score)
        for cat, sc in by_cat.items():
            comps[cat.value] = sc
        value = noisy_or(comps.values())
        reasons = [f"{k}={v:.2f}" for k, v in sorted(comps.items(), key=lambda kv: -kv[1])[:4]]
        needs = spec.needs_approval or (spec.effect.value != "read" and value >= self.s.hitl_threshold)
        evidence = noisy_or(by_cat.values())
        return RiskAssessment(value, self.level(value), comps, needs, reasons, evidence=evidence)

    def assess_text(self, findings: list[Finding]) -> float:
        return noisy_or(f.score for f in findings)
