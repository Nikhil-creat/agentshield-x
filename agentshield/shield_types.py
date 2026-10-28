"""Shared lightweight types (dataclasses, not pydantic, to keep the hot path fast)."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Iterable


class TrustLevel(enum.IntEnum):
    """Provenance of a piece of content. Lower = less trusted."""

    UNTRUSTED = 0  # RAG chunks, web pages, tool output, OCR text, QR payloads
    USER = 1  # authenticated end-user input
    SYSTEM = 2  # operator-authored templates


class Verdict(str, enum.Enum):
    ALLOW = "allow"
    SANITIZED = "sanitized"  # self-healed: content was rewritten
    PENDING_APPROVAL = "pending_approval"
    BLOCK = "block"


class ThreatCategory(str, enum.Enum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    PROMPT_LEAK = "prompt_leak"
    ROLE_SPOOF = "role_spoof"
    STEALTH = "stealth"
    EXFILTRATION = "exfiltration"
    TOOL_ABUSE = "tool_abuse"
    TOOL_FORGERY = "tool_forgery"
    SECRET_LEAK = "secret_leak"
    ENCODED_PAYLOAD = "encoded_payload"
    OBFUSCATION = "obfuscation"
    TOKEN_SMUGGLING = "token_smuggling"
    HOMOGLYPH = "homoglyph"
    CONTEXT_POISONING = "context_poisoning"
    VECTOR_DRIFT = "vector_drift"
    INTENT_DIVERGENCE = "intent_divergence"
    PRIVILEGE = "privilege"
    POLICY = "policy"
    VISUAL_HIDDEN_TEXT = "visual_hidden_text"
    VISUAL_STEGANOGRAPHY = "visual_steganography"
    VISUAL_QR = "visual_qr"
    VISUAL_ADVERSARIAL = "visual_adversarial"
    RESOURCE = "resource"
    INTERNAL = "internal"  # scanner failure / timeout (fail closed)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single detection. ``span`` indexes the *normalized* text when present."""

    category: ThreatCategory
    rule: str
    score: float
    detail: str = ""
    span: tuple[int, int] | None = None
    rewritable: bool = False  # True if removing ``span`` is a safe remediation
    source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "rule": self.rule,
            "score": round(self.score, 4),
            "detail": self.detail[:200],
            "span": list(self.span) if self.span else None,
            "source": self.source,
        }


def noisy_or(scores: Iterable[float]) -> float:
    """Combine independent evidence: 1 - prod(1 - s). Result clamped to [0, 1]."""
    p = 1.0
    for s in scores:
        p *= 1.0 - min(max(s, 0.0), 1.0)
    return 1.0 - p


@dataclass(slots=True)
class TextScan:
    """Result of scanning one text field."""

    text: str  # normalized (and, if healed, sanitized) text safe to forward
    findings: list[Finding] = field(default_factory=list)
    score: float = 0.0
    verdict: Verdict = Verdict.ALLOW
    healed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": round(self.score, 4),
            "healed": self.healed,
            "findings": [f.as_dict() for f in self.findings],
        }
