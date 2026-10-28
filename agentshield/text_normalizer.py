"""Input stream normalization.

Defeats: zero-width / bidi / variation-selector smuggling, Unicode tag-character
("ASCII smuggling") payloads, zero-width binary encodings, mixed-script
homoglyph words, compatibility-form obfuscation (fullwidth, math alphanumerics),
and character-flood token attacks.

All transformations that feed span-based rewriting are length-stable *after*
normalization: detection views (`detection_view`) are 1:1 with the normalized
text, so a span found in a view is a valid span in the normalized text.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from .shield_types import Finding, ThreatCategory

# --- confusables: non-Latin look-alikes -> ASCII (1:1 mapping) ----------------
_CONFUSABLE_PAIRS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w",
    "һ": "h", "ь": "b", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J",
    "Ѕ": "S", "Ү": "Y",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t",
    "υ": "u", "χ": "x", "γ": "y", "ε": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Latin-extended look-alikes
    "ı": "i", "ɡ": "g", "ɑ": "a", "ǀ": "l", "ⅼ": "l", "ꓲ": "I", "ꓸ": ".",
}
CONFUSABLES: dict[str, str] = _CONFUSABLE_PAIRS
_CONFUSABLE_TABLE = str.maketrans(CONFUSABLES)

_LEET_TABLE = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"}
)

_ZW_CHARS = {"​", "‌", "‍", "⁠", "﻿", "᠎", "­", "͏", "⁡", "⁢", "⁣", "⁤"}
_BIDI_CHARS = {
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩", "‎", "‏", "؜",
}
_WORD_RE = re.compile(r"\w+", re.UNICODE)
_FLOOD_RE = re.compile(r"(.)\1{31,}", re.DOTALL)


def _is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


@dataclass(slots=True)
class NormalizationResult:
    text: str
    hidden_text: str = ""  # decoded smuggled payloads (scan these too!)
    findings: list[Finding] = field(default_factory=list)
    changed: bool = False


def _decode_zero_width_bits(s: str) -> str:
    bits = "".join("0" if c == "​" else "1" for c in s if c in ("​", "‌"))
    n = len(bits) // 8 * 8
    if n < 16:
        return ""
    raw = bytes(int(bits[i : i + 8], 2) for i in range(0, n, 8))
    try:
        out = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in out)
    return out if out and printable / len(out) > 0.9 else ""


def normalize(text: str, *, max_chars: int = 200_000, source: str = "text") -> NormalizationResult:
    """Normalize ``text`` and report every deviation as a :class:`Finding`."""
    findings: list[Finding] = []
    original = text
    if len(text) > max_chars:
        text = text[:max_chars]
        findings.append(Finding(ThreatCategory.RESOURCE, "norm.truncated", 0.3, f"input truncated to {max_chars} chars", source=source))
    text = text.replace("\x00", "")

    # -- pass 1: strip invisible/control characters, harvest hidden payloads --
    out: list[str] = []
    tag_chars: list[str] = []
    zw_count = bidi_count = vs_count = ctrl_count = 0
    zw_run: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        cp = ord(ch)
        if _is_tag_char(cp):
            if 0xE0020 <= cp <= 0xE007E:
                tag_chars.append(chr(cp - 0xE0000))
            vs_count += 1
        elif _is_variation_selector(cp):
            vs_count += 1
        elif ch in _BIDI_CHARS:
            bidi_count += 1
        elif ch in _ZW_CHARS:
            # keep a *single* ZWJ/ZWNJ between two non-ASCII letters (Indic/Persian/emoji)
            j = i
            while j < n and text[j] in _ZW_CHARS:
                j += 1
            run = text[i:j]
            prev_c = out[-1] if out else ""
            next_c = text[j] if j < n else ""
            legit = (
                len(run) == 1
                and run in ("‌", "‍")
                and prev_c
                and next_c
                and not prev_c.isascii()
                and not next_c.isascii()
            )
            zw_run.append(run)
            zw_count += len(run)
            if legit:
                out.append(run)
                zw_count -= 1
            i = j
            continue
        elif unicodedata.category(ch) == "Cf":
            bidi_count += 1
        elif unicodedata.category(ch) == "Cc" and ch not in "\n\t\r":
            ctrl_count += 1
        else:
            out.append(ch)
        i += 1
    stripped = "".join(out)

    hidden_parts: list[str] = []
    if tag_chars:
        hidden_parts.append("".join(tag_chars))
        findings.append(Finding(ThreatCategory.TOKEN_SMUGGLING, "norm.unicode_tag_payload", 0.85,
                                f"{len(tag_chars)} Unicode tag chars decoded to hidden text", source=source))
    zw_hidden = _decode_zero_width_bits("".join(zw_run)) if zw_run else ""
    if zw_hidden:
        hidden_parts.append(zw_hidden)
        findings.append(Finding(ThreatCategory.TOKEN_SMUGGLING, "norm.zero_width_binary", 0.85,
                                "zero-width binary encoding decoded to hidden text", source=source))
    if zw_count and not zw_hidden:
        score = 0.15 if zw_count < 4 else min(0.2 + zw_count / 200, 0.5)
        findings.append(Finding(ThreatCategory.TOKEN_SMUGGLING, "norm.zero_width", score,
                                f"{zw_count} zero-width chars stripped", source=source))
    if vs_count and not tag_chars:
        findings.append(Finding(ThreatCategory.TOKEN_SMUGGLING, "norm.variation_selectors", min(0.15 + vs_count / 100, 0.6),
                                f"{vs_count} variation selectors stripped", source=source))
    if bidi_count:
        findings.append(Finding(ThreatCategory.TOKEN_SMUGGLING, "norm.bidi_controls", 0.5,
                                f"{bidi_count} bidi/format controls stripped (Trojan-Source style)", source=source))
    if ctrl_count:
        findings.append(Finding(ThreatCategory.OBFUSCATION, "norm.control_chars", 0.2,
                                f"{ctrl_count} control chars stripped", source=source))

    # -- pass 2: compatibility normalization (fullwidth, math alphanumerics, ligatures)
    text = unicodedata.normalize("NFKC", stripped)

    # -- pass 3: token-flood collapse
    def _collapse(m: re.Match[str]) -> str:
        return m.group(1) * 32

    flooded = _FLOOD_RE.sub(_collapse, text)
    if flooded != text:
        findings.append(Finding(ThreatCategory.RESOURCE, "norm.char_flood", 0.2, "long character run collapsed", source=source))
        text = flooded

    # -- pass 4: mixed-script homoglyph words (pure Cyrillic/Greek words are left alone)
    if not text.isascii():
        mixed = 0
        pieces: list[str] = []
        last = 0
        for m in _WORD_RE.finditer(text):
            w = m.group(0)
            if w.isascii():
                continue
            has_ascii_alpha = any(c.isascii() and c.isalpha() for c in w)
            has_conf = any(c in CONFUSABLES for c in w)
            if has_ascii_alpha and has_conf:
                pieces.append(text[last : m.start()])
                pieces.append(w.translate(_CONFUSABLE_TABLE))
                last = m.end()
                mixed += 1
        if mixed:
            pieces.append(text[last:])
            text = "".join(pieces)
            findings.append(Finding(ThreatCategory.HOMOGLYPH, "norm.mixed_script_homoglyph",
                                    0.5 if mixed < 3 else 0.7, f"{mixed} mixed-script homoglyph words repaired", source=source))

    return NormalizationResult(
        text=text,
        hidden_text="\n".join(hidden_parts),
        findings=findings,
        changed=(text != original),
    )


def _fold_char(c: str) -> str:
    lo = c.lower()
    return lo if len(lo) == 1 else c


def detection_view(text: str, *, leet: bool = True) -> str:
    """1:1 length-preserving view for pattern matching.

    Lowercases and maps *all* confusables (even in pure-script words) to ASCII. With ``leet=True``
    it also folds leetspeak (``1gn0re``); that fold corrupts punctuation-based patterns (``!`` -> ``i``),
    so callers that match structure (URLs, markdown) must also use ``leet=False``.
    Never used for output, only for matching.
    """
    if text.isascii():
        v = text.lower()
    else:
        v = "".join(_fold_char(c) for c in text.translate(_CONFUSABLE_TABLE))
    return v.translate(_LEET_TABLE) if leet else v


_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def compact_view(view: str) -> str:
    """Remove every non-alphanumeric (defeats ``i.g.n.o.r.e`` / spaced-out text)."""
    return _NON_ALNUM.sub("", view)
