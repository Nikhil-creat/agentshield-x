"""Signature-based detection (fast path) + secret/PII redaction.

Signatures run on :func:`detection_view` (lowercased, de-homoglyphed, leet-folded).
Secret patterns run on the *normalized* text because they are case sensitive.
This is deliberately only one layer: pair with the semantic hunters in
``threat_hunter.py`` and the policy engine.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import itertools
import re
from dataclasses import dataclass

from .shield_types import Finding, ThreatCategory as C, TrustLevel
from .text_normalizer import compact_view, detection_view

_F = re.IGNORECASE


@dataclass(frozen=True, slots=True)
class Signature:
    rule: str
    category: C
    weight: float
    pattern: re.Pattern[str]
    untrusted_only: bool = False  # only meaningful when content is *data*, not user instructions
    rewritable: bool = True


def _s(rule: str, cat: C, w: float, rx: str, *, untrusted_only: bool = False, rewritable: bool = True, flags: int = _F) -> Signature:
    return Signature(rule, cat, w, re.compile(rx, flags), untrusted_only, rewritable)


_ART = r"(?:all\s+|any\s+|the\s+|your\s+|my\s+|every\s+|these\s+|those\s+|of\s+)*"
_PRIOR = r"(?:previous|prior|above|earlier|preceding|former|original|existing|system|initial|foregoing)"
_INSTR = r"(?:instructions?|prompts?|rules?|directives?|context|messages?|guidelines?|constraints?|commands?|programming)"

INSTRUCTION_SIGNATURES: tuple[Signature, ...] = (
    _s("inj.ignore_prior", C.DIRECT_INJECTION, 0.90,
       rf"\b(?:ignore|disregard|forget|override|discard|bypass|skip|abandon|drop)\s+{_ART}{_PRIOR}\s+{_INSTR}"),
    _s("inj.new_instructions", C.DIRECT_INJECTION, 0.70,
       r"\b(?:new|updated|revised|real|actual|additional|secret)\s+(?:instructions?|directives?|system\s+prompt|rules)\s*[:\-]"),
    _s("inj.do_not_follow", C.DIRECT_INJECTION, 0.85,
       rf"\b(?:do\s+not|don'?t|stop|never)\s+(?:follow|obey|listen\s+to|adhere\s+to|comply\s+with)\s+{_ART}{_PRIOR}?\s*{_INSTR}"),
    _s("jb.persona", C.JAILBREAK, 0.85,
       r"\b(?:you\s+are\s+now|from\s+now\s+on,?\s+you(?:\s+are|'?re)?|pretend\s+(?:to\s+be|you\s+are)|act\s+as(?:\s+if\s+you\s+(?:are|were))?|roleplay\s+as)\s+(?:an?\s+|the\s+)?"
       r"(?:dan\b|unrestricted|unfiltered|uncensored|jailbroken|evil|developer\s+mode|god\s+mode|no\s+(?:rules|restrictions|limits)|without\s+(?:rules|restrictions|limits))"),
    _s("jb.dan", C.JAILBREAK, 0.85,
       r"\b(?:do\s+anything\s+now|dan\s+mode|developer\s+mode\s+(?:enabled|on|activated)|jailbreak(?:ed)?\s+mode|sudo\s+mode|god\s+mode)\b"),
    _s("jb.disable_safety", C.JAILBREAK, 0.85,
       r"\b(?:disable|turn\s+off|deactivate|remove|bypass|circumvent|override|ignore|switch\s+off)\s+(?:all\s+|your\s+|the\s+|any\s+)*"
       r"(?:safety|security|guardrails?|content\s+(?:policy|filters?)|filters?|restrictions?|safeguards?|moderation|alignment|ethic\w*)"),
    _s("leak.system_prompt", C.PROMPT_LEAK, 0.80,
       r"\b(?:reveal|print|show|repeat|output|display|leak|dump|tell\s+me|what\s+(?:is|are|was|were))\s+(?:me\s+)?(?:all\s+)?(?:of\s+)?(?:your|the)\s+"
       r"(?:system|hidden|secret|initial|original|developer|internal)\s+(?:prompt|instructions?|message|rules)"),
    _s("inj.ignore_own_rules", C.DIRECT_INJECTION, 0.80,
       rf"\b(?:ignore|disregard|bypass|override|forget|violate|abandon)\s+(?:all\s+|any\s+|the\s+)?(?:your|these|those)\s+(?:\w+\s+)?{_INSTR}"),
    _s("inj.dismiss_prior", C.DIRECT_INJECTION, 0.85,
       rf"\b(?:pay\s+no\s+(?:attention|heed)\s+to|stop\s+(?:paying\s+attention\s+to|following)|set\s+aside|throw\s+(?:away|out)|put\s+aside)\s+{_ART}(?:\w+\s+){{0,2}}?{_INSTR}"),
    _s("inj.void_prior", C.DIRECT_INJECTION, 0.85,
       r"\b(?:everything|anything|all)\s+(?:that\s+)?(?:you(?:'ve|\s+have)?\s+(?:were|been|was)\s+(?:told|given|taught|instructed)|i\s+(?:said|told\s+you)|above)\b[^.\n]{0,40}\b(?:void|invalid|obsolete|irrelevant|cancell?ed|null|wrong|no\s+longer\s+(?:applies|apply|matters?))"
       r"|\b(?:your|the)\s+(?:previous|prior|earlier|old|original|initial)\s+(?:instructions?|directives?|rules|guidelines|prompts?|orders)\s+(?:are|is|were|have\s+been)\s+(?:now\s+)?(?:obsolete|void|invalid|revoked|cancell?ed|outdated|irrelevant|superseded|replaced)"
       r"|\b(?:instructions?|directives?|rules|guidelines)\s+(?:above|before|so\s+far)\s+(?:no\s+longer|do(?:es)?\s+not)\s+apply"),
    _s("inj.only_obey", C.DIRECT_INJECTION, 0.75,
       r"\b(?:follow|obey|listen\s+to|answer\s+to)\s+only\s+(?:what\s+i|my|me|the\s+instructions\s+(?:below|that\s+follow))\b|\bobey\s+me\s+(?:only|and\s+no\s+one)|\byou\s+(?:work|answer)\s+for\s+me\s+(?:alone|only)\b"),
    _s("leak.repeat_above", C.PROMPT_LEAK, 0.80,
       r"\b(?:repeat|print|output|recite|copy|echo|reproduce)\s+(?:everything|all\s+(?:of\s+)?(?:the\s+)?text|the\s+(?:text|words|content))\s+(?:above|before)\b[^.\n]{0,60}\b(?:verbatim|word\s+for\s+word|starting\s+(?:from|with)|including\s+(?:the\s+)?(?:system|hidden))"
       r"|\b(?:quote|recite|list|give\s+me|tell\s+me|show\s+me|print|reveal)\s+(?:me\s+)?(?:(?:your)\s+(?:exact\s+|full\s+|complete\s+|entire\s+|verbatim\s+)?(?:initial|original|system|hidden|secret|developer)|(?:the|all\s+of\s+the)\s+(?:exact\s+|full\s+|complete\s+|entire\s+)?(?:system|hidden|secret|developer|initial))\s+(?:instructions?|prompt|rules|message|configuration)"
       r"|\bwhat\s+(?:were|are|was|is)\s+(?:your|the)\s+(?:exact\s+|full\s+|complete\s+)?(?:initial|original|system|hidden|secret|developer)\s+(?:instructions?|prompt|rules|message|configuration)"
       r"|\b(?:output|print|reveal|show|display|dump|share|disclose)\s+(?:out\s+)?(?:the\s+text\s+of\s+|the\s+contents?\s+of\s+)?(?:your|the)\s+(?:entire|whole|full|complete|exact|confidential|secret|hidden|private|internal|system)\s+(?:system\s+)?(?:prompt|instructions?|context|message|configuration|setup|settings|rules)"),
    _s("inj.rules_suspended", C.DIRECT_INJECTION, 0.80,
       r"\b(?:your|above|previous|earlier|prior|all|system|safety|these|those|original|initial)\s+(?:\w+\s+){0,2}(?:instructions?|directives?|rules|guidelines|restrictions|policies)\b[^.\n]{0,50}\b(?:no\s+longer\s+(?:apply|applies|valid|in\s+effect)|are\s+(?:now\s+)?(?:suspended|lifted|revoked|disabled|void))"
       r"|\b(?:safety|security|content)\s+(?:checks?|measures?|filters?|rules|policy|policies)\s+(?:are|is|have\s+been)\s+(?:now\s+)?(?:suspended|lifted|disabled|off|removed|waived)"),
    _s("jb.persona_unrestricted", C.JAILBREAK, 0.85,
       r"\b(?:respond|answer|reply|behave|operate|speak)\s+(?:only\s+)?as\b[^.\n]{0,80}\b(?:never\s+refuses?|no\s+(?:\w+\s+)?(?:rules|limits|restrictions)|without\s+(?:\w+\s+)?(?:rules|restrictions|limits|filters)|unrestricted|unfiltered|uncensored|can\s+do\s+anything)"),
    _s("exfil.sensitive_file", C.EXFILTRATION, 0.80,
       r"\b(?:send|upload|post|email|forward|cat|print|read|show|output|exfiltrate|copy)\b[^\n]{0,60}(?:/etc/(?:passwd|shadow)|~?/\.ssh/|\.aws/credentials|\.env\b|\bid_rsa\b)"),
    _s("spoof.role_marker", C.ROLE_SPOOF, 0.70,
       r"(?:^|\n)\s*(?:#{1,3}\s*)?(?:system|assistant|developer)\s*(?:prompt|message)?\s*:|<\|?(?:im_start|im_end|system|endoftext)\|?>|\[/?(?:inst|sys|system)\]|<</?sys>>"),
    _s("stealth.conceal", C.STEALTH, 0.80,
       r"\b(?:do\s+not|don'?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|notify(?:ing)?|alert(?:ing)?|let(?:ting)?)\s+(?:\w+\s+){0,3}?(?:the\s+|your\s+)?(?:user|human|person|operator|admin\w*)"
       r"|\b(?:secretly|silently|covertly|quietly)\s+(?:send|forward|email|upload|exfiltrate|post|execute|run|delete)"),
    _s("obf.decode_and_follow", C.OBFUSCATION, 0.70,
       r"\b(?:decode|decrypt|deobfuscate|translate)\s+(?:this\s+)?(?:and\s+)?(?:then\s+)?(?:follow|execute|run|obey|apply)"
       r"|\b(?:base64|rot13|hex)\s*(?:decode[d]?|encoded)?\s*(?:and|then)\s+(?:follow|execute|run|obey)"),
    # --- semantic cue co-occurrence: override/reveal/mode-switch verb near a target noun (paraphrase coverage) ---
    _s("sem.override_rules", C.DIRECT_INJECTION, 0.75,
       r"\b(?:set\s+aside|put\s+aside|forget|ignore|disregard|discard|drop|override|overrule|supersede|cancel|void|abandon|never\s+(?:existed|written)|no\s+longer\s+(?:apply|applies|matter|valid))\b"
       r"(?:\W+\w+){0,8}?\W+(?:everything|anything|rules?|guidelines?|instructions?|directions?|restrictions?|limitations?|constraints?|told|programming|training|safeguards?|filters?)\b"),
    _s("sem.reveal_hidden", C.PROMPT_LEAK, 0.75,
       r"\b(?:print|repeat|recite|echo|reveal|show|display|output|quote|copy|dump|expose|disclose|give\s+me)\b(?:\W+\w+){0,5}?\W+"
       r"(?:verbatim|word\s+for\s+word)?(?:\W+\w+){0,3}?\W*(?:(?:developer|system|hidden|initial|original|secret|first|internal)\s+(?:message|prompt|instructions?|text)"
       r"|text\s+(?:that\s+)?(?:was\s+)?given\s+to\s+you\s+before|(?:everything|instructions?)\s+(?:you\s+(?:were|was)\s+given|above))"),
    _s("sem.mode_switch", C.JAILBREAK, 0.75,
       r"\b(?:switch|enter|go|change|turn)\b(?:\W+\w+){0,4}?\W+(?:unrestricted|unfiltered|uncensored|maintenance|debug|admin|root|god|developer|jailbreak)\s+mode\b"
       r"|\b(?:model|assistant|ai|bot)\s+(?:with|that\s+has)\s+(?:zero|no)\s+(?:limitations?|restrictions?|rules|filters?|boundaries)"
       r"|\bstop\s+being\s+(?:an?\s+)?(?:assistant|ai|chatbot)\b|\bfilters?\s+(?:are\s+)?(?:off|disabled)\b"),
    _s("sem.obey_me", C.DIRECT_INJECTION, 0.70,
       r"\b(?:just\s+)?(?:obey|follow|listen\s+to)\s+(?:only\s+)?(?:me|my\s+(?:commands?|orders?|instructions?))\b(?:\W+\w+){0,4}?\W+(?:from\s+(?:here|now)\s+on|only|exclusively|from\s+now)"),
    # --- tool / exfil abuse, relevant in any trust level ---
    _s("exfil.markdown_image", C.EXFILTRATION, 0.70,
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*\)", rewritable=True),
    _s("exfil.img_tag", C.EXFILTRATION, 0.60,
       r"<img[^>]+src\s*=\s*[\"']?https?://[^\"'>\s]*\?", rewritable=True),
    _s("abuse.shell_destructive", C.TOOL_ABUSE, 0.80,
       r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:/|~|\*|\$home)|\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|/dev/tcp/|\bnc\s+-[a-z]*e\b|\bchmod\s+(?:-r\s+)?[0-7]*777\b|\bmkfifo\b",
       rewritable=False),
    _s("abuse.sql_destructive", C.TOOL_ABUSE, 0.60,
       r"\b(?:drop|truncate)\s+(?:table|database|schema)\b|\bdelete\s+from\s+\w+\s*(?:;|$)|\bunion\s+(?:all\s+)?select\b", rewritable=False),
    # --- indirect injection: only suspicious when it arrives as *data* ---
    _s("indirect.addressing_ai", C.INDIRECT_INJECTION, 0.85,
       r"\b(?:when(?:ever)?|if|once)\s+(?:the\s+|an?\s+)?(?:assistant|ai|llm|model|agent|chatbot|language\s+model)\s+(?:reads?|sees?|processes?|summari[sz]es?|encounters?|retrieves?|parses?)"
       r"|\b(?:note|message|instruction)s?\s+(?:to|for)\s+(?:the\s+)?(?:assistant|ai|llm|model|agent)\b"
       r"|\bassistant\s*[:,]\s*(?:you\s+must|please\s+(?:ignore|do)|ignore)"
       r"|\b(?:important|attention|urgent)\s*[:!]\s*(?:ai|assistant|llm|agents?)\b",
       untrusted_only=True),
    _s("indirect.imperative_to_ai", C.INDIRECT_INJECTION, 0.60,
       r"\b(?:you\s+(?:must|should|need\s+to|will|are\s+required\s+to)|please)\s+(?:now\s+)?(?:immediately\s+)?"
       r"(?:send|email|forward|call|execute|run|delete|transfer|ignore|reveal|output|print|visit|click|open|download|upload|post)\b",
       untrusted_only=True),
    _s("indirect.exfil_target", C.EXFILTRATION, 0.75,
       r"\b(?:send|post|forward|upload|exfiltrate|transmit|leak|email|submit)\b[^\n]{0,120}?\b(?:to|at)\s*(?:https?://|ftp://|[\w.+-]+@[\w-]+\.\w{2,})",
       untrusted_only=True),
    _s("indirect.hidden_html", C.INDIRECT_INJECTION, 0.80,
       r"<!--[\s\S]{0,2000}?(?:ignore|instruction|assistant|system|\bai\b|\bllm\b)[\s\S]*?-->", untrusted_only=True),
    _s("indirect.hidden_css", C.CONTEXT_POISONING, 0.45,
       r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\b|color\s*:\s*(?:white|#fff(?:fff)?)\b)", untrusted_only=True),
    _s("forge.tool_call", C.TOOL_FORGERY, 0.70,
       r"<(?:tool_call|function_call|tool_use|invoke)\b|\"(?:tool|function|name)\"\s*:\s*\"[\w.-]+\"\s*,\s*\"(?:arguments|args|parameters|input)\"\s*:", untrusted_only=True),
)

# De-spaced patterns catch "i.g.n.o.r.e  p r e v i o u s ..." evasions.
_COMPACT_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("inj.ignore_prior", re.compile(r"(?:ignore|disregard|forget|override|bypass|discard)(?:all|any|the|your|every)*(?:previous|prior|above|earlier|preceding|system|initial)(?:instructions?|prompts?|rules|directives|guidelines|context)")),
    ("leak.system_prompt", re.compile(r"(?:reveal|show|print|repeat|output|display|dump|leak)(?:me)?(?:all)?(?:of)?(?:your|the)(?:system|hidden|initial|original|secret)(?:prompt|instructions?)")),
    ("jb.disable_safety", re.compile(r"(?:disable|bypass|turnoff|deactivate|circumvent)(?:all|your|the|any)*(?:safety|guardrails?|filters?|restrictions?|safeguards?)")),
    ("jb.dan", re.compile(r"(?:doanythingnow|danmode|developermodeenabled)")),
)

SECRET_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("api_key_sk", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("groq_api_key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _match_instruction_sigs(view: str, trust: TrustLevel, source: str) -> list[Finding]:
    out: list[Finding] = []
    untrusted = trust <= TrustLevel.UNTRUSTED
    for sig in INSTRUCTION_SIGNATURES:
        if sig.untrusted_only and not untrusted:
            continue
        weight = sig.weight
        cat = sig.category
        if untrusted and cat in (C.DIRECT_INJECTION, C.JAILBREAK, C.PROMPT_LEAK, C.ROLE_SPOOF, C.STEALTH):
            # Instruction-like content inside *data* is the definition of indirect injection.
            weight = min(1.0, weight * 1.1)
            cat = C.INDIRECT_INJECTION
        for m in itertools.islice(sig.pattern.finditer(view), 6):  # every occurrence, so healing removes all of them
            out.append(Finding(cat, sig.rule, weight, m.group(0)[:120], m.span(), sig.rewritable, source))
    return out


def scan_instructions(text: str, trust: TrustLevel = TrustLevel.USER, *, source: str = "text") -> list[Finding]:
    """Scan *normalized* text. Spans index ``text``."""
    view = detection_view(text)
    findings = _match_instruction_sigs(view, trust, source)
    plain = detection_view(text, leet=False)  # structural patterns (URLs, markdown) need real punctuation
    if plain != view:
        have = {(f.rule, f.span) for f in findings}
        findings += [f for f in _match_instruction_sigs(plain, trust, source) if (f.rule, f.span) not in have]
    seen_rules = {f.rule for f in findings}

    # compact (de-spaced) pass: evasion if it hits where the plain pass did not
    compact = compact_view(view)
    for rule, rx in _COMPACT_SIGNATURES:
        if rule not in seen_rules and rx.search(compact):
            findings.append(Finding(C.OBFUSCATION, f"obf.compact.{rule}", 0.90,
                                    "instruction hidden by separators/spacing", None, False, source))
            seen_rules.add(rule)

    # alternate encodings of the whole text: rot13 / reversed / embedded base64
    for label, alt in (("rot13", codecs.decode(view, "rot13")), ("reversed", view[::-1])):
        hits = _match_instruction_sigs(alt, TrustLevel.USER, source)
        if hits:
            top = max(hits, key=lambda f: f.score)
            findings.append(Finding(C.ENCODED_PAYLOAD, f"enc.{label}.{top.rule}", 0.85,
                                    f"{label}-encoded instruction", None, False, source))
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        pad = "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob.replace("-", "+").replace("_", "/") + pad, validate=False)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if not decoded or sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) < 0.85:
            continue
        hits = _match_instruction_sigs(detection_view(decoded), TrustLevel.USER, source)
        compact_hit = any(rx.search(compact_view(detection_view(decoded))) for _, rx in _COMPACT_SIGNATURES)
        if hits or compact_hit:
            findings.append(Finding(C.ENCODED_PAYLOAD, "enc.base64_instruction", 0.90,
                                    f"base64 blob decodes to instruction: {decoded[:60]!r}", m.span(), True, source))
    return findings


def scan_secrets(text: str, *, source: str = "text") -> list[Finding]:
    """Detect credentials / PII. Spans index ``text`` (rewritable by redaction)."""
    out: list[Finding] = []
    for name, rx in SECRET_SIGNATURES:
        for m in rx.finditer(text):
            out.append(Finding(C.SECRET_LEAK, f"secret.{name}", 0.95 if name != "us_ssn" else 0.6,
                               name, m.span(), True, source))
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            out.append(Finding(C.SECRET_LEAK, "secret.payment_card", 0.9, "luhn-valid card number", m.span(), True, source))
    return out


def redact_secrets(text: str, findings: list[Finding]) -> str:
    """Replace secret spans with ``[REDACTED:<type>]``."""
    spans = sorted(((f.span, f.detail) for f in findings if f.category is C.SECRET_LEAK and f.span), reverse=True)
    for (a, b), name in spans:
        text = text[:a] + f"[REDACTED:{name[:24]}]" + text[b:]
    return text
