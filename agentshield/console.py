"""Data + static assets for the web security console (``/console``).

The page is a single static file with no external requests (a security console must not load third-party code); the
response carries a strict CSP whose script/style hashes are computed from the shipped file, so editing the page cannot
silently desync the policy. Data endpoints require the ``auditor`` role; the page itself holds no data.
"""

from __future__ import annotations

import base64
import hashlib
import re
from functools import lru_cache
from importlib import resources
from typing import Any

from .observability import FINDINGS, HITL_OUTCOMES, HITL_PENDING, REDTEAM_RATE, REQUESTS, SANDBOX_RUNS
from .pipeline import ShieldPipeline


@lru_cache(maxsize=1)
def console_html() -> tuple[str, str]:
    """Returns (html, content-security-policy)."""
    html = resources.files("agentshield").joinpath("static/console.html").read_text(encoding="utf-8")

    def h(block: str) -> str:
        return "'sha256-" + base64.b64encode(hashlib.sha256(block.encode()).digest()).decode() + "'"
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    styles = re.findall(r"<style>(.*?)</style>", html, re.S)
    csp = ("default-src 'none'; script-src " + " ".join(h(x) for x in scripts) + "; style-src " + " ".join(h(x) for x in styles) +
           "; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return html, csp


def stats_payload(pipe: ShieldPipeline) -> dict[str, Any]:
    by_route: dict[str, dict[str, int]] = {}
    for (route, verdict), n in REQUESTS.snapshot().items():
        by_route.setdefault(route, {})[verdict] = int(n)
    totals: dict[str, int] = {}
    for verdicts in by_route.values():
        for v, n in verdicts.items():
            totals[v] = totals.get(v, 0) + n
    ok, why = pipe.ledger.verify_integrity()
    return {
        "ledger": {"entries": pipe.ledger.size, "intact": ok, "detail": why},
        "verdicts": totals,
        "by_route": by_route,
        "findings": sorted(({"category": k[0], "count": int(v)} for k, v in FINDINGS.snapshot().items()), key=lambda r: -r["count"])[:12],
        "hitl": {"pending": int(sum(HITL_PENDING.snapshot().values())), "outcomes": {k[0]: int(v) for k, v in HITL_OUTCOMES.snapshot().items()}},
        "sandbox": {k[0]: int(v) for k, v in SANDBOX_RUNS.snapshot().items()},
        "redteam": {k[0]: round(v, 4) for k, v in REDTEAM_RATE.snapshot().items()},
    }


def recent_entries(pipe: ShieldPipeline, n: int = 40) -> list[dict[str, Any]]:
    """Newest-first ledger entries, digests and metadata only (payloads are never stored, so nothing sensitive can leak)."""
    n = max(1, min(int(n), 200))
    return [{"seq": e.seq, "ts": e.ts, "kind": e.kind, "actor": e.actor, "prev": e.prev, "leaf": e.leaf,
             "meta": {k: v for k, v in e.meta.items() if isinstance(v, (str, int, float, bool))}} for e in reversed(pipe.ledger._entries[-n:])]
