"""External checkpoint anchoring + consistency verification.

A Merkle ledger proves integrity only relative to a root you trust. If an attacker with write access rewrites the
*whole* history and recomputes every hash, the ledger still verifies in isolation. Anchoring defeats this: signed
checkpoints are periodically written somewhere the attacker cannot rewrite (WORM bucket, separate account, transparency
log, e-mail to the auditor, a git repo). ``verify_anchors`` then checks every anchored checkpoint against the live
ledger: a rewritten prefix no longer hashes to an anchored root.

Anchor file format: JSON lines ``{"cp": {...}, "prev": "<sha256 of previous line>"}`` (hash-chained, so deleting a middle
anchor is detectable too). Hybrid (Ed25519 + ML-DSA-65) checkpoints are verified strictly when a PQ key is supplied.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audit_merkle_ledger import AuditLedger, LedgerEntry, SignedCheckpoint, merkle_root

GENESIS = "0" * 64


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


class CheckpointAnchor:
    def __init__(self, ledger: AuditLedger, path: str, *, interval_s: float = 300.0, publish: Callable[[str], None] | None = None) -> None:
        """``publish(line)`` is called with each anchor line (e.g. upload to an object-lock bucket / POST to a log)."""
        self.ledger, self.path, self.interval, self.publish = ledger, path, interval_s, publish
        self._prev = GENESIS
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        self._prev = _line_hash(line.rstrip("\n"))
        except FileNotFoundError:
            pass
        self._last_size = -1

    def anchor_once(self) -> str | None:
        """Write one anchor (skipped if the ledger has not grown). Returns the line written."""
        cp = self.ledger.checkpoint()
        if cp.size == self._last_size or cp.size == 0:
            return None
        line = json.dumps({"cp": asdict(cp), "prev": self._prev}, sort_keys=True, separators=(",", ":"))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
        self._prev, self._last_size = _line_hash(line), cp.size
        if self.publish:
            self.publish(line)
        return line

    async def run(self) -> None:
        while True:
            self.anchor_once()
            await asyncio.sleep(self.interval)


def verify_anchors(path: str, ed_public: Ed25519PublicKey, *, pq_public=None, entries: list[LedgerEntry] | None = None) -> tuple[bool, str]:
    """Verify signatures, hash-chain, monotonic sizes and (when ``entries`` given) that each anchored root is a
    prefix-root of the live ledger. Returns (ok, reason)."""
    prev, last_size, n = GENESIS, 0, 0
    leaves = [bytes.fromhex(e.leaf) for e in entries] if entries is not None else None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            doc = json.loads(line)
            if doc["prev"] != prev:
                return False, f"anchor chain broken at anchor #{n}"
            cp = SignedCheckpoint(**doc["cp"])
            ok = AuditLedger.verify_checkpoint_hybrid(cp, ed_public, pq_public) if pq_public is not None else AuditLedger.verify_checkpoint(cp, ed_public)
            if not ok:
                return False, f"bad signature at anchor #{n}"
            if cp.size < last_size:
                return False, f"ledger size went backwards at anchor #{n} ({last_size} -> {cp.size})"
            if leaves is not None:
                if cp.size > len(leaves):
                    return False, f"ledger is shorter than anchored size at anchor #{n} (history truncated)"
                if merkle_root(leaves[: cp.size]).hex() != cp.root:
                    return False, f"history rewritten: root of first {cp.size} entries differs from anchor #{n}"
            prev, last_size, n = _line_hash(line), cp.size, n + 1
    return True, f"{n} anchors verified"
