"""Environment-driven assembly of the production pipeline (kept out of ``app.py`` so it is unit-testable without FastAPI).

Environment (all optional; secure defaults apply when unset):
  SHIELD_POLICY_DIR       directory with tools.yaml / abac.yaml (strictly validated; invalid => startup FAILS, never falls back)
  SHIELD_LEDGER_KEY_DIR   directory produced by ``agentshield keygen``: persistent Ed25519 (+ ML-DSA-65) checkpoint keys
  SHIELD_ANCHOR_PATH      file that receives hash-chained signed checkpoints (ship it to WORM storage)
  SHIELD_ANCHOR_INTERVAL_S  seconds between anchors (default 300)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization as ser

from .anchor import CheckpointAnchor
from .audit_merkle_ledger import AuditLedger
from .config import ShieldSettings
from .hitl import InMemoryNotifier, Notifier
from .pipeline import ShieldPipeline
from .policy_engine import PolicyEngine


def load_ledger_keys(directory: str | Path) -> tuple[Any, Any | None]:
    """Returns (ed25519_private, mldsa65_private | None). Refuses group/world-readable private key files."""
    d = Path(directory)
    out: list[Any] = []
    for name in ("ledger_ed25519.key.pem", "ledger_mldsa65.key.pem"):
        p = d / name
        if not p.exists():
            out.append(None)
            continue
        if p.stat().st_mode & 0o077:
            raise PermissionError(f"{p} is readable by group/others; chmod 600 it")
        out.append(ser.load_pem_private_key(p.read_bytes(), password=None))
    if out[0] is None:
        raise FileNotFoundError(f"{d}/ledger_ed25519.key.pem not found (run `agentshield keygen --out {d}`)")
    return out[0], out[1]


def build_pipeline(s: ShieldSettings, env: Mapping[str, str] | None = None, *, sinks: list[Any] | None = None,
                   notifier: Notifier | None = None) -> tuple[ShieldPipeline, CheckpointAnchor | None]:
    env = os.environ if env is None else env
    registry = policy = None
    if env.get("SHIELD_POLICY_DIR"):
        from .policy_loader import load_policy_dir
        registry, rules = load_policy_dir(env["SHIELD_POLICY_DIR"])  # raises PolicyError -> process exits; no silent fallback
        policy = PolicyEngine(registry, rules)
    ed = pq = None
    if env.get("SHIELD_LEDGER_KEY_DIR"):
        ed, pq = load_ledger_keys(env["SHIELD_LEDGER_KEY_DIR"])
    ledger = AuditLedger(ed, sinks=list(sinks or []), pq_key=pq)
    key = env.get("SHIELD_APPROVAL_KEY")
    pipe = ShieldPipeline(s, registry=registry, policy=policy, ledger=ledger, notifier=notifier or InMemoryNotifier(),
                          approval_key=bytes.fromhex(key) if key else None)
    anchor = CheckpointAnchor(ledger, env["SHIELD_ANCHOR_PATH"], interval_s=float(env.get("SHIELD_ANCHOR_INTERVAL_S", "300"))) if env.get("SHIELD_ANCHOR_PATH") else None
    return pipe, anchor
