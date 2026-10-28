"""Central, immutable configuration. Every default is the *restrictive* choice."""

from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, ConfigDict


class ShieldSettings(BaseModel):
    """Runtime settings. Override any field with ``SHIELD_<FIELD_NAME>`` env vars."""

    model_config = ConfigDict(frozen=True)

    # --- ingress limits (fail closed when exceeded) ---
    max_body_bytes: int = 1_048_576
    max_text_chars: int = 200_000
    max_image_bytes: int = 8_000_000
    max_image_pixels: int = 25_000_000
    max_rag_chunks: int = 64

    # --- risk thresholds (0.0 - 1.0) ---
    heal_threshold: float = 0.35  # >= : try to sanitize / rewrite
    hitl_threshold: float = 0.60  # >= : human approval for side-effecting tools
    block_threshold: float = 0.85  # >= : hard block unless healed below this

    # --- concurrency / timeouts ---
    hunter_timeout_s: float = 0.25  # a hunter that times out counts as a finding
    hitl_timeout_s: float = 300.0
    hitl_fallback: Literal["deny"] = "deny"  # never auto-approve on timeout

    # --- identity ---
    token_ttl_s: int = 900
    challenge_ttl_s: int = 60
    audience: str = "agentshield-x"

    # --- vision ---
    require_ocr: bool = False  # True in prod: OCR unavailable => block images
    require_cnn: bool = False  # True in prod: missing ONNX model => images are blocked
    visual_model_path: str = "models/visual_guard.onnx"

    # --- sandbox ---
    sandbox_backend: Literal["docker", "kubernetes"] = "docker"
    sandbox_namespace: str = "agentshield-sandbox"  # kubernetes backend: namespace for short-lived sandbox pods
    sandbox_image: str = "agentshield/sandbox-python:1"
    sandbox_runtime: str = ""  # docker: OCI runtime (e.g. "runsc"); kubernetes: RuntimeClass name (e.g. "gvisor")
    sandbox_timeout_s: float = 10.0
    sandbox_memory: str = "128m"
    sandbox_cpus: float = 0.5
    sandbox_pids: int = 64
    sandbox_max_output_bytes: int = 65_536
    sandbox_egress_network: str = ""  # docker --internal network that only the egress proxy can leave
    sandbox_egress_proxy: str = ""  # e.g. http://egress-proxy:3128

    # --- audit ---
    audit_path: str = ""  # JSONL sink; empty = memory only

    # --- rate limiting ---
    rate_limit_per_min: int = 120

    @classmethod
    def from_env(cls) -> "ShieldSettings":
        """Build settings from ``SHIELD_*`` environment variables."""
        raw = {
            name: os.environ[f"SHIELD_{name.upper()}"]
            for name in cls.model_fields
            if f"SHIELD_{name.upper()}" in os.environ
        }
        return cls(**raw)
