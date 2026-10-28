"""Embedding backends used for intent divergence and vector-drift analysis.

``HashingEmbedder`` is a deterministic, dependency-light baseline (signed
feature hashing over word/bigram/char-trigram features). It is good enough for
*relative* similarity checks and tests; plug in ``TransformersEmbedder`` (or any
object implementing :class:`Embedder`) for production-grade semantics.
"""

from __future__ import annotations

import math
import re
import zlib
from typing import Protocol, Sequence

import numpy as np

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


class Embedder(Protocol):
    dim: int

    def embed(self, text: str) -> np.ndarray: ...
    def embed_many(self, texts: Sequence[str]) -> np.ndarray: ...


class HashingEmbedder:
    """Signed feature-hashing embedder. Deterministic across processes."""

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def embed(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        toks = _TOKEN_RE.findall(text.lower())
        feats: list[str] = list(toks)
        feats += [f"{a}_{b}" for a, b in zip(toks, toks[1:])]
        for t in toks:
            if len(t) > 3:
                feats += [t[i : i + 3] for i in range(len(t) - 2)]
        for f in feats:
            h = zlib.crc32(f.encode("utf-8", "ignore"))
            vec[h % self.dim] += 1.0 if (h >> 31) & 1 else -1.0
        n = float(np.linalg.norm(vec))
        return vec / n if n else vec

    def embed_many(self, texts: Sequence[str]) -> np.ndarray:
        return np.stack([self.embed(t) for t in texts]) if texts else np.zeros((0, self.dim), np.float32)


class TransformersEmbedder:  # pragma: no cover - requires torch + HF weights
    """Mean-pooled Hugging Face encoder (e.g. ``sentence-transformers/all-MiniLM-L6-v2``)."""

    def __init__(self, model_name: str, device: str = "cpu") -> None:
        import torch
        from transformers import AutoModel, AutoTokenizer

        self._torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(device).eval()
        self.device = device
        self.dim = int(self.model.config.hidden_size)

    def embed_many(self, texts: Sequence[str]) -> np.ndarray:
        torch = self._torch
        with torch.inference_mode():
            enc = self.tok(list(texts), padding=True, truncation=True, max_length=256, return_tensors="pt").to(self.device)
            out = self.model(**enc).last_hidden_state
            mask = enc["attention_mask"].unsqueeze(-1)
            pooled = (out * mask).sum(1) / mask.sum(1).clamp(min=1)
            pooled = torch.nn.functional.normalize(pooled, dim=-1)
        return pooled.cpu().numpy().astype(np.float32)

    def embed(self, text: str) -> np.ndarray:
        return self.embed_many([text])[0]


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = float(np.linalg.norm(a)), float(np.linalg.norm(b))
    return float(np.dot(a, b) / (na * nb)) if na and nb else 0.0


class RunningCentroid:
    """Online centroid + distance statistics (Welford) for one RAG collection.

    Drift is the z-score of a chunk's cosine distance from the collection
    centroid relative to the historical distance distribution.
    """

    def __init__(self, dim: int, warmup: int = 8) -> None:
        self.centroid = np.zeros(dim, dtype=np.float64)
        self.n = 0
        self._mean = 0.0
        self._m2 = 0.0
        self.warmup = warmup

    def distance(self, v: np.ndarray) -> float:
        return 1.0 - cosine(self.centroid.astype(np.float32), v) if self.n else 0.0

    def zscore(self, v: np.ndarray) -> float:
        if self.n < self.warmup:
            return 0.0
        std = math.sqrt(self._m2 / max(self.n - 1, 1)) or 1e-3
        return (self.distance(v) - self._mean) / max(std, 0.02)

    def update(self, v: np.ndarray) -> None:
        """Only call with chunks that passed all checks (never learn from attacks)."""
        d = self.distance(v)
        self.n += 1
        delta = d - self._mean
        self._mean += delta / self.n
        self._m2 += delta * (d - self._mean)
        self.centroid += (v - self.centroid) / self.n
