"""Learned prompt-injection classifier hook (the paraphrase-coverage layer).

Regex signatures cannot generalize to paraphrases (see ``evals/paraphrase_eval.py``: ~2/10 on
unseen attacks). Production deployments should enable a learned classifier:

    clf = OnnxTextClassifier("models/injection_guard.onnx", "models/tokenizer.json", attack_labels=(1, 2))
    pipeline = ShieldPipeline(settings, text_classifier=clf)

Any ONNX sequence-classification export works (e.g. a DeBERTa/MiniLM fine-tune or Llama Prompt Guard
style model). No weights are bundled. Fail-closed semantics: if ``require_classifier`` is set on the
pipeline and the model is unavailable or errors, inputs are scored as high risk.
"""

from __future__ import annotations

import os
from typing import Protocol, Sequence

import numpy as np


class SyncTextClassifier(Protocol):
    available: bool

    def score_sync(self, text: str) -> float:
        """Probability in [0, 1] that ``text`` is an injection/jailbreak attempt."""
        ...


class OnnxTextClassifier:
    """ONNX Runtime sequence classifier with a Hugging Face ``tokenizers`` JSON tokenizer."""

    def __init__(self, model_path: str, tokenizer_path: str, *, attack_labels: Sequence[int] = (1,), max_len: int = 256) -> None:
        self.available = False
        self.attack_labels = tuple(attack_labels)
        self.max_len = max_len
        self._sess = None
        self._tok = None
        if not (os.path.isfile(model_path) and os.path.isfile(tokenizer_path)):
            return
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer  # type: ignore[import-not-found]

            self._tok = Tokenizer.from_file(tokenizer_path)
            self._tok.enable_truncation(max_length=max_len)
            so = ort.SessionOptions()
            so.intra_op_num_threads = 1
            self._sess = ort.InferenceSession(model_path, so, providers=["CPUExecutionProvider"])
            self._inputs = {i.name for i in self._sess.get_inputs()}
            self.available = True
        except Exception:  # noqa: BLE001 - missing optional dep / corrupt model => unavailable
            self.available = False

    def score_sync(self, text: str) -> float:
        enc = self._tok.encode(text)  # type: ignore[union-attr]
        feed = {"input_ids": np.array([enc.ids], dtype=np.int64), "attention_mask": np.array([enc.attention_mask], dtype=np.int64)}
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = np.zeros_like(feed["input_ids"])
        logits = self._sess.run(None, {k: v for k, v in feed.items() if k in self._inputs})[0][0].astype(np.float64)  # type: ignore[union-attr]
        e = np.exp(logits - logits.max())
        p = e / e.sum()
        return float(sum(p[i] for i in self.attack_labels))
