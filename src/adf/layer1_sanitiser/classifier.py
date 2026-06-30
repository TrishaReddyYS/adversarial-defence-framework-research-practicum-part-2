"""Hugging Face transformer classifier for prompt-injection detection.

Wraps a text-classification model behind a uniform interface and lazy-loads it on first use.
"""
from __future__ import annotations

# Public prompt-injection classifiers on the HF Hub (any text-classification model works).
_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
_INJECTION_LABELS = {"injection", "label_1", "jailbreak", "malicious", "unsafe"}

# Loaded HF pipelines are cached per model so many classifier instances share one in-memory model.
_PIPELINE_CACHE: dict = {}


class InjectionClassifier:
    """Thin wrapper over a HF text-classification pipeline. Lazy, optional."""

    def __init__(self, model: str = _DEFAULT_MODEL) -> None:
        self.model = model
        self._pipe = None
        self._loaded = False
        self._available = False

    def _try_load(self) -> bool:
        if self._loaded:
            return self._available
        self._loaded = True
        if self.model in _PIPELINE_CACHE:
            self._pipe = _PIPELINE_CACHE[self.model]
            self._available = True
            return True
        try:
            from transformers import pipeline

            self._pipe = pipeline("text-classification", model=self.model, truncation=True)
            _PIPELINE_CACHE[self.model] = self._pipe
            self._available = True
        except Exception:  # noqa: BLE001 - report unavailable; the caller decides whether to raise
            self._available = False
        return self._available

    @property
    def available(self) -> bool:
        return self._try_load()

    def injection_score(self, prompt: str) -> float | None:
        """Return P(injection) in [0,1], or None if the classifier is unavailable."""
        if not self._try_load() or self._pipe is None:
            return None
        try:
            out = self._pipe(prompt)
        except Exception:  # noqa: BLE001
            return None
        if not out:
            return None
        row = out[0]
        label = str(row.get("label", "")).strip().lower()
        score = float(row.get("score", 0.0))
        if label in _INJECTION_LABELS:
            return score
        return 1.0 - score  # model returned the "safe" label
