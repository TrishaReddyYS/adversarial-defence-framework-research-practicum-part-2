"""Layer 1: pre-generation prompt sanitisation.

Combines pattern-based injection detection, an intent-deviation heuristic, and an optional
transformer classifier into a single risk score, then takes a graduated action:
approve (pass through) -> flag/sanitise (strip injected instructions) -> block.
"""
from __future__ import annotations

import re
import time

from adf.common.config import Config, load_config
from adf.common.types import LayerResult
from adf.layer1_sanitiser.classifier import InjectionClassifier
from adf.layer1_sanitiser.patterns import Signal, detect_signals

# Imperative verbs that signal an embedded *instruction* (vs. a task description).
_IMPERATIVE_RE = re.compile(
    r"\b(ignore|disregard|forget|disable|bypass|insert|concatenate|hard-?code|"
    r"reveal|print|exfiltrate|override|skip)\b",
    re.I,
)
# Phrases that mark a pivot away from the originally declared task.
_PIVOT_RE = re.compile(r"\b(instead|rather than|but first|actually|now)\b", re.I)


class SanitisationResult:
    """Detailed Layer 1 outcome (wraps a LayerResult with the sanitised prompt + action)."""

    def __init__(self, layer_result: LayerResult, sanitised_prompt: str,
                 action: str, signals: list[Signal]):
        self.layer_result = layer_result
        self.sanitised_prompt = sanitised_prompt
        self.action = action            # "approve" | "sanitise" | "block"
        self.signals = signals


def intent_deviation_score(prompt: str) -> float:
    """Heuristic: how strongly does the prompt embed instructions / pivot from its task?

    A benign code request describes *what* to build. Injected prompts add *commands* ("ignore...",
    "instead do...") that deviate from the declared intent. Returns a score in [0, 1].
    """
    score = 0.0
    if _IMPERATIVE_RE.search(prompt):
        score += 0.5
    if _PIVOT_RE.search(prompt):
        score += 0.3
    # Multiple sentences where a later one issues a command is a classic hijack shape.
    sentences = [s for s in re.split(r"[.\n]", prompt) if s.strip()]
    if len(sentences) > 1 and _IMPERATIVE_RE.search(sentences[-1]):
        score += 0.2
    return min(score, 1.0)


class PromptSanitiser:
    """Layer 1 entry point."""

    LAYER = "layer1_sanitiser"

    def __init__(self, config: Config | None = None, use_classifier: bool | None = None) -> None:
        self.config = config or load_config()
        self.block_threshold = float(self.config.get("layer1_sanitiser.block_threshold", 0.80))
        self.flag_threshold = float(self.config.get("layer1_sanitiser.flag_threshold", 0.50))
        self.strip_on_flag = bool(self.config.get("layer1_sanitiser.strip_on_flag", True))
        # The transformer classifier is enabled by default.
        if use_classifier is None:
            use_classifier = bool(self.config.get("layer1_sanitiser.use_classifier", True))
        self._classifier = InjectionClassifier() if use_classifier else None
        if self._classifier is not None and not self._classifier.available:
            raise RuntimeError(
                "Layer 1 requires the transformer injection classifier, but it could not be "
                "loaded. Install the LLM extra (pip install -e '.[llm]') and ensure network "
                "access for the first model download, or set layer1_sanitiser.use_classifier=false."
            )

    def _combine(self, signals: list[Signal], intent: float, clf: float | None) -> float:
        """Combine the pattern, intent-deviation, and classifier signals into one risk score."""
        pattern_risk = max((s.score for s in signals), default=0.0)
        components = [pattern_risk, intent * 0.7]
        if clf is not None:
            # The classifier contributes in full when a pattern or intent signal corroborates it,
            # and a capped amount otherwise.
            corroborated = pattern_risk > 0.0 or intent >= 0.3
            components.append(clf if corroborated else min(clf, 0.55))
        # Combine the signals so that a strong signal from any source raises the overall risk.
        inv = 1.0
        for c in components:
            inv *= 1.0 - min(max(c, 0.0), 1.0)
        return 1.0 - inv

    def _strip(self, prompt: str, signals: list[Signal]) -> str:
        """Remove the highest-risk injected spans, keeping the benign task description."""
        spans = sorted(
            (s.span for s in signals if s.score >= 0.6 and s.span != (0, 0)),
            key=lambda sp: sp[0],
            reverse=True,
        )
        cleaned = prompt
        for start, end in spans:
            cleaned = cleaned[:start] + cleaned[end:]
        cleaned = re.sub(r"\s{2,}", " ", cleaned).strip(" .;,-")
        return cleaned or prompt

    def sanitise(self, prompt: str) -> SanitisationResult:
        start = time.perf_counter()
        signals = detect_signals(prompt)
        intent = intent_deviation_score(prompt)
        clf = self._classifier.injection_score(prompt) if self._classifier else None
        risk = self._combine(signals, intent, clf)

        if risk >= self.block_threshold:
            action, sanitised = "block", ""
        elif risk >= self.flag_threshold:
            action = "sanitise"
            sanitised = self._strip(prompt, signals) if self.strip_on_flag else prompt
        else:
            action, sanitised = "approve", prompt

        result = LayerResult(
            layer=self.LAYER,
            risk=risk,
            findings=[],
            latency_s=time.perf_counter() - start,
            metadata={
                "action": action,
                "intent_deviation": round(intent, 3),
                "classifier_score": None if clf is None else round(clf, 3),
                "n_signals": len(signals),
                "signal_kinds": sorted({s.kind.value for s in signals}),
            },
        )
        return SanitisationResult(result, sanitised, action, signals)
