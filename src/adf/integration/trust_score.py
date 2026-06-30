"""Trust scoring: combine the three layers' risk into one score and a graduated verdict.

Each layer reports a risk in [0, 1]; the trust score is 1 minus their weighted sum, and the
verdict thresholds map it to approve / flag / block.
"""
from __future__ import annotations

from adf.common.config import Config, load_config
from adf.common.types import LayerResult, Verdict


class TrustScorer:
    def __init__(self, config: Config | None = None) -> None:
        cfg = config or load_config()
        weights = cfg.get("trust_score.weights", {}) or {}
        self.weights = {
            "layer1_sanitiser": float(weights.get("layer1", 0.35)),
            "layer2_ast_cwe": float(weights.get("layer2", 0.45)),
            "layer3_sandbox": float(weights.get("layer3", 0.20)),
        }
        self.approve_above = float(cfg.get("trust_score.approve_above", 0.80))
        self.block_below = float(cfg.get("trust_score.block_below", 0.40))

    def score(self, layers: list[LayerResult]) -> float:
        """Weighted-sum trust across the layers that actually ran.

        Inactive layers (e.g. Layer 3 when Docker is absent) are excluded and the remaining
        weights are renormalised, so a missing sandbox doesn't silently inflate trust.
        """
        active = [layer for layer in layers if self._is_active(layer)]
        if not active:
            return 1.0
        total_w = sum(self.weights.get(layer.layer, 0.0) for layer in active)
        if total_w <= 0:
            # Unknown layers: fall back to the max risk (most conservative).
            risk = max(layer.risk for layer in active)
            return max(0.0, 1.0 - risk)
        weighted_risk = sum(
            self.weights.get(layer.layer, 0.0) * layer.risk for layer in active
        ) / total_w
        return max(0.0, min(1.0, 1.0 - weighted_risk))

    @staticmethod
    def _is_active(layer: LayerResult) -> bool:
        if layer.layer == "layer3_sandbox":
            return bool(layer.metadata.get("sandbox_available", False))
        return True

    def verdict(self, trust: float, layers: list[LayerResult] | None = None) -> Verdict:
        """Return the verdict for the request.

        Code with a confirmed CWE finding from Layer 2 or Layer 3 is blocked. Otherwise the trust
        score selects the verdict: approve at or above the approve threshold, block below the block
        threshold, and flag in between.
        """
        if layers and self._has_confirmed_vulnerability(layers):
            return Verdict.BLOCK
        if trust >= self.approve_above:
            return Verdict.APPROVE
        if trust < self.block_below:
            return Verdict.BLOCK
        return Verdict.FLAG

    @staticmethod
    def _has_confirmed_vulnerability(layers: list[LayerResult]) -> bool:
        for layer in layers:
            if layer.layer in ("layer2_ast_cwe", "layer3_sandbox") and layer.findings:
                return True
        return False
