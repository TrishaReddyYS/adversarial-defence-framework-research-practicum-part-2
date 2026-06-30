"""The full defence pipeline: the three layers wired together with trust scoring.

Flow (application-layer, model treated as a black box):

    prompt
      -> Layer 1 (sanitise)         [block here if prompt is clearly adversarial]
      -> LLM generates code         [the developer's model; optional/injected]
      -> Layer 2 (AST/CWE scan)
      -> Layer 3 (sandbox validate, using Layer 2 findings as threat intel)
      -> Trust score -> verdict (approve / flag / block)

The LLM is optional: if no client is supplied, the pipeline can analyse pre-existing code
directly (used for the SecurityEval benchmark and unit tests).
"""
from __future__ import annotations

import time

from adf.common.config import Config, load_config
from adf.common.logging import get_logger
from adf.common.types import PipelineResult, Verdict
from adf.integration.trust_score import TrustScorer
from adf.layer1_sanitiser.sanitiser import PromptSanitiser
from adf.layer2_ast_cwe.detector import Layer2Detector
from adf.layer3_sandbox.validator import Layer3Validator
from adf.llm.base import LLMClient

log = get_logger("pipeline")


class DefencePipeline:
    """Orchestrates Layers 1-3 + trust scoring."""

    def __init__(self, config: Config | None = None, llm_client: LLMClient | None = None,
                 use_classifier: bool = False) -> None:
        self.config = config or load_config()
        self.llm = llm_client
        self.layer1 = PromptSanitiser(self.config, use_classifier=use_classifier)
        self.layer2 = Layer2Detector(self.config)
        self.layer3 = Layer3Validator(self.config)
        self.scorer = TrustScorer(self.config)

    def run(self, prompt: str | None = None, code: str | None = None) -> PipelineResult:
        """Defend one request.

        Provide `prompt` (and an llm_client) to generate+defend, or `code` to defend an
        existing snippet directly.
        """
        start = time.perf_counter()
        result = PipelineResult(prompt=prompt or "")

        # --- Layer 1: sanitise the incoming prompt -------------------------------------------
        if prompt is not None:
            san = self.layer1.sanitise(prompt)
            result.layers.append(san.layer_result)
            result.sanitised_prompt = san.sanitised_prompt
            if san.action == "block":
                # Adversarial prompt blocked before it ever reaches the model.
                result.blocked_pre_generation = True
                result.verdict = Verdict.BLOCK
                result.trust_score = san.layer_result.trust
                result.total_latency_s = time.perf_counter() - start
                return result

        # --- obtain the code (generate, or use provided) -------------------------------------
        if code is None:
            if prompt is None:
                raise ValueError("Provide either a prompt or code.")
            if self.llm is None:
                # No model wired (e.g. running Layer-1-only). Nothing to scan downstream.
                result.trust_score = self.scorer.score(result.layers)
                result.verdict = self.scorer.verdict(result.trust_score, result.layers)
                result.total_latency_s = time.perf_counter() - start
                return result
            gen_prompt = result.sanitised_prompt or prompt
            try:
                code = self.llm.generate_code(gen_prompt)
            except Exception as exc:  # noqa: BLE001 - surface as a blocked result, no crash
                log.warning("generation failed: %s", exc)
                result.verdict = Verdict.FLAG
                result.total_latency_s = time.perf_counter() - start
                return result
        result.generated_code = code

        # --- Layer 2: static AST/CWE analysis ------------------------------------------------
        l2 = self.layer2.detect(code)
        result.layers.append(l2)

        # --- Layer 3: sandbox validation, using Layer 2 findings as threat intel -------------
        l3 = self.layer3.validate(code, prior_findings=l2.findings)
        result.layers.append(l3)

        # --- trust score + verdict -----------------------------------------------------------
        result.trust_score = self.scorer.score(result.layers)
        result.verdict = self.scorer.verdict(result.trust_score, result.layers)
        result.total_latency_s = time.perf_counter() - start
        return result
