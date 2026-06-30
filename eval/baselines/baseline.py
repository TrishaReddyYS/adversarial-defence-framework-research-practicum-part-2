"""Baseline harness: measure vulnerability rate with NO defence applied.

This is the measurement backbone every defended condition is compared against. For CODE samples
(e.g. SecurityEval) the code is analysed directly with no LLM. For PROMPT samples (LLMSecEval,
synthetic adversarial) an LLM client generates the code first.
"""
from __future__ import annotations

import time

from adf.common.datasets import Sample, SampleKind
from adf.common.logging import get_logger
from adf.layer2_ast_cwe.detector import Layer2Detector
from adf.llm.base import LLMClient
from eval.metrics.metrics import EvalRecord
from eval.metrics.oracle import oracle_available, scan_code

log = get_logger("eval.baseline")


def _oracle_verdict(s: Sample, code: str | None, blocked: bool, use_oracle: bool) -> bool | None:
    """Independent-oracle verdict on the delivered code for a generated (PROMPT) sample.

    Returns None when the oracle does not apply (oracle unavailable, blocked output, ground-truth
    CODE sample, or no code produced) so the metric falls back to the appropriate label.
    """
    if not use_oracle or blocked or s.kind != SampleKind.PROMPT or not code:
        return None
    return scan_code(code).vulnerable


def run_baseline(
    samples: list[Sample],
    detector: Layer2Detector | None = None,
    llm_client: LLMClient | None = None,
) -> list[EvalRecord]:
    """Run the unprotected condition and return one EvalRecord per processed sample."""
    detector = detector or Layer2Detector()
    use_oracle = oracle_available()
    records: list[EvalRecord] = []

    for s in samples:
        start = time.perf_counter()
        if s.kind == SampleKind.CODE:
            code = s.text
        elif llm_client is not None:
            try:
                code = llm_client.generate_code(s.text)
            except Exception as exc:  # noqa: BLE001 - record failure, keep the run going
                log.warning("generation failed for %s: %s", s.id, exc)
                continue
        else:
            log.info("skipping prompt sample %s (no llm_client provided)", s.id)
            continue

        result = detector.detect(code, language=s.language)
        # Benchmark samples with a labelled CWE represent vulnerability scenarios (adversarial).
        adversarial = s.is_adversarial or bool(s.expected_cwes)
        known_vuln = s.kind == SampleKind.CODE and bool(s.expected_cwes)
        records.append(
            EvalRecord(
                sample_id=s.id,
                expected_cwes=list(s.expected_cwes),
                detected_cwes=sorted({f.cwe_id for f in result.findings}),
                is_adversarial=adversarial,
                is_benign=not adversarial and not s.expected_cwes,
                blocked=False,  # baseline applies no defence
                latency_s=time.perf_counter() - start,
                known_vulnerable=known_vuln,
                oracle_vulnerable=_oracle_verdict(s, code, blocked=False, use_oracle=use_oracle),
            )
        )
    return records


def _generate_or_code(s: Sample, llm_client: LLMClient | None) -> str | None:
    """Return the code for a sample: the code itself (CODE) or an LLM generation (PROMPT)."""
    if s.kind == SampleKind.CODE:
        return s.text
    if llm_client is None:
        return None
    try:
        return llm_client.generate_code(s.text)
    except Exception as exc:  # noqa: BLE001
        log.warning("generation failed for %s: %s", s.id, exc)
        return None


def _record(s: Sample, detected: list[str], blocked: bool, start: float,
            code: str | None = None, use_oracle: bool = False) -> EvalRecord:
    adversarial = s.is_adversarial or bool(s.expected_cwes)
    return EvalRecord(
        sample_id=s.id,
        expected_cwes=list(s.expected_cwes),
        detected_cwes=detected,
        is_adversarial=adversarial,
        is_benign=not adversarial and not s.expected_cwes,
        blocked=blocked,
        latency_s=time.perf_counter() - start,
        known_vulnerable=s.kind == SampleKind.CODE and bool(s.expected_cwes),
        oracle_vulnerable=_oracle_verdict(s, code, blocked=blocked, use_oracle=use_oracle),
    )


def run_input_filter_baseline(samples: list[Sample], llm_client: LLMClient | None = None,
                              config=None) -> list[EvalRecord]:
    """Baseline: single-layer INPUT filtering only (Layer 1 prompt sanitisation, no code analysis).

    Blocks adversarial prompts at the input, but performs no output/static/runtime checks. A
    measurement-only Layer 2 pass records whether the delivered code is actually vulnerable.
    """
    from adf.layer1_sanitiser.sanitiser import PromptSanitiser

    san = PromptSanitiser(config)
    measure = Layer2Detector(config)
    use_oracle = oracle_available()
    records: list[EvalRecord] = []
    for s in samples:
        start = time.perf_counter()
        blocked = False
        prompt_text = s.text
        if s.kind == SampleKind.PROMPT:
            res = san.sanitise(s.text)
            blocked = res.action == "block"
            prompt_text = res.sanitised_prompt or s.text
        if blocked:
            records.append(_record(s, [], True, start))
            continue
        code = s.text if s.kind == SampleKind.CODE else _generate_or_code(
            Sample(id=s.id, text=prompt_text, kind=s.kind, language=s.language), llm_client)
        if code is None:
            continue
        # Measurement only — the input-filter defence does NOT itself analyse the output.
        detected = sorted({f.cwe_id for f in measure.detect(code, language=s.language).findings})
        records.append(_record(s, detected, False, start, code=code, use_oracle=use_oracle))
    return records


def run_semgrep_baseline(samples: list[Sample], llm_client: LLMClient | None = None,
                         config=None, semgrep_config: str = "p/python") -> list[EvalRecord]:
    """Baseline: standalone static analysis (Semgrep with default rulesets only).

    No prompt sanitisation, no AST layer, no sandbox. Semgrep's default registry rules flag the
    delivered code; a finding is treated as a block.
    """
    from adf.layer2_ast_cwe.semgrep_scanner import SemgrepScanner

    scanner = SemgrepScanner(config=semgrep_config)
    use_oracle = oracle_available()
    records: list[EvalRecord] = []
    for s in samples:
        start = time.perf_counter()
        code = _generate_or_code(s, llm_client)
        if code is None:
            continue
        findings = scanner.scan(code, language=s.language)
        detected = sorted({f.cwe_id for f in findings})
        records.append(_record(s, detected, blocked=bool(findings), start=start,
                               code=code, use_oracle=use_oracle))
    return records
