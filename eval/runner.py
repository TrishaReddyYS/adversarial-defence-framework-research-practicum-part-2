"""Evaluation runner: compare the unprotected baseline against the full defence pipeline.

For each sample it produces a paired EvalRecord under both conditions, computes the headline
metrics (ASR, per-CWE detection, false-positive rate, latency), runs the significance tests, and
writes the results to per-dataset Excel and Word reports.

Code samples (SecurityEval) are analysed directly; prompt samples (LLMSecEval, synthetic
adversarial) require an LLM client to generate the code first.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from adf.common.datasets import Sample, SampleKind
from adf.common.logging import get_logger
from adf.common.results import write_all
from adf.integration.pipeline import DefencePipeline
from adf.common.types import Verdict
from adf.llm.base import LLMClient
from eval.baselines.baseline import run_baseline
from eval.metrics.metrics import EvalRecord, summarise
from eval.metrics.oracle import oracle_available, scan_code
from eval.stats.significance import mcnemar_test, wilcoxon_test

log = get_logger("eval.runner")


@dataclass
class ComparisonResult:
    condition_metrics: dict[str, dict] = field(default_factory=dict)
    significance: dict[str, dict] = field(default_factory=dict)
    code_quality: dict = field(default_factory=dict)
    rows: list[dict] = field(default_factory=list)
    excel_path: str | None = None
    word_path: str | None = None


def run_defended(samples: list[Sample], pipeline: DefencePipeline | None = None,
                 llm_client: LLMClient | None = None) -> list[EvalRecord]:
    """Run the full defence pipeline and return one EvalRecord per sample."""
    pipeline = pipeline or DefencePipeline(llm_client=llm_client)
    use_oracle = oracle_available()
    records: list[EvalRecord] = []
    for s in samples:
        start = time.perf_counter()
        if s.kind == SampleKind.CODE:
            res = pipeline.run(code=s.text)
        elif pipeline.llm is not None:
            res = pipeline.run(prompt=s.text)
        else:
            log.info("skipping prompt sample %s (no llm_client)", s.id)
            continue
        adversarial = s.is_adversarial or bool(s.expected_cwes)
        known_vuln = s.kind == SampleKind.CODE and bool(s.expected_cwes)
        blocked = res.verdict == Verdict.BLOCK
        # Framework overhead = time inside the defence layers, excluding LLM generation.
        framework_latency = sum(layer.latency_s for layer in res.layers)
        # Independent oracle judges the delivered generated code (skipped for ground-truth CODE
        # samples, which carry their own label, and for blocked output, which delivers nothing).
        # Measured after the timed pipeline so it never inflates the latency figures.
        oracle_vuln = None
        if use_oracle and not known_vuln and not blocked and s.kind == SampleKind.PROMPT:
            oracle_vuln = scan_code(res.generated_code or "").vulnerable
        records.append(EvalRecord(
            sample_id=s.id,
            expected_cwes=list(s.expected_cwes),
            detected_cwes=sorted({f.cwe_id for f in res.all_findings}),
            is_adversarial=adversarial,
            is_benign=not adversarial and not s.expected_cwes,
            blocked=blocked,
            latency_s=time.perf_counter() - start,
            framework_latency_s=framework_latency,
            known_vulnerable=known_vuln,
            oracle_vulnerable=oracle_vuln,
        ))
    return records


# CWEs the framework is scoped to detect.
SUPPORTED_CWES = {"CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94",
                  "CWE-327", "CWE-502", "CWE-798"}


def scope_to_supported(samples: list[Sample]) -> list[Sample]:
    """Keep only samples whose labelled CWE is within the framework's target scope."""
    return [s for s in samples
            if any(c in SUPPORTED_CWES for c in s.expected_cwes)]


def _pair(baseline: list[EvalRecord], defended: list[EvalRecord]
          ) -> tuple[list[EvalRecord], list[EvalRecord]]:
    """Align the two runs by sample_id so the tests are genuinely paired."""
    d_by_id = {r.sample_id: r for r in defended}
    bb, dd = [], []
    for b in baseline:
        if b.sample_id in d_by_id:
            bb.append(b)
            dd.append(d_by_id[b.sample_id])
    return bb, dd


def evaluate(samples: list[Sample], llm_client: LLMClient | None = None,
             write_reports: bool = True, name: str = "evaluation",
             seed: int | None = 42, extra_baselines: bool = False) -> ComparisonResult:
    """Run the conditions, compute metrics + significance, and (optionally) write reports.

    `seed` enables randomised prompt ordering (internal-validity control; deterministic per seed).
    `extra_baselines` adds the single-layer input-filter and standalone-Semgrep comparison baselines.
    """
    if seed is not None:
        import random

        samples = list(samples)
        random.Random(seed).shuffle(samples)
    log.info("evaluating %d samples (seed=%s)", len(samples), seed)
    baseline = run_baseline(samples, llm_client=llm_client)
    defended = run_defended(samples, llm_client=llm_client)
    b_paired, d_paired = _pair(baseline, defended)

    result = ComparisonResult()
    result.condition_metrics["unprotected"] = summarise(b_paired)
    result.condition_metrics["defended"] = summarise(d_paired)

    # Comparison baselines: single-layer input filter + standalone Semgrep.
    if extra_baselines:
        from eval.baselines.baseline import run_input_filter_baseline, run_semgrep_baseline
        try:
            inp = run_input_filter_baseline(samples, llm_client=llm_client)
            result.condition_metrics["input_filter_only"] = summarise(_pair(inp, defended)[0])
        except Exception as exc:  # noqa: BLE001
            log.warning("input-filter baseline failed: %s", exc)
        try:
            sg = run_semgrep_baseline(samples, llm_client=llm_client)
            result.condition_metrics["semgrep_only"] = summarise(_pair(sg, defended)[0])
        except Exception as exc:  # noqa: BLE001
            log.warning("semgrep-only baseline failed: %s", exc)

    # Code-quality impact (utility must not collapse): assessed on the delivered code that is
    # directly available (CODE samples). Functional correctness is measured separately via
    # HumanEval pass@k (eval.metrics.code_quality.pass_at_k).
    from eval.metrics.code_quality import aggregate_quality, assess
    code_texts = [s.text for s in samples if s.kind == SampleKind.CODE and s.text.strip()]
    if code_texts:
        result.code_quality = aggregate_quality([assess(c) for c in code_texts])

    # Paired significance tests on adversarial samples (security outcome) + all (latency).
    adv_idx = [i for i, r in enumerate(b_paired) if r.is_adversarial]
    b_vuln = [b_paired[i].vulnerable_delivered for i in adv_idx]
    d_vuln = [d_paired[i].vulnerable_delivered for i in adv_idx]
    mc = mcnemar_test(b_vuln, d_vuln)
    wx = wilcoxon_test([r.latency_s for r in b_paired], [r.latency_s for r in d_paired])
    result.significance = {
        "mcnemar_security": mc.__dict__,
        "wilcoxon_latency": wx.__dict__,
    }

    # Per-sample rows for the Excel/Word tables.
    for b, d in zip(b_paired, d_paired):
        result.rows.append({
            "sample_id": b.sample_id,
            "adversarial": b.is_adversarial,
            "expected_cwes": ";".join(b.expected_cwes),
            "baseline_detected": ";".join(b.detected_cwes),
            "baseline_vulnerable": b.vulnerable_delivered,
            "defended_detected": ";".join(d.detected_cwes),
            "defended_blocked": d.blocked,
            "defended_vulnerable": d.vulnerable_delivered,
            "defended_latency_s": round(d.latency_s, 4),
            "defended_framework_latency_s": round(d.framework_latency_s, 4),
        })

    if write_reports:
        defended = result.condition_metrics["defended"]
        summary = {
            "unprotected_ASR": result.condition_metrics["unprotected"]["attack_success_rate"],
            "defended_ASR": defended["attack_success_rate"],
            "defended_meets_<5%": defended["asr_meets_target"],
            "defended_detection_rate": defended["overall_detection_rate"],
            "defended_false_positive_rate": defended["false_positive_rate"],
            "time_to_detection_s": defended["time_to_detection_s"],
            "defended_framework_p95_latency_s": defended["framework_p95_latency_s"],
            "defended_framework_overhead_meets_<1s": defended["latency_meets_target"],
            "defended_end_to_end_p95_latency_s": defended["p95_latency_s"],
            "mcnemar_p": mc.p_value,
            "mcnemar_significant": mc.significant,
            "wilcoxon_latency_p": wx.p_value,
        }
        for cond in ("input_filter_only", "semgrep_only"):
            if cond in result.condition_metrics:
                summary[f"{cond}_ASR"] = result.condition_metrics[cond]["attack_success_rate"]
        if result.code_quality:
            summary["compilation_success_rate"] = \
                result.code_quality.get("compilation_success_rate")
            summary["mean_cyclomatic_complexity"] = \
                result.code_quality.get("mean_cyclomatic_complexity")
            summary["mean_maintainability_index"] = \
                result.code_quality.get("mean_maintainability_index")
        xlsx, docx = write_all(result.rows, name=name,
                               title="Adversarial Defence Framework — Evaluation Results",
                               summary=summary)
        result.excel_path, result.word_path = str(xlsx), str(docx)
        log.info("wrote %s and %s", xlsx, docx)
    return result
