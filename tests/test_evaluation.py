"""Tests for the evaluation runner, metrics, and significance tests."""
from __future__ import annotations

from adf.common.datasets import Sample, SampleKind, generate_adversarial
from eval.metrics.metrics import (
    EvalRecord,
    attack_success_rate,
    false_positive_rate,
    summarise,
)
from eval.runner import evaluate, run_defended
from eval.stats.significance import mcnemar_test, wilcoxon_test


# --- metrics --------------------------------------------------------------------------------
def test_asr_counts_delivered_vulnerabilities():
    recs = [
        EvalRecord("a", expected_cwes=["CWE-89"], detected_cwes=["CWE-89"],
                   is_adversarial=True, blocked=False),     # delivered vuln
        EvalRecord("b", expected_cwes=["CWE-89"], detected_cwes=[],
                   is_adversarial=True, blocked=True),       # blocked -> safe
    ]
    assert attack_success_rate(recs) == 0.5


def test_fpr_zero_when_benign_not_flagged():
    recs = [EvalRecord("x", expected_cwes=[], detected_cwes=[], is_benign=True, blocked=False)]
    assert false_positive_rate(recs) == 0.0


# --- significance ---------------------------------------------------------------------------
def test_mcnemar_detects_improvement():
    # Defence fixes 8 vulnerable cases, breaks none.
    base = [True] * 10
    deff = [False] * 8 + [True] * 2
    res = mcnemar_test(base, deff)
    assert res.significant is True


def test_mcnemar_no_discordant_pairs():
    res = mcnemar_test([True, False], [True, False])
    assert res.p_value == 1.0 and res.significant is False


def test_wilcoxon_runs_on_latency():
    res = wilcoxon_test([0.1, 0.2, 0.3], [0.15, 0.25, 0.35])
    assert 0.0 <= res.p_value <= 1.0


# --- runner (code-only path, no LLM) --------------------------------------------------------
def test_run_defended_on_code_samples():
    samples = [
        Sample(id="vuln1", text="def f(x):\n    return eval(x)\n",
               kind=SampleKind.CODE, expected_cwes=["CWE-94"]),
        Sample(id="safe1", text="def add(a, b):\n    return a + b\n",
               kind=SampleKind.CODE),
    ]
    recs = run_defended(samples)
    assert len(recs) == 2
    vuln = next(r for r in recs if r.sample_id == "vuln1")
    assert "CWE-94" in vuln.detected_cwes


def test_evaluate_defended_beats_baseline_on_adversarial_code():
    """End-to-end: on code-bearing adversarial samples, defended ASR <= baseline ASR."""
    samples = [s for s in generate_adversarial() if s.kind == SampleKind.CODE]
    if not samples:  # synthetic set is prompt-based; fall back to explicit code samples
        samples = [
            Sample(id=f"v{i}", text="import os\ndef run(c):\n    os.system(c)\n",
                   kind=SampleKind.CODE, expected_cwes=["CWE-78"], adversarial=True)
            for i in range(5)
        ]
    res = evaluate(samples, write_reports=False)
    b = res.condition_metrics["unprotected"]["attack_success_rate"]
    d = res.condition_metrics["defended"]["attack_success_rate"]
    assert d <= b


def test_summarise_has_headline_fields():
    s = summarise([EvalRecord("a", is_adversarial=True, blocked=True)])
    for key in ("attack_success_rate", "false_positive_rate", "p95_latency_s",
                "asr_meets_target"):
        assert key in s


# --- code quality --------------------------------------------------------------------------
def test_code_quality_assess():
    from eval.metrics.code_quality import assess
    q = assess("def add(a, b):\n    return a + b\n")
    assert q.compiles is True
    assert q.maintainability_index > 0


def test_code_quality_compile_failure():
    from eval.metrics.code_quality import assess
    assert assess("def broken(:\n    pass").compiles is False


def test_pass_at_k_estimator():
    from eval.metrics.code_quality import pass_at_k
    assert pass_at_k([[True], [True]], k=1) == 1.0
    assert pass_at_k([[False], [False]], k=1) == 0.0
    assert pass_at_k([[True], [False]], k=1) == 0.5


def test_passes_tests_runs_unit_test():
    from eval.metrics.code_quality import passes_tests
    assert passes_tests("def sq(x):\n    return x*x\n", "assert sq(3) == 9") is True
    assert passes_tests("def sq(x):\n    return x+x\n", "assert sq(3) == 9") is False


def test_time_to_detection_metric():
    from eval.metrics.metrics import EvalRecord, time_to_detection
    recs = [EvalRecord("a", detected_cwes=["CWE-89"], latency_s=0.4),
            EvalRecord("b", detected_cwes=[], latency_s=9.0)]  # not flagged -> excluded
    assert time_to_detection(recs) == 0.4


# --- baselines (code-only, no LLM) ----------------------------------------------------------
def test_input_filter_baseline_on_code():
    from eval.baselines.baseline import run_input_filter_baseline
    samples = [Sample(id="v", text="def f(x):\n    return eval(x)\n",
                      kind=SampleKind.CODE, expected_cwes=["CWE-94"])]
    recs = run_input_filter_baseline(samples)
    assert len(recs) == 1
    # input filter does not analyse output, but measurement detects the known vuln
    assert recs[0].known_vulnerable is True


def test_randomised_ordering_is_deterministic_per_seed():
    from eval.runner import evaluate
    samples = [Sample(id=f"s{i}", text="def add(a,b):\n    return a+b\n",
                      kind=SampleKind.CODE) for i in range(6)]
    r1 = evaluate(samples, write_reports=False, seed=42)
    r2 = evaluate(samples, write_reports=False, seed=42)
    assert [row["sample_id"] for row in r1.rows] == [row["sample_id"] for row in r2.rows]


# --- HumanEval loader -----------------------------------------------------------------------
def test_humaneval_loads():
    from eval.humaneval import load_humaneval
    probs = load_humaneval()
    assert len(probs) == 164
    assert probs[0].entry_point and probs[0].test
