"""Tests for the evaluation metrics."""
from __future__ import annotations

from eval.metrics.metrics import (
    EvalRecord,
    attack_success_rate,
    detection_rate_per_cwe,
    false_positive_rate,
    latency_stats,
    summarise,
)


def test_attack_success_rate_baseline_vs_defended():
    baseline = [
        EvalRecord("a", expected_cwes=["CWE-89"], detected_cwes=["CWE-89"], is_adversarial=True),
        EvalRecord("b", expected_cwes=["CWE-79"], detected_cwes=["CWE-79"], is_adversarial=True),
    ]
    # Baseline applies no defence -> both vulnerabilities delivered -> ASR = 1.0
    assert attack_success_rate(baseline) == 1.0

    defended = [
        EvalRecord("a", expected_cwes=["CWE-89"], detected_cwes=["CWE-89"],
                   is_adversarial=True, blocked=True),
        EvalRecord("b", expected_cwes=["CWE-79"], detected_cwes=["CWE-79"],
                   is_adversarial=True, blocked=True),
    ]
    assert attack_success_rate(defended) == 0.0


def test_detection_rate_per_cwe():
    records = [
        EvalRecord("a", expected_cwes=["CWE-89"], detected_cwes=["CWE-89"]),
        EvalRecord("b", expected_cwes=["CWE-89"], detected_cwes=[]),
        EvalRecord("c", expected_cwes=["CWE-79"], detected_cwes=["CWE-79"]),
    ]
    rates = detection_rate_per_cwe(records)
    assert rates["CWE-89"] == 0.5
    assert rates["CWE-79"] == 1.0


def test_false_positive_rate():
    records = [
        EvalRecord("benign1", is_benign=True, detected_cwes=[]),
        EvalRecord("benign2", is_benign=True, detected_cwes=["CWE-89"]),  # false positive
        EvalRecord("benign3", is_benign=True, detected_cwes=[]),
        EvalRecord("benign4", is_benign=True, detected_cwes=[]),
    ]
    assert false_positive_rate(records) == 0.25


def test_latency_stats():
    records = [EvalRecord(str(i), latency_s=float(i)) for i in range(1, 5)]
    stats = latency_stats(records)
    assert stats["max_s"] == 4.0
    assert stats["mean_s"] == 2.5


def test_summarise_meets_targets():
    records = [
        EvalRecord("a", expected_cwes=["CWE-89"], detected_cwes=["CWE-89"],
                   is_adversarial=True, blocked=True, latency_s=0.1),
    ]
    summary = summarise(records, asr_target=0.05, latency_target_s=1.0)
    assert summary["asr_meets_target"] is True
    assert summary["latency_meets_target"] is True
    assert summary["n_samples"] == 1
