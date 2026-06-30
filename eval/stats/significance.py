"""Statistical significance tests for the protected-vs-unprotected comparison.

Implements two paired tests:
  * McNemar's test  -> paired binary outcomes (vulnerable / secure) per sample.
  * Wilcoxon signed-rank -> paired continuous outcomes (e.g. per-sample latency).

SciPy is used when available; a self-contained fallback keeps the tests usable without it
(McNemar via an exact binomial / chi-square; Wilcoxon via the normal approximation).
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class TestResult:
    name: str
    statistic: float
    p_value: float
    significant: bool
    detail: str = ""


def mcnemar_test(baseline_vuln: list[bool], defended_vuln: list[bool],
                 alpha: float = 0.05) -> TestResult:
    """Paired test on whether the defence changes the vulnerable/secure outcome.

    `*_vuln[i]` is True if sample i shipped a vulnerability under that condition.
    Discordant pairs: b = baseline-vuln & defended-secure (fixed by defence);
                      c = baseline-secure & defended-vuln (newly broken by defence).
    """
    if len(baseline_vuln) != len(defended_vuln):
        raise ValueError("paired inputs must have equal length")
    b = sum(1 for x, y in zip(baseline_vuln, defended_vuln) if x and not y)
    c = sum(1 for x, y in zip(baseline_vuln, defended_vuln) if not x and y)
    n = b + c
    detail = f"discordant: fixed={b}, newly_broken={c}"
    if n == 0:
        return TestResult("McNemar", 0.0, 1.0, False, detail + " (no discordant pairs)")

    try:
        from scipy.stats import binomtest

        p = binomtest(min(b, c), n, 0.5).pvalue
        stat = float(min(b, c))
    except ImportError:
        # Chi-square with continuity correction.
        stat = (abs(b - c) - 1) ** 2 / n
        p = math.erfc(math.sqrt(stat / 2))
    return TestResult("McNemar", round(stat, 4), round(p, 6), p < alpha, detail)


def wilcoxon_test(baseline_vals: list[float], defended_vals: list[float],
                  alpha: float = 0.05) -> TestResult:
    """Wilcoxon signed-rank test on paired continuous metrics (e.g. latency)."""
    if len(baseline_vals) != len(defended_vals):
        raise ValueError("paired inputs must have equal length")
    diffs = [d - b for b, d in zip(baseline_vals, defended_vals) if (d - b) != 0]
    n = len(diffs)
    if n == 0:
        return TestResult("Wilcoxon", 0.0, 1.0, False, "all paired differences are zero")

    try:
        from scipy.stats import wilcoxon

        stat, p = wilcoxon(baseline_vals, defended_vals)
        return TestResult("Wilcoxon", round(float(stat), 4), round(float(p), 6),
                          p < alpha, f"n_nonzero={n}")
    except ImportError:
        pass

    # Normal-approximation fallback.
    ranks = _signed_ranks(diffs)
    w_plus = sum(r for r, d in zip(ranks, diffs) if d > 0)
    w_minus = sum(r for r, d in zip(ranks, diffs) if d < 0)
    w = min(w_plus, w_minus)
    mean_w = n * (n + 1) / 4
    std_w = math.sqrt(n * (n + 1) * (2 * n + 1) / 24)
    if std_w == 0:
        return TestResult("Wilcoxon", float(w), 1.0, False, f"n_nonzero={n}")
    z = (w - mean_w) / std_w
    p = math.erfc(abs(z) / math.sqrt(2))
    return TestResult("Wilcoxon", round(float(w), 4), round(p, 6), p < alpha,
                      f"n_nonzero={n} (normal approx)")


def _signed_ranks(diffs: list[float]) -> list[float]:
    order = sorted(range(len(diffs)), key=lambda i: abs(diffs[i]))
    ranks = [0.0] * len(diffs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and abs(diffs[order[j + 1]]) == abs(diffs[order[i]]):
            j += 1
        avg = (i + j) / 2 + 1  # average rank for ties (1-based)
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks
