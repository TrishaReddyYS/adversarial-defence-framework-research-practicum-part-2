"""Code-quality metrics.

Quantifies the framework's effect on the *utility* of generated code. Implements:
  * compilation-success rate  (does the code parse/compile?)
  * cyclomatic complexity      (radon)
  * maintainability index      (radon)
  * pass@k                     (functional correctness on HumanEval-style problems)

These operate on generated-code strings, independent of which experimental condition produced them.
"""
from __future__ import annotations

from dataclasses import dataclass
from statistics import mean


@dataclass
class CodeQuality:
    compiles: bool
    cyclomatic_complexity: float   # mean per-function CC (0 if no functions)
    maintainability_index: float   # 0-100 (higher is better)


def compiles_ok(code: str) -> bool:
    """True if the code is syntactically valid Python (a proxy for compilation success)."""
    try:
        compile(code, "<generated>", "exec")
        return True
    except (SyntaxError, ValueError):
        return False


def _mean_cyclomatic(code: str) -> float:
    try:
        from radon.complexity import cc_visit

        blocks = cc_visit(code)
        return round(mean([b.complexity for b in blocks]), 2) if blocks else 0.0
    except Exception:  # noqa: BLE001 - unparsable code has no measurable complexity
        return 0.0


def _maintainability(code: str) -> float:
    try:
        from radon.metrics import mi_visit

        return round(float(mi_visit(code, multi=True)), 2)
    except Exception:  # noqa: BLE001
        return 0.0


def assess(code: str) -> CodeQuality:
    return CodeQuality(
        compiles=compiles_ok(code),
        cyclomatic_complexity=_mean_cyclomatic(code),
        maintainability_index=_maintainability(code),
    )


def aggregate_quality(samples: list[CodeQuality]) -> dict:
    if not samples:
        return {"compilation_success_rate": 0.0, "mean_cyclomatic_complexity": 0.0,
                "mean_maintainability_index": 0.0, "n": 0}
    return {
        "compilation_success_rate": round(sum(s.compiles for s in samples) / len(samples), 4),
        "mean_cyclomatic_complexity": round(mean(s.cyclomatic_complexity for s in samples), 2),
        "mean_maintainability_index": round(mean(s.maintainability_index for s in samples), 2),
        "n": len(samples),
    }


# --- pass@k (functional correctness) ----------------------------------------------------------
def passes_tests(code: str, test_code: str, entry_point: str | None = None,
                 timeout_s: float = 5.0) -> bool:
    """Run `code` + `test_code` in a subprocess and report whether the tests pass.

    Used for HumanEval-style functional correctness. Execution is isolated in a separate process
    with a timeout; for untrusted code prefer the Layer 3 Docker sandbox.
    """
    import subprocess
    import sys
    import tempfile
    from pathlib import Path

    if not compiles_ok(code):
        return False
    harness = f"{code}\n\n{test_code}\n"
    if entry_point:
        harness += f"\ncheck({entry_point})\n" if "check(" in test_code else ""
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "prob.py"
        f.write_text(harness, encoding="utf-8")
        try:
            proc = subprocess.run([sys.executable, str(f)], capture_output=True,
                                  timeout=timeout_s)
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False


def pass_at_k(results_per_problem: list[list[bool]], k: int = 1) -> float:
    """Unbiased pass@k estimator (Chen et al., 2021).

    `results_per_problem[i]` is the list of pass/fail booleans for the k samples of problem i.
    """
    import math

    def _estimator(n: int, c: int, k: int) -> float:
        if n - c < k:
            return 1.0
        return 1.0 - math.prod((n - c - i) / (n - i) for i in range(k))

    if not results_per_problem:
        return 0.0
    vals = []
    for results in results_per_problem:
        n = len(results)
        c = sum(results)
        vals.append(_estimator(n, c, min(k, n)))
    return round(mean(vals), 4)
