"""HumanEval functional-correctness evaluation (pass@k).

Loads the HumanEval problems, generates a solution for each prompt with an LLM, runs the official
unit tests, and reports pass@k. This measures whether the defence framework affects the model's
ability to produce *correct* code (utility), complementing the security metrics.

The full run needs an LLM client; the loader, harness, and pass@k estimator are unit-testable
without one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from adf.common.datasets import DATA_DIR
from adf.common.logging import get_logger
from adf.llm.base import LLMClient
from eval.metrics.code_quality import pass_at_k, passes_tests

log = get_logger("eval.humaneval")


@dataclass
class HumanEvalProblem:
    task_id: str
    prompt: str
    entry_point: str
    test: str


def load_humaneval(path: str | Path | None = None) -> list[HumanEvalProblem]:
    p = Path(path) if path else DATA_DIR / "raw" / "humaneval.jsonl"
    if not p.is_file():
        raise FileNotFoundError(
            f"HumanEval not found at {p}. Download HumanEval.jsonl.gz from "
            "https://github.com/openai/human-eval and unzip into data/raw/humaneval.jsonl."
        )
    problems = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        problems.append(HumanEvalProblem(d["task_id"], d["prompt"], d["entry_point"], d["test"]))
    return problems


def _run_check(solution_code: str, problem: HumanEvalProblem, timeout_s: float = 8.0) -> bool:
    """Append the official test + check(entry_point) call and run it."""
    harness = f"{solution_code}\n\n{problem.test}\n\ncheck({problem.entry_point})\n"
    return passes_tests(solution_code, problem.test + f"\ncheck({problem.entry_point})\n",
                        timeout_s=timeout_s) if "check(" in problem.test else \
        passes_tests(harness, "", timeout_s=timeout_s)


def evaluate_pass_at_k(llm_client: LLMClient, k: int = 1, n_samples: int = 1,
                       limit: int | None = None) -> dict:
    """Generate `n_samples` solutions per problem and compute pass@k.

    For deterministic k=1 evaluation use n_samples=1. The model is prompted with the HumanEval
    function signature/docstring; the canonical test decides correctness.
    """
    problems = load_humaneval()
    if limit:
        problems = problems[:limit]
    results_per_problem: list[list[bool]] = []
    for prob in problems:
        outcomes = []
        for _ in range(n_samples):
            try:
                code = llm_client.generate_code(prob.prompt)
            except Exception as exc:  # noqa: BLE001
                log.warning("generation failed for %s: %s", prob.task_id, exc)
                outcomes.append(False)
                continue
            # Ensure the entry-point function is present; prepend the prompt signature if needed.
            full = code if prob.entry_point in code else prob.prompt + "\n" + code
            outcomes.append(_run_check(full, prob))
        results_per_problem.append(outcomes)
    return {
        "n_problems": len(problems),
        "n_samples_per_problem": n_samples,
        f"pass@{k}": pass_at_k(results_per_problem, k=k),
    }


def evaluate_utility_impact(llm_client: LLMClient, limit: int | None = None) -> dict:
    """Compare pass@1 of the raw model against pass@1 of the defended pipeline's delivered code.

    Answers whether the defence degrades utility: the framework runs each HumanEval prompt, and a
    blocked request delivers no solution (counts as a failure). The gap between the two pass@1
    figures is the utility cost of the defence on benign, security-neutral tasks.
    """
    from adf.common.types import Verdict
    from adf.integration.pipeline import DefencePipeline

    pipeline = DefencePipeline(llm_client=llm_client)
    problems = load_humaneval()
    if limit:
        problems = problems[:limit]

    raw, defended, blocked = [], [], 0
    for prob in problems:
        try:
            code = llm_client.generate_code(prob.prompt)
        except Exception as exc:  # noqa: BLE001
            log.warning("generation failed for %s: %s", prob.task_id, exc)
            raw.append(False)
            defended.append(False)
            continue
        full = code if prob.entry_point in code else prob.prompt + "\n" + code
        raw_pass = _run_check(full, prob)
        raw.append(raw_pass)
        # Defended: the framework may block the delivered code; a block delivers nothing.
        result = pipeline.run(code=full)
        if result.verdict == Verdict.BLOCK:
            blocked += 1
            defended.append(False)
        else:
            defended.append(raw_pass)

    n = len(problems)
    raw_p1 = pass_at_k([[r] for r in raw], k=1)
    def_p1 = pass_at_k([[d] for d in defended], k=1)
    return {
        "n_problems": n,
        "undefended_pass@1": round(raw_p1, 4),
        "defended_pass@1": round(def_p1, 4),
        "utility_drop": round(raw_p1 - def_p1, 4),
        "blocked_benign_solutions": blocked,
        "blocked_rate": round(blocked / n, 4) if n else 0.0,
    }
