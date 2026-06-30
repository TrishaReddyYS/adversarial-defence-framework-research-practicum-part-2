"""Per-layer and end-to-end latency profiling.

Times each defence layer in isolation on representative inputs and reports the per-layer and
combined overhead. Layer 1 is timed on prompts, Layers 2 and 3 on code samples. No LLM is needed,
so the profile is reproducible without API access or a GPU.
"""
from __future__ import annotations

import time
from statistics import mean

from adf.common.datasets import generate_adversarial, load_securityeval
from adf.common.logging import get_logger
from adf.layer1_sanitiser.sanitiser import PromptSanitiser
from adf.layer2_ast_cwe.detector import Layer2Detector
from adf.layer3_sandbox.validator import Layer3Validator

log = get_logger("eval.latency")


def _stats(values: list[float]) -> dict[str, float]:
    vals = sorted(values)
    if not vals:
        return {"mean_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "max_s": 0.0, "n": 0}

    def pct(p: float) -> float:
        return vals[min(len(vals) - 1, int(round(p * (len(vals) - 1))))]

    return {
        "mean_s": round(mean(vals), 4),
        "p50_s": round(pct(0.50), 4),
        "p95_s": round(pct(0.95), 4),
        "max_s": round(max(vals), 4),
        "n": len(vals),
    }


def profile_latency(layer3_sample: int = 25) -> dict:
    """Measure per-layer latency on representative inputs and return a summary dict.

    `layer3_sample` caps how many code samples are run through the Docker sandbox (Layer 3 is the
    slowest layer); Layers 1 and 2 run over the full sets.
    """
    prompts = [s.text for s in generate_adversarial()]
    code_samples = [s.text for s in load_securityeval()]

    l1 = PromptSanitiser()
    l1_times = []
    for p in prompts:
        t = time.perf_counter()
        l1.sanitise(p)
        l1_times.append(time.perf_counter() - t)

    l2 = Layer2Detector()
    l2_times = []
    for c in code_samples:
        t = time.perf_counter()
        l2.detect(c)
        l2_times.append(time.perf_counter() - t)

    l3 = Layer3Validator()
    l3_times = []
    for c in code_samples[:layer3_sample]:
        prior = l2.detect(c).findings
        t = time.perf_counter()
        l3.validate(c, prior_findings=prior)
        l3_times.append(time.perf_counter() - t)

    s1, s2, s3 = _stats(l1_times), _stats(l2_times), _stats(l3_times)
    combined_mean = round(s1["mean_s"] + s2["mean_s"] + s3["mean_s"], 4)
    combined_p95 = round(s1["p95_s"] + s2["p95_s"] + s3["p95_s"], 4)
    return {
        "layer1_mean_s": s1["mean_s"], "layer1_p95_s": s1["p95_s"], "layer1_n": s1["n"],
        "layer2_mean_s": s2["mean_s"], "layer2_p95_s": s2["p95_s"], "layer2_n": s2["n"],
        "layer3_mean_s": s3["mean_s"], "layer3_p95_s": s3["p95_s"], "layer3_n": s3["n"],
        "combined_mean_s": combined_mean,
        "combined_p95_s": combined_p95,
        "overhead_target_s": 1.0,
        "combined_meets_target": combined_p95 <= 1.0,
    }
