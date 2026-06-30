"""Command-line interface for the Adversarial Defence Framework."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _cmd_scan(args: argparse.Namespace) -> int:
    from adf.layer2_ast_cwe.detector import Layer2Detector

    path = Path(args.path)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    result = Layer2Detector().detect(path.read_text(encoding="utf-8"))
    if not result.findings:
        print(f"No CWE findings in {path} (risk={result.risk:.2f}).")
        return 0
    print(f"{len(result.findings)} finding(s) in {path} (risk={result.risk:.2f}):")
    for f in result.findings:
        print(f"  L{f.line:<4} {f.cwe_id:<8} {f.severity.value:<8} {f.name} [{f.source}]")
    return 0  # demo report (the finding is printed above), not a CI gate


def _cmd_baseline(args: argparse.Namespace) -> int:
    """Baseline measurement: how many code samples are vulnerable with NO defence.

    Every .py file in the directory is scored by the independent Bandit oracle (a different tool
    from the framework's Tree-sitter/Semgrep, so the score is non-circular). The vulnerable rate
    over the sample set is the unprotected baseline the defended pipeline is compared against.
    """
    from eval.metrics.oracle import oracle_available, scan_code

    if not oracle_available():
        print("error: Bandit oracle not available. Run: pip install bandit", file=sys.stderr)
        return 2
    folder = Path(args.path)
    files = sorted(folder.glob("*.py")) if folder.is_dir() else [folder]
    if not files:
        print(f"error: no .py files found in {folder}", file=sys.stderr)
        return 2

    vulnerable = 0
    print(f"{'file':<32} {'vulnerable':<11} CWEs")
    print("-" * 64)
    for f in files:
        res = scan_code(f.read_text(encoding="utf-8"))
        vulnerable += int(res.vulnerable)
        print(f"{f.name:<32} {'YES' if res.vulnerable else 'no':<11} {', '.join(res.cwes) or '-'}")
    n = len(files)
    rate = 100.0 * vulnerable / n if n else 0.0
    print("-" * 64)
    print(f"Baseline (no defence): {vulnerable}/{n} samples vulnerable = {rate:.2f}% "
          f"(independent Bandit oracle)")
    return 0


def _cmd_sanitise(args: argparse.Namespace) -> int:
    from adf.layer1_sanitiser.sanitiser import PromptSanitiser

    res = PromptSanitiser().sanitise(args.prompt)
    lr = res.layer_result
    print(f"action: {res.action}   risk: {lr.risk:.2f}   "
          f"intent-deviation: {lr.metadata['intent_deviation']}")
    if res.signals:
        print("signals:")
        for s in res.signals:
            print(f"  {s.kind.value:<18} score={s.score:<4} {s.note}")
    if res.action == "sanitise":
        print(f"sanitised prompt: {res.sanitised_prompt}")
    elif res.action == "block":
        print("prompt blocked (not forwarded to the model)")
    return 0  # demo report (the action is printed above), not a CI gate


def _cmd_sandbox(args: argparse.Namespace) -> int:
    from adf.layer2_ast_cwe.detector import Layer2Detector
    from adf.layer3_sandbox.validator import Layer3Validator

    path = Path(args.path)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    code = path.read_text(encoding="utf-8")
    findings = Layer2Detector().detect(code).findings
    result = Layer3Validator().validate(code, prior_findings=findings)
    if not result.metadata.get("sandbox_available"):
        print(f"sandbox unavailable ({result.metadata.get('reason', 'n/a')}); "
              "install/run Docker to enable Layer 3.")
        return 0
    print(f"sandbox risk={result.risk:.2f}  exit={result.metadata['exit_code']}  "
          f"signals={result.metadata['signals']}")
    for f in result.findings:
        print(f"  runtime-confirmed {f.cwe_id}: {f.message}")
    return 1 if result.findings else 0


def _cmd_defend(args: argparse.Namespace) -> int:
    from adf.integration.pipeline import DefencePipeline

    pipe = DefencePipeline()
    if args.file:
        code = Path(args.file).read_text(encoding="utf-8")
        res = pipe.run(code=code)
    else:
        res = pipe.run(prompt=args.prompt)

    print(f"verdict: {res.verdict.value.upper()}   trust: {res.trust_score:.2f}")
    if res.blocked_pre_generation:
        print("  (prompt blocked at Layer 1 — never sent to the model)")
    for layer in res.layers:
        note = "" if layer.metadata.get("sandbox_available", True) else "   (inactive: no Docker)"
        print(f"  {layer.layer:<18} risk={layer.risk:.2f}{note}")
    for f in res.all_findings:
        print(f"    {f.cwe_id} {f.name} [{f.source}]")
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    from adf.common.datasets import (
        generate_adversarial,
        load_llmseceval,
        load_securityeval,
    )
    from eval.runner import evaluate

    llm = None
    if args.model:
        from adf.llm import get_client
        llm = get_client(args.model)

    if args.dataset == "adversarial":
        samples = generate_adversarial()
    elif args.dataset == "securityeval":
        samples = load_securityeval()
    elif args.dataset == "securityeval-gen":
        # SecurityEval used as code-completion prompts (generate -> defend -> judge), matching how
        # secure-code-generation defences are benchmarked on this dataset.
        samples = load_securityeval(as_prompts=True)
    elif args.dataset == "llmseceval":
        samples = load_llmseceval()
    else:
        samples = generate_adversarial() + load_securityeval() + load_llmseceval()

    if args.cwe_scoped:
        from eval.runner import scope_to_supported
        samples = scope_to_supported(samples)

    if args.limit:
        samples = samples[: args.limit]

    # Name reports per model so different models' results do not overwrite each other.
    _model_tag = {"openai": "gpt4o", "codellama": "codellama"}
    report_name = args.dataset
    if args.model:
        report_name = f"{args.dataset}_{_model_tag.get(args.model, args.model)}"

    res = evaluate(samples, llm_client=llm, name=report_name,
                   extra_baselines=args.extra_baselines)
    b = res.condition_metrics["unprotected"]
    d = res.condition_metrics["defended"]
    print(f"samples: {d['n_samples']}")
    print(f"unprotected ASR:  {b['attack_success_rate']:.2%}")
    for cond in ("input_filter_only", "semgrep_only"):
        if cond in res.condition_metrics:
            print(f"{cond} ASR:  {res.condition_metrics[cond]['attack_success_rate']:.2%}")
    print(f"defended ASR:  {d['attack_success_rate']:.2%}  "
          f"(target <5%: {'MET' if d['asr_meets_target'] else 'not met'})")
    print(f"detection rate: {d['overall_detection_rate']:.2%}  | "
          f"false-positive rate: {d['false_positive_rate']:.2%}  | "
          f"time-to-detection: {d['time_to_detection_s']}s")
    print(f"framework overhead p95: {d['framework_p95_latency_s']}s  "
          f"(target <1s: {'MET' if d['latency_meets_target'] else 'not met'})  | "
          f"end-to-end p95: {d['p95_latency_s']}s")
    if res.code_quality:
        print(f"code quality: compile={res.code_quality['compilation_success_rate']:.0%}, "
              f"CC={res.code_quality['mean_cyclomatic_complexity']}, "
              f"MI={res.code_quality['mean_maintainability_index']}")
    mc = res.significance["mcnemar_security"]
    print(f"McNemar p={mc['p_value']} significant={mc['significant']} ({mc['detail']})")
    if res.excel_path:
        print(f"\nresults written:\n  {res.excel_path}\n  {res.word_path}")
    return 0


def _cmd_humaneval(args: argparse.Namespace) -> int:
    from adf.llm import get_client
    from adf.common.results import write_all
    from eval.humaneval import evaluate_utility_impact

    llm = get_client(args.model)
    res = evaluate_utility_impact(llm, limit=args.limit)
    print(f"problems: {res['n_problems']}")
    print(f"undefended pass@1: {res['undefended_pass@1']:.2%}")
    print(f"defended pass@1:   {res['defended_pass@1']:.2%}")
    print(f"utility drop: {res['utility_drop']:.2%}  | "
          f"benign solutions blocked: {res['blocked_benign_solutions']} "
          f"({res['blocked_rate']:.2%})")
    _model_tag = {"openai": "gpt4o", "codellama": "codellama"}
    xlsx, docx = write_all([res], name=f"humaneval_{_model_tag.get(args.model, args.model)}",
                           title="Adversarial Defence Framework — Code Quality (HumanEval pass@1)",
                           summary=res)
    print(f"\nresults written:\n  {xlsx}\n  {docx}")
    return 0


def _cmd_latency_profile(args: argparse.Namespace) -> int:
    from adf.common.results import write_all
    from eval.latency import profile_latency

    res = profile_latency(layer3_sample=args.layer3_sample)
    print(f"Layer 1 (sanitise): mean {res['layer1_mean_s']}s  p95 {res['layer1_p95_s']}s")
    print(f"Layer 2 (AST+CWE):  mean {res['layer2_mean_s']}s  p95 {res['layer2_p95_s']}s")
    print(f"Layer 3 (sandbox):  mean {res['layer3_mean_s']}s  p95 {res['layer3_p95_s']}s")
    print(f"combined pipeline overhead: mean {res['combined_mean_s']}s  p95 {res['combined_p95_s']}s "
          f"(target <1s: {'MET' if res['combined_meets_target'] else 'not met'})")
    xlsx, docx = write_all([res], name="latency_profile",
                           title="Adversarial Defence Framework — Per-Layer Latency Profile",
                           summary=res)
    print(f"\nresults written:\n  {xlsx}\n  {docx}")
    return 0


def _cmd_make_adversarial(args: argparse.Namespace) -> int:
    from adf.common.datasets import save_adversarial

    out = save_adversarial(args.out)
    print(f"Wrote synthetic adversarial dataset -> {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adf", description="Adversarial Defence Framework")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Layer 2: detect CWEs in a Python source file")
    p_scan.add_argument("path", help="path to a .py file")
    p_scan.set_defaults(func=_cmd_scan)

    p_base = sub.add_parser("baseline", help="measure the no-defence vulnerable rate over a folder")
    p_base.add_argument("path", help="folder of .py samples (or a single .py file)")
    p_base.set_defaults(func=_cmd_baseline)

    p_san = sub.add_parser("sanitise", help="Layer 1: check a prompt for injection")
    p_san.add_argument("prompt", help="the prompt text to inspect")
    p_san.set_defaults(func=_cmd_sanitise)

    p_box = sub.add_parser("sandbox", help="Layer 3: run a file in the Docker sandbox")
    p_box.add_argument("path", help="path to a .py file")
    p_box.set_defaults(func=_cmd_sandbox)

    p_def = sub.add_parser("defend", help="run the full pipeline on a prompt or a file")
    g = p_def.add_mutually_exclusive_group(required=True)
    g.add_argument("prompt", nargs="?", help="prompt text to defend")
    g.add_argument("--file", help="defend an existing .py file instead of a prompt")
    p_def.set_defaults(func=_cmd_defend)

    p_eval = sub.add_parser("evaluate", help="run baseline vs defended evaluation + write reports")
    p_eval.add_argument("--dataset",
                        choices=["adversarial", "securityeval", "securityeval-gen",
                                 "llmseceval", "all"],
                        default="adversarial", help="which benchmark to evaluate")
    p_eval.add_argument("--model", choices=["openai", "codellama"], default=None,
                        help="LLM for prompt samples (omit for code-only datasets)")
    p_eval.add_argument("--limit", type=int, default=None,
                        help="evaluate only the first N samples (for quick/subset runs)")
    p_eval.add_argument("--cwe-scoped", action="store_true",
                        help="restrict to samples whose CWE is in the framework's target scope")
    p_eval.add_argument("--extra-baselines", action="store_true",
                        help="also run the input-filter-only and standalone-Semgrep baselines")
    p_eval.set_defaults(func=_cmd_evaluate)

    p_he = sub.add_parser("humaneval",
                          help="code-quality: HumanEval pass@1, undefended vs defended")
    p_he.add_argument("--model", choices=["openai", "codellama"], default="openai",
                      help="LLM to evaluate")
    p_he.add_argument("--limit", type=int, default=None,
                      help="evaluate only the first N problems")
    p_he.set_defaults(func=_cmd_humaneval)

    p_lat = sub.add_parser("latency-profile",
                           help="measure per-layer and combined pipeline latency (no LLM)")
    p_lat.add_argument("--layer3-sample", type=int, default=25,
                       help="number of code samples to run through the Docker sandbox")
    p_lat.set_defaults(func=_cmd_latency_profile)

    p_adv = sub.add_parser("make-adversarial", help="generate the synthetic adversarial dataset")
    p_adv.add_argument("--out", default=None, help="output JSONL path")
    p_adv.set_defaults(func=_cmd_make_adversarial)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
