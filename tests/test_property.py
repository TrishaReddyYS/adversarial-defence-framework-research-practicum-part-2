"""Property-based security tests using Hypothesis.

These assert robustness invariants over large, randomised input spaces rather than fixed examples:
the defence layers must never crash on arbitrary input, must keep risk scores in range, and must
be deterministic — properties a security component has to hold against adversarial/malformed input.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from adf.layer1_sanitiser.patterns import detect_signals
from adf.layer1_sanitiser.sanitiser import PromptSanitiser, intent_deviation_score
from adf.layer2_ast_cwe.ast_analyzer import ASTAnalyzer

_sanitiser = PromptSanitiser()
_ast = ASTAnalyzer()

# Arbitrary text, including control chars / unicode, to stress the parsers.
_text = st.text(max_size=2000)


@given(_text)
@settings(max_examples=150, deadline=None)
def test_layer1_never_crashes_and_risk_in_range(prompt):
    res = _sanitiser.sanitise(prompt)
    assert 0.0 <= res.layer_result.risk <= 1.0
    assert res.action in {"approve", "sanitise", "block"}


@given(_text)
@settings(max_examples=150, deadline=None)
def test_intent_deviation_bounded(prompt):
    assert 0.0 <= intent_deviation_score(prompt) <= 1.0


@given(_text)
@settings(max_examples=100, deadline=None)
def test_signal_scores_bounded(prompt):
    for s in detect_signals(prompt):
        assert 0.0 <= s.score <= 1.0


@given(_text)
@settings(max_examples=100, deadline=None)
def test_ast_analyzer_robust_to_arbitrary_input(code):
    # AST analysis must not raise on syntactically invalid / arbitrary code.
    findings = _ast.analyze(code)
    assert isinstance(findings, list)


@given(_text)
@settings(max_examples=80, deadline=None)
def test_sanitiser_is_deterministic(prompt):
    a = _sanitiser.sanitise(prompt)
    b = _sanitiser.sanitise(prompt)
    assert a.action == b.action
    assert abs(a.layer_result.risk - b.layer_result.risk) < 1e-9


_SAFE_WORDS = ["write", "a", "function", "that", "reads", "computes", "returns", "the", "sum",
               "list", "numbers", "string", "file", "user", "value", "sorted", "average",
               "please", "create", "method", "parse", "date", "convert", "format"]


@given(st.lists(st.sampled_from(_SAFE_WORDS), min_size=3, max_size=20))
@settings(max_examples=80, deadline=None)
def test_realistic_benign_prompt_not_blocked(words):
    # A prompt built from ordinary, non-adversarial words must never be BLOCKED.
    prompt = " ".join(words)
    assert _sanitiser.sanitise(prompt).action != "block"
