"""Tests for the Layer 2 detector (scoring, dedupe, LayerResult)."""
from __future__ import annotations

from adf.layer2_ast_cwe.detector import Layer2Detector

detector = Layer2Detector()


def test_vulnerable_code_produces_high_risk():
    result = detector.detect("result = eval(user_input)")
    assert result.risk >= 0.85
    assert any(f.cwe_id == "CWE-94" for f in result.findings)
    assert result.layer == "layer2_ast_cwe"


def test_clean_code_zero_risk():
    result = detector.detect("def add(a, b):\n    return a + b\n")
    assert result.risk == 0.0
    assert result.findings == []


def test_layer_result_trust_is_inverse_of_risk():
    result = detector.detect("result = eval(x)")
    assert abs(result.trust - (1.0 - result.risk)) < 1e-9


def test_latency_recorded():
    result = detector.detect("x = 1")
    assert result.latency_s >= 0.0
    assert "cwes" in result.metadata


def test_javascript_detection():
    """External validity: Layer 2 detects CWEs in JavaScript as well as Python."""
    js = (
        "const cp = require('child_process');\n"
        "function run(userInput) { cp.exec('ls ' + userInput); }\n"
        "const PASSWORD = 'admin123';\n"
    )
    result = detector.detect(js, language="javascript")
    cwes = {f.cwe_id for f in result.findings}
    assert "CWE-78" in cwes      # command injection
    assert result.risk >= 0.85
