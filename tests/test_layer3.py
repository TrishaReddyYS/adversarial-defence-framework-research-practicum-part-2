"""Tests for Layer 3 (sandbox validator + security-probe generation).

These run without Docker by exercising the pure probe-generation logic. The real container
execution is covered by an integration test that auto-skips when Docker is not installed.
"""
from __future__ import annotations

from adf.common.types import CweFinding, Severity
from adf.layer3_sandbox.docker_runner import DockerSandbox
from adf.layer3_sandbox.security_tests import (
    PROBE_PASS,
    generate_probes,
    render_test_block,
)
from adf.layer3_sandbox.validator import Layer3Validator


def test_probes_target_found_cwes():
    code = "def get_user(name):\n    return db.execute('SELECT * FROM u WHERE n=' + name)\n"
    findings = [CweFinding("CWE-89", "SQL Injection", "", 2, severity=Severity.HIGH)]
    probes = generate_probes(code, findings)
    assert any(p.target_cwe == "CWE-89" for p in probes)
    assert all(PROBE_PASS in p.code or "ADF_PROBE" in p.code for p in probes)


def test_probes_default_to_boundary_when_no_findings():
    code = "def parse(n):\n    return int(n)\n"
    probes = generate_probes(code, [])
    # With no specific findings, a boundary (CWE-20) probe is generated.
    assert any(p.target_cwe == "CWE-20" for p in probes)


def test_no_probes_when_no_function():
    assert generate_probes("x = 1 + 2\n", []) == []


def test_render_test_block_combines_probes():
    code = "def f(x):\n    return eval(x)\n"
    findings = [CweFinding("CWE-94", "Code Injection", "", 2, severity=Severity.CRITICAL)]
    block = render_test_block(generate_probes(code, findings))
    assert "f(" in block


def test_validator_degrades_without_docker():
    """Layer 3 runs the real sandbox when Docker is available, and degrades gracefully
    (reported inactive and excluded from the trust score) when it is not -- it must never
    crash the pipeline."""
    sandbox = DockerSandbox()
    result = Layer3Validator().validate("def f(x):\n    return x\n")
    assert result.layer == "layer3_sandbox"
    if sandbox.is_available():
        assert result.metadata.get("sandbox_available") is True
    else:
        # No Docker daemon -> Layer 3 reports inactive (risk 0); the pipeline continues.
        assert result.metadata.get("sandbox_available") is False
        assert result.risk == 0.0


def test_sandbox_availability_is_boolean():
    assert isinstance(DockerSandbox().is_available(), bool)


def test_layer2_detects_javascript_vulnerabilities():
    """External validity: Layer 2 (Semgrep) detects CWEs in JavaScript, not just Python."""
    from adf.layer2_ast_cwe.detector import Layer2Detector
    js = ("function run(cmd){ require('child_process').exec('ping ' + cmd); }\n"
          "el.innerHTML = userInput;\n"
          "const apikey = 'sk-secret-123';\n"
          "eval(userData);\n")
    findings = Layer2Detector().detect(js, language="javascript").findings
    cwes = {f.cwe_id for f in findings}
    assert "CWE-78" in cwes and "CWE-79" in cwes and "CWE-94" in cwes
