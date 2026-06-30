"""Layer 3 orchestration: run generated code in the Docker sandbox with auto-generated security
probes, interpret the runtime behaviour, and produce a scored LayerResult.
"""
from __future__ import annotations

import time

from adf.common.config import Config, load_config
from adf.common.types import CweFinding, LayerResult, Severity
from adf.layer3_sandbox.docker_runner import DockerSandbox
from adf.layer3_sandbox.security_tests import (
    PROBE_FAIL,
    generate_behavioural_probes,
    generate_probes,
    render_test_block,
)

# Runtime behaviour signals and the risk they imply.
_SIGNAL_RISK = {
    "execution_timeout": 0.7,
    "memory_exhaustion": 0.8,
    "permission_denied": 0.5,
    "network_attempt_blocked": 0.9,
}


class Layer3Validator:
    """Post-generation sandboxed validation layer."""

    LAYER = "layer3_sandbox"

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or load_config()
        self._sandbox = DockerSandbox(self.config)

    def validate(self, code: str, prior_findings: list[CweFinding] | None = None) -> LayerResult:
        start = time.perf_counter()
        prior_findings = prior_findings or []

        # The sandbox runs in Docker. Where Docker is not available (e.g. a laptop without
        # Docker Desktop), Layer 3 is reported inactive and excluded from the trust score by
        # the scorer, rather than failing the whole pipeline.
        if not self._sandbox.is_available():
            return LayerResult(
                layer=self.LAYER,
                risk=0.0,
                findings=[],
                latency_s=time.perf_counter() - start,
                metadata={"sandbox_available": False, "reason": "Docker not available"},
            )

        # Build the CWE-targeted probes and the privilege-escalation / network-egress probes.
        probes = generate_probes(code, prior_findings) + generate_behavioural_probes()
        test_block = render_test_block(probes)
        outcome = self._sandbox.run(code, test_code=test_block or None)

        findings: list[CweFinding] = []
        risk = 0.0

        # Behavioural signals from the runtime.
        for sig in outcome.signals:
            base = sig.split(":")[0]
            risk = max(risk, _SIGNAL_RISK.get(base, 0.3))

        # A probe that printed the UNSAFE marker = a runtime-confirmed vulnerability.
        combined = outcome.stdout + outcome.stderr
        if PROBE_FAIL in combined:
            for probe in probes:
                if f"{PROBE_FAIL}:{probe.target_cwe}" in combined:
                    findings.append(CweFinding(
                        cwe_id=probe.target_cwe,
                        name=f"Runtime-confirmed {probe.target_cwe}",
                        message=f"Probe '{probe.name}' triggered unsafe behaviour at runtime",
                        severity=Severity.HIGH,
                        source="sandbox",
                        confidence=1.0,
                    ))
            risk = max(risk, 0.85)

        return LayerResult(
            layer=self.LAYER,
            risk=risk,
            findings=findings,
            latency_s=time.perf_counter() - start,
            metadata={
                "sandbox_available": True,
                "exit_code": outcome.exit_code,
                "timed_out": outcome.timed_out,
                "signals": outcome.signals,
                "n_probes": len(probes),
            },
        )
