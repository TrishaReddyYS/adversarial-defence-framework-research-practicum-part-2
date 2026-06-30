"""Shared data types used across all defence layers and the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    APPROVE = "approve"
    FLAG = "flag"
    BLOCK = "block"


@dataclass
class CweFinding:
    """A single detected weakness mapped to a MITRE CWE identifier."""

    cwe_id: str
    name: str
    message: str
    line: int = 0
    column: int = 0
    severity: Severity = Severity.MEDIUM
    source: str = "ast"          # "ast" | "semgrep"
    confidence: float = 1.0       # 0..1

    def key(self) -> tuple[str, int, str]:
        return (self.cwe_id, self.line, self.source)


@dataclass
class LayerResult:
    """Output of one defence layer.

    `risk` is in [0, 1] where 0 = certainly safe and 1 = certainly malicious/vulnerable.
    """

    layer: str
    risk: float
    findings: list[CweFinding] = field(default_factory=list)
    latency_s: float = 0.0
    metadata: dict = field(default_factory=dict)

    @property
    def trust(self) -> float:
        return max(0.0, min(1.0, 1.0 - self.risk))


@dataclass
class PipelineResult:
    """End-to-end result of running the full defence pipeline on one prompt."""

    prompt: str
    sanitised_prompt: str | None = None
    generated_code: str | None = None
    layers: list[LayerResult] = field(default_factory=list)
    trust_score: float = 1.0
    verdict: Verdict = Verdict.APPROVE
    blocked_pre_generation: bool = False
    total_latency_s: float = 0.0

    @property
    def all_findings(self) -> list[CweFinding]:
        out: list[CweFinding] = []
        for layer in self.layers:
            out.extend(layer.findings)
        return out

    @property
    def is_vulnerable(self) -> bool:
        """True if the pipeline let through code with at least one CWE finding."""
        return self.verdict != Verdict.BLOCK and len(self.all_findings) > 0
