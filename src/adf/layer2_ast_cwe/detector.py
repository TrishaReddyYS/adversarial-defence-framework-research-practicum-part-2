"""Layer 2 orchestration: combine AST + Semgrep findings into a scored LayerResult."""
from __future__ import annotations

import time

from adf.common.config import Config, load_config
from adf.common.types import CweFinding, LayerResult, Severity
from adf.layer2_ast_cwe.ast_analyzer import ASTAnalyzer
from adf.layer2_ast_cwe.semgrep_scanner import SemgrepScanner

_SEVERITY_RISK = {
    Severity.LOW: 0.30,
    Severity.MEDIUM: 0.60,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 1.0,
}


class Layer2Detector:
    """Runtime semantic analysis layer: Tree-sitter AST + Semgrep CWE detection (both required)."""

    LAYER = "layer2_ast_cwe"

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or load_config()
        self._ast = ASTAnalyzer()
        # The bundled injection rules run alongside a curated Semgrep registry pack so Layer 2
        # covers the wider MITRE CWE Top 25, not just the injection-focused subset.
        extra = self.config.get("layer2_ast_cwe.semgrep_extra_configs", ["p/security-audit"])
        self._semgrep = SemgrepScanner(
            extra_configs=list(extra),
            timeout_s=int(self.config.get("layer2_ast_cwe.semgrep_timeout_s", 60)),
        )
        # Semgrep is required for Layer 2; raise a clear error if it is not installed.
        if not self._semgrep.is_available():
            raise RuntimeError(
                "Layer 2 requires Semgrep but it is not installed. Run: pip install semgrep"
            )

    def detect(self, code: str, language: str = "python") -> LayerResult:
        start = time.perf_counter()
        # Both analysers always run; Semgrep raises on failure rather than returning nothing.
        findings: list[CweFinding] = list(self._ast.analyze(code))
        findings.extend(self._semgrep.scan(code, language=language))
        findings = self._dedupe(findings)
        risk = self._risk(findings)
        return LayerResult(
            layer=self.LAYER,
            risk=risk,
            findings=findings,
            latency_s=time.perf_counter() - start,
            metadata={
                "semgrep_used": True,
                "n_findings": len(findings),
                "cwes": sorted({f.cwe_id for f in findings}),
            },
        )

    @staticmethod
    def _dedupe(findings: list[CweFinding]) -> list[CweFinding]:
        """Merge AST + Semgrep duplicates on (cwe, line), preferring higher confidence."""
        best: dict[tuple[str, int], CweFinding] = {}
        for f in findings:
            k = (f.cwe_id, f.line)
            if k not in best or f.confidence > best[k].confidence:
                best[k] = f
        return sorted(best.values(), key=lambda f: (f.line, f.cwe_id))

    @staticmethod
    def _risk(findings: list[CweFinding]) -> float:
        if not findings:
            return 0.0
        return max(_SEVERITY_RISK.get(f.severity, 0.6) for f in findings)
