"""Semgrep-based scanning. Augments the Tree-sitter AST analyser.

Semgrep is an external CLI. The scanner can run several rule configurations in one pass (the
bundled injection rules plus a curated registry pack for broader CWE coverage) and maps each
finding to its MITRE CWE.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from adf.common.types import CweFinding, Severity


_LOCAL_RULES = Path(__file__).parent / "semgrep_rules"


def _find_semgrep() -> str | None:
    """Locate the semgrep executable on PATH or in the active interpreter's bin dir.

    Resolving relative to sys.executable makes it work when the venv is not 'activated'
    (e.g. invoking .venv/bin/python directly), which is how the framework is usually run.
    """
    found = shutil.which("semgrep")
    if found:
        return found
    candidate = Path(sys.executable).parent / "semgrep"
    return str(candidate) if candidate.is_file() else None

_CWE_RE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)
_SEV_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepScanner:
    def __init__(self, config: str | None = None, extra_configs: list[str] | None = None,
                 timeout_s: int = 60) -> None:
        # The base config is the bundled rule set unless one is provided; extra_configs adds
        # further rule sources (e.g. a registry pack) that run in the same scan.
        base = config or str(_LOCAL_RULES)
        self.configs = [base, *(extra_configs or [])]
        self.timeout_s = timeout_s
        self._exe = _find_semgrep()

    def is_available(self) -> bool:
        return self._exe is not None

    def scan(self, code: str, language: str = "python") -> list[CweFinding]:
        """Run Semgrep on the code and return the CWE findings; raise on any execution failure."""
        if not self.is_available():
            raise RuntimeError(
                "Semgrep is required but not found. Install it: pip install semgrep"
            )
        suffix = {"python": ".py", "javascript": ".js", "js": ".js"}.get(language, ".txt")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / f"snippet{suffix}"
            src.write_text(code, encoding="utf-8")
            config_flags: list[str] = []
            for cfg in self.configs:
                config_flags += ["--config", cfg]
            try:
                proc = subprocess.run(
                    # Run Semgrep on the snippet with the configured rules and JSON output.
                    [self._exe, "scan", "--experimental", *config_flags,
                     "--json", "--quiet", "--disable-version-check", "--metrics", "off",
                     "--no-git-ignore", str(src)],
                    capture_output=True, text=True, timeout=self.timeout_s,
                    env={**__import__("os").environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"},
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                raise RuntimeError(f"Semgrep execution failed: {exc}") from exc
            if proc.returncode not in (0, 1):  # 0=clean, 1=findings; anything else is an error
                raise RuntimeError(
                    f"Semgrep exited {proc.returncode}: {proc.stderr.strip()[:300]}"
                )
            if not proc.stdout:
                raise RuntimeError("Semgrep produced no output")
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Semgrep returned invalid JSON: {exc}") from exc
        return [f for r in data.get("results", []) if (f := self._to_finding(r)) is not None]

    def _to_finding(self, result: dict) -> CweFinding | None:
        extra = result.get("extra", {})
        meta = extra.get("metadata", {})
        cwe_field = meta.get("cwe")
        cwe_text = " ".join(cwe_field) if isinstance(cwe_field, list) else str(cwe_field or "")
        m = _CWE_RE.search(cwe_text) or _CWE_RE.search(result.get("check_id", ""))
        if not m:
            return None
        sev = _SEV_MAP.get(str(extra.get("severity", "WARNING")).upper(), Severity.MEDIUM)
        return CweFinding(
            cwe_id=f"CWE-{int(m.group(1))}",
            name=str(meta.get("shortlink") or result.get("check_id", "semgrep finding")),
            message=str(extra.get("message", "")).strip()[:300],
            line=int(result.get("start", {}).get("line", 0)),
            severity=sev,
            source="semgrep",
            confidence=0.9,
        )
