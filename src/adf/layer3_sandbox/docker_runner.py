"""Docker sandbox runner for Layer 3.

Executes untrusted generated code inside an isolated, resource-limited, network-disabled
container via the Docker SDK and captures the outcome (exit code, output, and behaviour signals).
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from adf.common.config import Config, load_config
from adf.common.logging import get_logger

log = get_logger("layer3.docker")


@dataclass
class SandboxOutcome:
    """Result of executing code (and optional tests) in the sandbox."""

    available: bool                 # was Docker usable?
    exit_code: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    error: str = ""                 # harness-level error (not the code's own stderr)
    network_attempted: bool = False
    duration_s: float = 0.0
    signals: list[str] = field(default_factory=list)


class DockerSandbox:
    """Runs Python code in a locked-down container."""

    def __init__(self, config: Config | None = None) -> None:
        cfg = config or load_config()
        self.image = str(cfg.get("layer3_sandbox.docker_image", "python:3.11-slim"))
        self.cpu_limit = float(cfg.get("layer3_sandbox.cpu_limit", 1.0))
        self.memory_limit = str(cfg.get("layer3_sandbox.memory_limit", "256m"))
        self.network_disabled = bool(cfg.get("layer3_sandbox.network_disabled", True))
        self.timeout_s = int(cfg.get("layer3_sandbox.exec_timeout_s", 10))
        self._client = None
        self._checked = False
        self._available = False

    def is_available(self) -> bool:
        if self._checked:
            return self._available
        self._checked = True
        try:
            import docker

            self._client = docker.from_env()
            self._client.ping()
            self._available = True
        except Exception as exc:  # noqa: BLE001 - any failure => sandbox unavailable
            log.info("Docker sandbox unavailable: %s", exc)
            self._available = False
        return self._available

    def run(self, code: str, test_code: str | None = None) -> SandboxOutcome:
        """Execute `code` (optionally followed by `test_code`) in an isolated container."""
        import time

        if not self.is_available():
            return SandboxOutcome(available=False, error="docker unavailable")

        import docker

        script = code if not test_code else f"{code}\n\n# --- security tests ---\n{test_code}\n"
        start = time.perf_counter()
        with tempfile.TemporaryDirectory() as tmp:
            snippet = Path(tmp) / "snippet.py"
            snippet.write_text(script, encoding="utf-8")
            snippet.chmod(0o644)  # world-readable so the non-root sandbox user can read it
            try:
                container = self._client.containers.run(
                    self.image,
                    command=["python", "/sandbox/snippet.py"],
                    volumes={tmp: {"bind": "/sandbox", "mode": "ro"}},
                    network_disabled=self.network_disabled,
                    mem_limit=self.memory_limit,
                    nano_cpus=int(self.cpu_limit * 1_000_000_000),
                    pids_limit=64,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges"],
                    user="65534:65534",  # run as 'nobody' so privilege ops genuinely fail
                    detach=True,
                    stdout=True,
                    stderr=True,
                )
            except docker.errors.APIError as exc:
                return SandboxOutcome(available=True, error=f"container start failed: {exc}")

            timed_out = False
            try:
                result = container.wait(timeout=self.timeout_s)
                exit_code = int(result.get("StatusCode", -1))
            except Exception:  # noqa: BLE001 - timeout or daemon error
                timed_out = True
                exit_code = None
                try:
                    container.kill()
                except Exception:  # noqa: BLE001
                    pass

            stdout = self._safe_logs(container, stdout=True)
            stderr = self._safe_logs(container, stdout=False)
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                pass

        return SandboxOutcome(
            available=True,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            duration_s=time.perf_counter() - start,
            signals=self._behaviour_signals(stdout, stderr, exit_code, timed_out),
        )

    @staticmethod
    def _safe_logs(container, stdout: bool) -> str:
        try:
            return container.logs(stdout=stdout, stderr=not stdout).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _behaviour_signals(stdout: str, stderr: str, exit_code: int | None,
                           timed_out: bool) -> list[str]:
        signals: list[str] = []
        if timed_out:
            signals.append("execution_timeout")
        if exit_code not in (0, None):
            signals.append(f"nonzero_exit:{exit_code}")
        blob = (stdout + stderr).lower()
        if any(tok in blob for tok in ("connection refused", "network is unreachable",
                                       "name or service not known", "errno -3")):
            signals.append("network_attempt_blocked")
        if "permission denied" in blob:
            signals.append("permission_denied")
        if "memoryerror" in blob:
            signals.append("memory_exhaustion")
        return signals
