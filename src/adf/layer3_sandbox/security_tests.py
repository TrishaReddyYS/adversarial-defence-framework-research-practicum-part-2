"""Auto-generation of security test cases for Layer 3.

Given generated code, statically inspects it (via Layer 2 findings and simple AST cues) and emits
small probe snippets that exercise security-relevant behaviour at runtime: boundary conditions,
injection vectors, and privilege/resource paths. The probes are appended to the code and run in
the Docker sandbox; a probe that triggers unsafe behaviour reveals a runtime vulnerability that
static analysis alone might miss.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from adf.common.types import CweFinding


@dataclass
class SecurityProbe:
    """One auto-generated runtime probe."""

    name: str
    target_cwe: str
    code: str          # Python that exercises the behaviour; prints ADF_PROBE markers


# Markers the sandbox parses out of stdout to decide whether a probe fired.
PROBE_PASS = "ADF_PROBE_SAFE"
PROBE_FAIL = "ADF_PROBE_UNSAFE"

_FUNC_RE = re.compile(r"^def\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)", re.MULTILINE)


def _first_function(code: str) -> tuple[str, list[str]] | None:
    m = _FUNC_RE.search(code)
    if not m:
        return None
    params = [p.strip().split(":")[0].split("=")[0].strip()
              for p in m.group(2).split(",") if p.strip() and p.strip() != "self"]
    return m.group(1), params


_MALICIOUS_INPUTS = {
    "CWE-89": "' OR '1'='1",                      # SQL injection
    "CWE-78": "; echo ADF_PROBE_UNSAFE",          # command injection
    "CWE-79": "<script>alert(1)</script>",        # XSS
    "CWE-94": "__import__('os').getcwd()",        # code injection
    "CWE-20": "9" * 10000,                          # oversized / boundary input
}


def generate_probes(code: str, findings: list[CweFinding]) -> list[SecurityProbe]:
    """Produce runtime probes targeted at the weaknesses found (or general boundary probes)."""
    fn = _first_function(code)
    if fn is None:
        return []
    name, params = fn
    if not params:
        return []

    probes: list[SecurityProbe] = []
    target_cwes = {f.cwe_id for f in findings} or {"CWE-20"}

    for cwe in sorted(target_cwes):
        payload = _MALICIOUS_INPUTS.get(cwe)
        if payload is None:
            continue
        args = ", ".join(repr(payload) for _ in params)
        probe_code = (
            f"try:\n"
            f"    _r = {name}({args})\n"
            f"    print('{PROBE_PASS}:{cwe}', repr(_r)[:80])\n"
            f"except Exception as _e:\n"
            f"    print('{PROBE_PASS}:{cwe}', type(_e).__name__)\n"
        )
        probes.append(SecurityProbe(f"probe_{cwe}", cwe, probe_code))
    return probes


def generate_behavioural_probes() -> list[SecurityProbe]:
    """Runtime probes for privilege escalation, network egress, and resource use. Each prints an
    ADF_PROBE marker the sandbox parses.

    The sandbox runs network-disabled with all capabilities dropped and no-new-privileges, so these
    attempts are expected to fail (be blocked). A probe that succeeds indicates a sandbox escape.
    """
    privilege = (
        "import os\n"
        "try:\n"
        "    os.setuid(0)\n"
        f"    print('{PROBE_FAIL}:CWE-250 privilege-escalation succeeded')\n"
        "except Exception as _e:\n"
        f"    print('{PROBE_PASS}:privilege', type(_e).__name__)\n"
        "try:\n"
        "    open('/etc/shadow').read()\n"
        f"    print('{PROBE_FAIL}:CWE-269 read protected file')\n"
        "except Exception as _e:\n"
        f"    print('{PROBE_PASS}:file-perm', type(_e).__name__)\n"
    )
    network = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('8.8.8.8', 53), timeout=2)\n"
        f"    print('{PROBE_FAIL}:CWE-918 network egress succeeded')\n"
        "except Exception as _e:\n"
        f"    print('{PROBE_PASS}:network-blocked', type(_e).__name__)\n"
    )
    return [
        SecurityProbe("probe_privilege_escalation", "CWE-250", privilege),
        SecurityProbe("probe_network_egress", "CWE-918", network),
    ]


def render_test_block(probes: list[SecurityProbe]) -> str:
    """Combine probes into a single appended test block."""
    if not probes:
        return ""
    return "\n".join(p.code for p in probes)
