"""Tree-sitter AST-based CWE detection for generated Python code.

Combines AST-structural sink detection with lightweight taint tracking (sources flow into
sinks) to map code constructs to the MITRE CWE Top 25. High-precision, prototype-grade rules
covering the CWEs in the project's focused scope: CWE-20, CWE-78, CWE-79, CWE-89, CWE-94, CWE-798.
"""
from __future__ import annotations

from typing import Iterator

from adf.common.types import CweFinding, Severity

# Substrings that indicate an untrusted input source (lightweight taint markers).
_SOURCE_MARKERS = ("request.", "input(", "sys.argv", "argv[", "flask.request")

# Sinks by CWE.
_SQL_METHODS = {"execute", "executemany", "executescript", "executequery"}
_CMD_FUNCS = {"system", "popen"}
_SUBPROCESS = {"call", "run", "popen", "check_output", "check_call"}
_CODE_EXEC = {"eval", "exec", "compile"}
_XSS_SINKS = {"render_template_string", "mark_safe", "markup", "httpresponse", "response"}
_VALIDATION_SINKS = {"int", "float", "open"}

_CRED_NAMES = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "access_key", "private_key", "secret_key", "db_pass",
)


def _walk(node) -> Iterator:
    yield node
    for child in node.children:
        yield from _walk(child)


class ASTAnalyzer:
    """Parses Python source with Tree-sitter and detects CWE-mapped weaknesses."""

    def __init__(self) -> None:
        try:
            import tree_sitter_python as tspython
            from tree_sitter import Language, Parser
        except ImportError as exc:  # pragma: no cover - exercised only without the dep
            raise ImportError(
                "Layer 2 requires tree-sitter and tree-sitter-python. Install with "
                "`pip install tree-sitter tree-sitter-python`."
            ) from exc
        self._parser = Parser(Language(tspython.language()))

    # --- text / structural helpers ------------------------------------------------------------
    def _text(self, node) -> str:
        return self._src[node.start_byte:node.end_byte].decode("utf-8", "replace")

    @staticmethod
    def _line(node) -> int:
        return node.start_point[0] + 1

    def _is_static_string(self, node) -> bool:
        if node.type != "string":
            return False
        return not any(c.type == "interpolation" for c in _walk(node))

    def _has_source(self, node) -> bool:
        return any(marker in self._text(node) for marker in _SOURCE_MARKERS)

    def _is_dynamic(self, node) -> bool:
        """True if the expression is built from variables/inputs rather than a constant literal."""
        t = node.type
        if t == "string":
            return any(c.type == "interpolation" for c in _walk(node))  # f-string
        if t == "binary_operator":
            op = node.child_by_field_name("operator")
            if op is not None and self._text(op) in {"+", "%"}:
                return True
        if t == "call":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "attribute":
                attr = fn.child_by_field_name("attribute")
                if attr is not None and self._text(attr) == "format":
                    return True
        if t == "identifier" and self._text(node) in self._tainted:
            return True
        if self._has_source(node):
            return True
        return False

    @staticmethod
    def _call_parts(node):
        fn = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        args = [c for c in args_node.children if c.is_named] if args_node else []
        return fn, args

    def _func_name(self, fn) -> tuple[str, str]:
        """Return (full_name, base_name) for a call's function node."""
        if fn is None:
            return "", ""
        full = self._text(fn)
        if fn.type == "attribute":
            attr = fn.child_by_field_name("attribute")
            base = self._text(attr) if attr is not None else full
        else:
            base = full
        return full, base

    # --- taint pre-pass -----------------------------------------------------------------------
    def _collect_tainted(self, root) -> None:
        self._tainted: set[str] = set()
        # Iterate to a fixpoint so chained assignments propagate taint.
        changed = True
        while changed:
            changed = False
            for node in _walk(root):
                if node.type != "assignment":
                    continue
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None or left.type != "identifier":
                    continue
                name = self._text(left)
                if name in self._tainted:
                    continue
                if self._is_dynamic(right) and not self._is_static_string(right):
                    self._tainted.add(name)
                    changed = True

    # --- main entry ---------------------------------------------------------------------------
    def analyze(self, code: str) -> list[CweFinding]:
        self._src = code.encode("utf-8")
        tree = self._parser.parse(self._src)
        root = tree.root_node
        self._collect_tainted(root)

        findings: list[CweFinding] = []
        for node in _walk(root):
            if node.type == "call":
                findings.extend(self._check_call(node))
            elif node.type == "assignment":
                findings.extend(self._check_hardcoded_credentials(node))
            elif node.type == "keyword_argument":
                findings.extend(self._check_kwarg_credentials(node))

        # Deduplicate identical (cwe, line) findings.
        unique: dict[tuple, CweFinding] = {}
        for f in findings:
            unique.setdefault((f.cwe_id, f.line), f)
        return list(unique.values())

    def _check_call(self, node) -> list[CweFinding]:
        fn, args = self._call_parts(node)
        full, base = self._func_name(fn)
        base_l = base.lower()
        full_l = full.lower()
        out: list[CweFinding] = []
        first_dynamic = bool(args) and self._is_dynamic(args[0])

        # CWE-89: SQL injection via dynamically built query string.
        if base_l in _SQL_METHODS and first_dynamic and not self._is_static_string(args[0]):
            out.append(CweFinding("CWE-89", "SQL Injection", f"Dynamically built query passed to "
                                  f"{full}()", self._line(node), severity=Severity.HIGH))

        # CWE-94: code injection via eval/exec/compile on non-literal input.
        if base_l in _CODE_EXEC and args and not self._is_static_string(args[0]):
            out.append(CweFinding("CWE-94", "Code Injection", f"Non-literal input passed to "
                                  f"{base}()", self._line(node), severity=Severity.CRITICAL))

        # CWE-78: OS command injection.
        is_os_cmd = base_l in _CMD_FUNCS and ("os." in full_l or full_l.startswith("popen"))
        is_subprocess = "subprocess" in full_l and base_l in _SUBPROCESS
        if (is_os_cmd or is_subprocess) and (first_dynamic or self._shell_true(args)):
            if first_dynamic and not self._is_static_string(args[0]):
                out.append(CweFinding("CWE-78", "OS Command Injection", f"Untrusted input in "
                                      f"{full}()", self._line(node), severity=Severity.HIGH))

        # CWE-79: cross-site scripting via unescaped output.
        if base_l in _XSS_SINKS and first_dynamic and not self._is_static_string(args[0]):
            out.append(CweFinding("CWE-79", "Cross-site Scripting", f"Unescaped dynamic content in "
                                  f"{full}()", self._line(node), severity=Severity.HIGH))

        # CWE-20: improper input validation (untrusted input into int/float/open w/o guard).
        if base_l in _VALIDATION_SINKS and args and self._has_source(args[0]) \
                and not self._within_try(node):
            out.append(CweFinding("CWE-20", "Improper Input Validation", f"Unvalidated input passed "
                                  f"to {base}()", self._line(node), severity=Severity.MEDIUM))
        return out

    def _shell_true(self, args) -> bool:
        for a in args:
            if a.type == "keyword_argument":
                name = a.child_by_field_name("name")
                value = a.child_by_field_name("value")
                if name is not None and self._text(name) == "shell" and value is not None \
                        and self._text(value) == "True":
                    return True
        return False

    def _within_try(self, node) -> bool:
        cur = node.parent
        while cur is not None:
            if cur.type == "try_statement":
                return True
            cur = cur.parent
        return False

    def _check_hardcoded_credentials(self, node) -> list[CweFinding]:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            return []
        name = self._text(left).lower()
        if any(c in name for c in _CRED_NAMES) and self._is_static_string(right):
            literal = self._text(right).strip("\"'")
            if literal and literal.lower() not in {"", "none", "changeme", "x"}:
                return [CweFinding("CWE-798", "Hard-coded Credentials",
                                   f"Hard-coded secret assigned to '{self._text(left)}'",
                                   self._line(node), severity=Severity.HIGH)]
        return []

    def _check_kwarg_credentials(self, node) -> list[CweFinding]:
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or value is None:
            return []
        name = self._text(name_node).lower()
        if any(c in name for c in _CRED_NAMES) and self._is_static_string(value):
            literal = self._text(value).strip("\"'")
            if literal and literal.lower() not in {"", "none", "changeme", "x"}:
                return [CweFinding("CWE-798", "Hard-coded Credentials",
                                   f"Hard-coded secret passed as '{self._text(name_node)}'",
                                   self._line(node), severity=Severity.HIGH)]
        return []
