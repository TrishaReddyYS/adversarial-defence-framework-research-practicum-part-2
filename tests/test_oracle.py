"""Tests for the independent vulnerability oracle (Bandit-based, evaluation only)."""
from __future__ import annotations

import pytest

from eval.metrics.oracle import oracle_available, scan_code

pytestmark = pytest.mark.skipif(not oracle_available(),
                                reason="Bandit not installed (install the eval extra)")

_SHELL_INJECTION = """
import subprocess
def run(cmd):
    subprocess.call(cmd, shell=True)
"""

_SQL_INJECTION = """
import sqlite3
def lookup(name):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
"""

_SAFE = """
def add(a, b):
    return a + b
"""


def test_oracle_flags_shell_injection():
    result = scan_code(_SHELL_INJECTION)
    assert result.vulnerable
    assert "CWE-78" in result.cwes


def test_oracle_flags_sql_injection():
    result = scan_code(_SQL_INJECTION)
    assert result.vulnerable
    assert "CWE-89" in result.cwes


def test_oracle_passes_safe_code():
    assert not scan_code(_SAFE).vulnerable


def test_oracle_treats_empty_as_safe():
    assert not scan_code("").vulnerable
    assert not scan_code("   \n  ").vulnerable
