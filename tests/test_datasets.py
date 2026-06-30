"""Tests for dataset schema, CWE normalisation, and the synthetic adversarial generator."""
from __future__ import annotations

import json

from adf.common.datasets import (
    AdversarialKind,
    SampleKind,
    generate_adversarial,
    normalise_cwe,
    save_adversarial,
)


def test_normalise_cwe_variants():
    assert normalise_cwe("CWE-89") == "CWE-89"
    assert normalise_cwe("cwe_89") == "CWE-89"
    assert normalise_cwe("89") == "CWE-89"
    assert normalise_cwe("CWE-89_codeql_example") == "CWE-89"
    assert normalise_cwe("no-cwe-here") is None


def test_generate_adversarial_is_deterministic_and_labelled():
    a = generate_adversarial()
    b = generate_adversarial()
    assert [s.id for s in a] == [s.id for s in b]  # deterministic
    kinds = {s.adversarial for s in a}
    assert AdversarialKind.DIRECT in kinds
    assert AdversarialKind.INDIRECT in kinds
    assert AdversarialKind.OBFUSCATED in kinds
    assert AdversarialKind.BENIGN in kinds
    assert all(s.kind == SampleKind.PROMPT for s in a)


def test_save_adversarial_roundtrip(tmp_path):
    out = save_adversarial(tmp_path / "adv.jsonl")
    assert out.is_file()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(generate_adversarial())
    first = json.loads(lines[0])
    assert {"id", "text", "kind", "adversarial"} <= set(first)
