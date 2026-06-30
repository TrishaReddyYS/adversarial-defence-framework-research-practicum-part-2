"""Tests for the CodeLlama client logic that does NOT require the model download.

The actual weights (~13 GB, gated) are not loaded here; we test prompt formatting, code
extraction, and factory wiring. A fake subclass exercises generate_code() deterministically.
"""
from __future__ import annotations

from adf.llm import get_client
from adf.llm.base import LLMClient
from adf.llm.codellama_client import CodeLlamaClient, build_prompt


def test_build_prompt_uses_instruct_format():
    out = build_prompt("Write a function to add two numbers.")
    assert "[INST]" in out and "[/INST]" in out
    assert "<<SYS>>" in out
    assert "Write a function to add two numbers." in out


def test_factory_returns_codellama_without_loading_model():
    client = get_client("codellama")
    assert isinstance(client, CodeLlamaClient)
    # Constructing must not trigger a model download.
    assert client._model is None
    assert "CodeLlama" in client.model


def test_generate_code_strips_markdown_fence():
    class FakeLlama(LLMClient):
        name = "fake"

        def generate(self, prompt: str, *, temperature: float = 0.2,
                     max_tokens: int = 1024) -> str:
            return "Here is the code:\n```python\ndef add(a, b):\n    return a + b\n```\nDone."

    code = FakeLlama().generate_code("add two numbers")
    assert code == "def add(a, b):\n    return a + b"


def test_generate_code_without_fence_returns_stripped_text():
    class Plain(LLMClient):
        name = "plain"

        def generate(self, prompt: str, *, temperature: float = 0.2,
                     max_tokens: int = 1024) -> str:
            return "  def f():\n    return 1  \n"

    assert Plain().generate_code("x") == "def f():\n    return 1"


def test_unknown_client_raises():
    import pytest

    with pytest.raises(ValueError):
        get_client("does-not-exist")
