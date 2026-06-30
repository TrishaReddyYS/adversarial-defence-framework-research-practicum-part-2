"""LLM client factory."""
from __future__ import annotations

from adf.common.config import Config, env, load_config
from adf.llm.base import LLMClient


def get_client(name: str = "openai", config: Config | None = None) -> LLMClient:
    """Return an LLM client by name ('openai'/'gpt-4' or 'codellama').

    Model name precedence: ADF_*_MODEL env override (from .env) > YAML config > built-in default.
    """
    config = config or load_config()
    name = name.lower()
    if name in {"openai", "gpt-4", "gpt4"}:
        from adf.llm.openai_client import OpenAIClient
        model = env("ADF_OPENAI_MODEL") or config.get("models.openai", "gpt-4o")
        return OpenAIClient(model=model)
    if name in {"codellama", "code-llama"}:
        from adf.llm.codellama_client import CodeLlamaClient
        model = env("ADF_CODELLAMA_MODEL") or config.get("models.codellama")
        return CodeLlamaClient(model=model)
    raise ValueError(f"Unknown LLM client: {name!r}")


__all__ = ["LLMClient", "get_client"]
