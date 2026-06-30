"""Abstract LLM client interface. Concrete clients wrap GPT-4 (API) and CodeLlama (local/HF)."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

_CODE_FENCE = re.compile(r"```(?:python)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


class LLMClient(ABC):
    """Common interface implemented by the GPT-4o and CodeLlama clients."""

    name: str = "llm"

    @abstractmethod
    def generate(self, prompt: str, *, temperature: float = 0.2, max_tokens: int = 1024) -> str:
        """Return the model's raw text response for a prompt."""

    def generate_code(self, prompt: str, **kwargs) -> str:
        """Generate and extract just the code (strips Markdown fences if present)."""
        raw = self.generate(prompt, **kwargs)
        m = _CODE_FENCE.search(raw)
        return (m.group(1) if m else raw).strip()
