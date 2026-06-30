"""CodeLlama client via Hugging Face Transformers.

Loads the model locally through Transformers and generates code from natural-language prompts.
Heavy dependencies (transformers, torch) and the model download are lazy: the client only needs
them when `generate()` is first called, so the rest of the framework runs without them.
"""
from __future__ import annotations

from adf.common.config import env
from adf.common.logging import get_logger
from adf.llm.base import LLMClient

log = get_logger("llm.codellama")

# CodeLlama-Instruct prompt format (Meta). A system prompt is wrapped in <<SYS>>.
_SYSTEM = ("You are an expert programmer. Write secure, correct Python code for the user's "
           "request. Return only the code.")
_TEMPLATE = "<s>[INST] <<SYS>>\n{system}\n<</SYS>>\n\n{prompt} [/INST]"


def build_prompt(prompt: str, system: str = _SYSTEM) -> str:
    """Format a user prompt into the CodeLlama-Instruct template (pure, unit-testable)."""
    return _TEMPLATE.format(system=system, prompt=prompt.strip())


def _select_device() -> str:
    """Pick the best available device: CUDA > Apple MPS > CPU."""
    try:
        import torch
    except ImportError:
        return "cpu"
    if torch.cuda.is_available():
        return "cuda"
    if getattr(torch.backends, "mps", None) is not None and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


class CodeLlamaClient(LLMClient):
    def __init__(self, model: str = "codellama/CodeLlama-7b-Instruct-hf",
                 device: str | None = None) -> None:
        self.name = model
        self.model = model
        self.device = device or _select_device()
        self._tokenizer = None
        self._model = None

    def _lazy_load(self) -> None:
        if self._model is not None:
            return
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise ImportError(
                "CodeLlama needs the LLM extra: pip install -e '.[llm]'"
            ) from exc

        token = env("HF_TOKEN")  # used to download the CodeLlama weights
        log.info("Loading %s on %s ...", self.model, self.device)
        self._tokenizer = AutoTokenizer.from_pretrained(self.model, token=token)
        dtype = torch.float16 if self.device in {"cuda", "mps"} else torch.float32
        # transformers >=5 renamed `torch_dtype` to `dtype`; support both.
        try:
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model, token=token, dtype=dtype
            ).to(self.device)
        except TypeError:
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model, token=token, torch_dtype=dtype
            ).to(self.device)

    def generate(self, prompt: str, *, temperature: float = 0.2, max_tokens: int = 1024) -> str:
        self._lazy_load()
        import torch

        text = build_prompt(prompt)
        inputs = self._tokenizer(text, return_tensors="pt").to(self.device)
        with torch.no_grad():
            output = self._model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                do_sample=temperature > 0,
                temperature=max(temperature, 1e-4),
                pad_token_id=self._tokenizer.eos_token_id,
            )
        # Decode only the newly generated tokens (exclude the prompt).
        generated = output[0][inputs["input_ids"].shape[-1]:]
        return self._tokenizer.decode(generated, skip_special_tokens=True).strip()
