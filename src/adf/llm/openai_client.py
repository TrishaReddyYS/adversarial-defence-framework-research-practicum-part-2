"""GPT-4o client (application-layer: black-box, no model access).

Supports both the public OpenAI API and Azure OpenAI. If the AZURE_OPENAI_* variables are set,
the client uses Azure (the deployment name is the model id); otherwise it uses the public API.
"""
from __future__ import annotations

from adf.common.config import env
from adf.llm.base import LLMClient

_SYSTEM = "You are a helpful programming assistant. Return only the requested code."


class OpenAIClient(LLMClient):
    def __init__(self, model: str = "gpt-4o") -> None:
        self.name = model
        self.model = model
        self._client = None

    def _lazy_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import AzureOpenAI, OpenAI
        except ImportError as exc:
            raise ImportError("Install the LLM extra: pip install -e '.[llm]'") from exc

        azure_key = env("AZURE_OPENAI_API_KEY")
        azure_endpoint = env("AZURE_OPENAI_ENDPOINT")
        if azure_key and azure_endpoint:
            # Azure OpenAI: the model id passed to the API is the *deployment* name.
            self.model = env("AZURE_OPENAI_DEPLOYMENT", self.model)
            self._client = AzureOpenAI(
                api_key=azure_key,
                azure_endpoint=azure_endpoint,
                api_version=env("AZURE_OPENAI_API_VERSION", "2024-10-21"),
            )
            return self._client

        api_key = env("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "No LLM credentials: set AZURE_OPENAI_* (Azure) or OPENAI_API_KEY in .env."
            )
        self._client = OpenAI(api_key=api_key)
        return self._client

    def generate(self, prompt: str, *, temperature: float = 0.2, max_tokens: int = 1024) -> str:
        client = self._lazy_client()
        resp = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": _SYSTEM},
                      {"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""
