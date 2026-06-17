from __future__ import annotations

import os
from typing import Any

OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"
OPENROUTER_FREE_MODELS = [
    "deepseek/deepseek-chat",
    "mistral/mistral-nemo",
    "cognitivecomputations/dolphin-mixtral-8x7b",
    "microsoft/phi-4",
    "qwen/qwen-2.5-72b-instruct",
    "google/gemini-2.0-flash-exp:free",
]


class OpenRouterClient:
    """Cliente para OpenRouter — modelos gratuitos y de pago con una sola API."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError(
                "No se ha proporcionado una API Key de OpenRouter. "
                "Configúrala en OPENROUTER_API_KEY"
            )
        try:
            from openai import OpenAI
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=OPENROUTER_API_BASE,
            )
        except ImportError:
            raise RuntimeError("openai no está instalado. pip install openai")

    def _call(self, prompt: str, model: str = "deepseek/deepseek-chat", temperature: float = 0.1) -> str:
        try:
            completion = self._client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=2000,
            )
            return completion.choices[0].message.content or ""
        except Exception as e:
            raise RuntimeError(f"OpenRouter call failed: {e}")

    def analyze(self, prompt: str, model: str | None = None) -> str:
        return self._call(prompt, model=model or "deepseek/deepseek-chat")

    def analyze_fast(self, prompt: str) -> str:
        return self._call(prompt, model="microsoft/phi-4", temperature=0.1)

    def analyze_with_fallback(self, prompt: str) -> tuple[str, str]:
        models = ["deepseek/deepseek-chat", "mistral/mistral-nemo", "microsoft/phi-4"]
        for model in models:
            try:
                return self._call(prompt, model=model), model
            except Exception:
                continue
        return "", "none"
