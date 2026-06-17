from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseProvider(ABC):
    """Interfaz común para todos los proveedores LLM."""

    @abstractmethod
    def chat(
        self,
        prompt: str,
        model: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        system_prompt: str | None = None,
    ) -> str:
        """Envia prompt y devuelve respuesta."""

    @abstractmethod
    def supports(self, model: str) -> bool:
        """Indica si este proveedor puede servir el modelo indicado."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre del proveedor: 'groq', 'openrouter', 'google'."""


class GroqProvider(BaseProvider):
    """Wrapper sobre GroqClient existente."""

    def __init__(self, client: Any = None) -> None:
        if client is None:
            try:
                from skoll.client import GroqClient
                client = GroqClient()
            except Exception:
                client = None
        self._client = client
        self._groq_models: set[str] = {
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "llama3-8b-8192",
            "llama3-70b-8192",
            "llama-guard-3-8b",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
            "gemma2-27b-it",
            "gemma-7b-it",
            "deepseek-r1-distill-llama-70b",
            "deepseek-r1-distill-qwen-32b",
            "qwen-2.5-32b",
            "qwen-2.5-72b",
            "qwen-qwen3-32b",
            "qwen-qwen3.6-27b",
            "llama-4-scout-17b",
            "llama-4-maverick-17b",
        }

    @property
    def name(self) -> str:
        return "groq"

    def supports(self, model: str) -> bool:
        if not self._client or not model:
            return False
        base = model.split("/")[-1]
        return base in self._groq_models

    def chat(
        self,
        prompt: str,
        model: str = "llama-3.3-70b-versatile",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        system_prompt: str | None = None,
    ) -> str:
        if not self._client:
            return ""
        return self._client._call(prompt, model=model, temperature=temperature)


class OpenRouterProvider(BaseProvider):
    """Wrapper sobre OpenRouterClient existente."""

    def __init__(self, client: Any = None) -> None:
        if client is None:
            try:
                from skoll.client_openrouter import OpenRouterClient
                client = OpenRouterClient()
            except Exception:
                client = None
        self._client = client
        self._openrouter_prefixes: set[str] = {
            "deepseek/",
            "mistral/",
            "microsoft/",
            "google/gemini",
            "cognitivecomputations/",
        }

    @property
    def name(self) -> str:
        return "openrouter"

    def supports(self, model: str) -> bool:
        if not self._client or not model:
            return False
        for prefix in self._openrouter_prefixes:
            if model.startswith(prefix):
                return True
        return False

    def chat(
        self,
        prompt: str,
        model: str = "deepseek/deepseek-chat",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        system_prompt: str | None = None,
    ) -> str:
        if not self._client:
            return ""
        return self._client._call(prompt, model=model, temperature=temperature)


class GoogleProvider(BaseProvider):
    """Wrapper sobre GoogleClient (AI Studio, solo Judge)."""

    def __init__(self, client: Any = None) -> None:
        if client is None:
            try:
                from skoll.client_google import GoogleClient
                client = GoogleClient()
            except Exception:
                client = None
        self._client = client

    @property
    def name(self) -> str:
        return "google"

    def supports(self, model: str) -> bool:
        if not self._client or not model:
            return False
        return "gemini" in model.lower() and "openrouter" not in model

    def chat(
        self,
        prompt: str,
        model: str = "gemini-2.0-flash",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        system_prompt: str | None = None,
    ) -> str:
        if not self._client:
            return ""
        return self._client._call(prompt, temperature=temperature, max_tokens=max_tokens)

    def judge(self, findings_summary: str) -> str:
        if not self._client:
            return ""
        return self._client.judge(findings_summary)
