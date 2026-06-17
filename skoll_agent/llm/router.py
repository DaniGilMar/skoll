from __future__ import annotations

import random
import threading
import time
from typing import Any

from skoll_agent.llm.providers import (
    BaseProvider,
    GoogleProvider,
    GroqProvider,
    OpenRouterProvider,
)

MAX_RETRIES = 3
BACKOFF_BASE = 2
CIRCUIT_BREAKER_SECONDS = 300
MIN_REQUEST_INTERVAL = 0.35


class LLMRouter:
    """Router unificado de LLM. Elige el proveedor según el modelo.

    Uso básico:
        llm = LLMRouter()
        resp = llm.chat("analiza esto", model="llama-3.3-70b-versatile")
        resp2 = llm.chat("resume", model="deepseek/deepseek-chat")
    """

    def __init__(self) -> None:
        self._providers: list[BaseProvider] = [
            GroqProvider(),
            OpenRouterProvider(),
            GoogleProvider(),
        ]
        self._lock = threading.Lock()
        self._last_request: float = 0.0
        self._failures: dict[str, dict[str, Any]] = {}
        self._google_provider: GoogleProvider | None = None

    def _get_provider(self, model: str) -> BaseProvider | None:
        for p in self._providers:
            if p.supports(model):
                return p
        return None

    def _throttle(self) -> None:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request
            if elapsed < MIN_REQUEST_INTERVAL:
                time.sleep(MIN_REQUEST_INTERVAL - elapsed)
            self._last_request = time.time()

    def _is_blocked(self, model: str) -> bool:
        entry = self._failures.get(model)
        if not entry:
            return False
        if time.time() >= entry.get("unblock_at", 0):
            del self._failures[model]
            return False
        return True

    def _mark_failure(self, model: str, is_rate_limit: bool = False) -> None:
        if is_rate_limit:
            return
        entry = self._failures.setdefault(model, {"count": 0, "unblock_at": 0})
        entry["count"] += 1
        if entry["count"] >= 3:
            entry["unblock_at"] = time.time() + CIRCUIT_BREAKER_SECONDS

    def _mark_success(self, model: str) -> None:
        self._failures.pop(model, None)

    def chat(
        self,
        prompt: str,
        model: str = "llama-3.3-70b-versatile",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        system_prompt: str | None = None,
    ) -> str:
        if self._is_blocked(model):
            return ""

        provider = self._get_provider(model)
        if not provider:
            raise ValueError(
                f"No provider found for model '{model}'. "
                f"Available: {[p.name for p in self._providers]}"
            )

        for attempt in range(MAX_RETRIES):
            self._throttle()
            try:
                resp = provider.chat(
                    prompt=prompt,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    system_prompt=system_prompt,
                )
                self._mark_success(model)
                return resp
            except Exception as e:
                err_str = str(e)
                is_429 = "429" in err_str
                if is_429 and attempt < MAX_RETRIES - 1:
                    delay = (BACKOFF_BASE ** attempt) * 2 + random.uniform(0, 0.5)
                    time.sleep(delay)
                    continue
                if not is_429:
                    self._mark_failure(model, is_rate_limit=False)
                break

        return ""

    def judge(self, findings_summary: str) -> str:
        """Usa Google Gemini como juez de hallazgos."""
        if self._google_provider is None:
            self._google_provider = GoogleProvider()
        return self._google_provider.judge(findings_summary)

    def supports(self, model: str) -> bool:
        return self._get_provider(model) is not None


_router: LLMRouter | None = None


def get_llm_router() -> LLMRouter:
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router
