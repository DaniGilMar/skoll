from __future__ import annotations

import random
import threading
import time
from typing import Any

from skoll.client import GroqClient

_GOOGLE_CLIENT: Any | None = None

def _get_google_client() -> Any | None:
    global _GOOGLE_CLIENT
    if _GOOGLE_CLIENT is None:
        try:
            from skoll.client_google import GoogleClient
            _GOOGLE_CLIENT = GoogleClient()
        except Exception:
            _GOOGLE_CLIENT = False
    return _GOOGLE_CLIENT if _GOOGLE_CLIENT else None

FREE_MODELS: list[dict[str, Any]] = [
    {"model": "llama-3.3-70b-versatile", "weight": 5, "capability": "high"},
    {"model": "qwen/qwen3-32b", "weight": 4, "capability": "high"},
    {"model": "qwen/qwen3.6-27b", "weight": 3, "capability": "medium"},
    {"model": "deepseek-r1-distill-llama-70b", "weight": 4, "capability": "high"},
    {"model": "llama-4-scout-17b", "weight": 2, "capability": "medium"},
    {"model": "llama-4-maverick-17b", "weight": 3, "capability": "medium"},
    {"model": "gemma2-9b-it", "weight": 1, "capability": "low"},
    {"model": "llama-3.1-8b-instant", "weight": 1, "capability": "low"},
]

OPENROUTER_FREE_MODELS: list[str] = [
    "deepseek/deepseek-chat",
    "mistral/mistral-nemo",
    "microsoft/phi-4",
    "google/gemini-2.0-flash-exp:free",
]

MAX_RETRIES = 3
CIRCUIT_BREAKER_SECONDS = 300
MIN_REQUEST_INTERVAL = 0.33
BACKOFF_BASE = 2


class ModelPool:

    def __init__(self, groq_client: GroqClient | None = None, openrouter_client: Any = None):
        self.groq = groq_client
        self.openrouter = openrouter_client
        self._lock = threading.Lock()
        self._last_request: float = 0.0
        self._failures: dict[str, dict[str, Any]] = {}

    # ── Rate limiter ──────────────────────────────────────────

    def _throttle(self) -> None:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request
            if elapsed < MIN_REQUEST_INTERVAL:
                time.sleep(MIN_REQUEST_INTERVAL - elapsed)
            self._last_request = time.time()

    # ── Circuit breaker ───────────────────────────────────────

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

    # ── Query with retry + backoff ────────────────────────────

    def _query_one(self, model: str, prompt: str, cost_tracker: Any = None) -> str:
        if self._is_blocked(model):
            return ""

        for attempt in range(MAX_RETRIES):
            self._throttle()
            err: Exception | None = None

            # Intentar Groq
            if self.groq:
                try:
                    resp = self.groq._call(prompt, model=model, temperature=0.1)
                    if cost_tracker:
                        cost_tracker.record(
                            model=model, input_tokens=len(prompt)//4,
                            output_tokens=len(resp)//4, endpoint="model_pool",
                        )
                    self._mark_success(model)
                    return resp
                except Exception as e:
                    err = e

            # Intentar OpenRouter si Groq falló
            if self.openrouter:
                try:
                    resp = self.openrouter._call(prompt, model=model)
                    if cost_tracker:
                        cost_tracker.record(
                            model=model, input_tokens=len(prompt)//4,
                            output_tokens=len(resp)//4, endpoint="model_pool_or",
                        )
                    self._mark_success(model)
                    return resp
                except Exception as e:
                    err = e

            if err is None:
                return ""

            err_str = str(err)
            is_429 = "429" in err_str

            if is_429 and attempt < MAX_RETRIES - 1:
                delay = (BACKOFF_BASE ** attempt) * 2 + random.uniform(0, 0.5)
                time.sleep(delay)
                continue

            self._mark_failure(model, is_rate_limit=is_429)
            break

        return ""

    # ── Public API ────────────────────────────────────────────

    def all_models(self) -> list[str]:
        models = [m["model"] for m in FREE_MODELS]
        if self.openrouter:
            models.extend(OPENROUTER_FREE_MODELS)
        return models

    def query_all(
        self,
        prompt: str,
        min_capability: str = "low",
        cost_tracker: Any = None,
    ) -> dict[str, str]:
        results: dict[str, str] = {}
        sorted_models = sorted(
            [m for m in FREE_MODELS
             if m["capability"] in ("high", "medium", "low")
             and not (m["capability"] == "low" and min_capability in ("medium", "high"))
             and not (m["capability"] == "medium" and min_capability == "high")],
            key=lambda x: -x["weight"],
        )
        for m in sorted_models:
            resp = self._query_one(m["model"], prompt, cost_tracker)
            if resp:
                results[m["model"]] = resp
        return results

    def query_top_k(
        self,
        prompt: str,
        k: int = 3,
        cost_tracker: Any = None,
    ) -> dict[str, str]:
        selected = sorted(FREE_MODELS, key=lambda x: -x["weight"])[:k]
        results: dict[str, str] = {}
        for m in selected:
            resp = self._query_one(m["model"], prompt, cost_tracker)
            if resp:
                results[m["model"]] = resp
        return results

    def shutdown(self):
        pass
