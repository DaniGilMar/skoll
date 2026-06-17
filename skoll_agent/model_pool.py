from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from skoll.client import GroqClient

# Si Google AI Studio está configurado, se usa como juez independiente
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

# Modelos gratuitos disponibles en Groq — ordenados por capacidad
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

# Para OpenRouter — modelos gratuitos adicionales
OPENROUTER_FREE_MODELS: list[str] = [
    "deepseek/deepseek-chat",
    "mistral/mistral-nemo",
    "microsoft/phi-4",
    "google/gemini-2.0-flash-exp:free",
]


class ModelPool:
    """Pool de modelos gratuitos que ejecuta consultas en paralelo.

    Útil para multi-agente: cada agente usa un modelo diferente,
    todos corren simultáneamente, resultados se consolidan.

    Soporta Groq (gratis) y OpenRouter (opcional, si hay API key).
    """

    def __init__(self, groq_client: GroqClient | None = None, openrouter_client: Any = None):
        self.groq = groq_client
        self.openrouter = openrouter_client
        self._executor = ThreadPoolExecutor(max_workers=12)

    def _query_one(self, model: str, prompt: str, cost_tracker: Any = None) -> str:
        """Consulta un modelo individual. Prueba Groq primero, luego OpenRouter."""
        if self.groq:
            try:
                start = time.time()
                resp = self.groq._call(prompt, model=model, temperature=0.1)
                if cost_tracker:
                    cost_tracker.record(
                        model=model, input_tokens=len(prompt)//4,
                        output_tokens=len(resp)//4, endpoint="model_pool",
                    )
                return resp
            except Exception:
                pass
        if self.openrouter:
            try:
                resp = self.openrouter._call(prompt, model=model)
                if cost_tracker:
                    cost_tracker.record(
                        model=model, input_tokens=len(prompt)//4,
                        output_tokens=len(resp)//4, endpoint="model_pool_or",
                    )
                return resp
            except Exception:
                pass
        return ""

    def all_models(self) -> list[str]:
        """Todos los modelos disponibles (Groq + OpenRouter si configurado)."""
        models = [m["model"] for m in FREE_MODELS]
        if self.openrouter:
            models.extend(OPENROUTER_FREE_MODELS)
        return models

    def query_all(
        self,
        prompt: str,
        min_capability: str = "low",
        max_workers: int = 6,
        cost_tracker: Any = None,
    ) -> dict[str, str]:
        """Ejecuta el mismo prompt contra TODOS los modelos gratuitos en paralelo.

        Returns: {model_name: response_text}
        """
        futures: dict[Any, str] = {}
        for m in FREE_MODELS:
            if m["capability"] not in ("high", "medium", "low"):
                continue
            if m["capability"] == "low" and min_capability == "high":
                continue
            if m["capability"] == "low" and min_capability == "medium":
                continue
            if m["capability"] == "medium" and min_capability == "high":
                continue
            futures[self._executor.submit(self._query_one, m["model"], prompt, cost_tracker)] = m["model"]

        results: dict[str, str] = {}
        for future in as_completed(futures):
            model_name = futures[future]
            try:
                resp = future.result(timeout=60)
                if resp:
                    results[model_name] = resp
            except Exception:
                pass
        return results

    def query_top_k(
        self,
        prompt: str,
        k: int = 3,
        cost_tracker: Any = None,
    ) -> dict[str, str]:
        """Ejecuta contra los k modelos con mayor weight en paralelo."""
        selected = sorted(FREE_MODELS, key=lambda x: -x["weight"])[:k]
        futures = {}
        for m in selected:
            futures[self._executor.submit(self._query_one, m["model"], prompt, cost_tracker)] = m["model"]

        results: dict[str, str] = {}
        for future in as_completed(futures):
            model_name = futures[future]
            try:
                resp = future.result(timeout=60)
                if resp:
                    results[model_name] = resp
            except Exception:
                pass
        return results

    def shutdown(self):
        self._executor.shutdown(wait=False)
