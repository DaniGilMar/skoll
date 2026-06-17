from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


class GoogleClient:
    """Cliente directo para Google AI Studio (Gemini Flash).
    
    No requiere paquetes externos — usa urllib de la stdlib.
    Gratis: 60 requests/minuto, 1M tokens de contexto.
    """

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError(
                "No se ha proporcionado una API Key de Google AI Studio. "
                "Configúrala en GOOGLE_API_KEY (consíguela en https://aistudio.google.com/apikey)"
            )

    def _call(self, prompt: str, temperature: float = 0.1, max_tokens: int = 2048) -> str:
        data: dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        url = f"{self.BASE_URL}?key={self.api_key}"
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return text or ""
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            raise RuntimeError(f"Google AI Studio call failed: {e}")

    def analyze(self, prompt: str) -> str:
        return self._call(prompt, temperature=0.1)

    def judge(self, findings_summary: str) -> str:
        """Actúa como juez: valida hallazgos y detecta falsos positivos."""
        prompt = f"""Eres un juez imparcial de seguridad informática. Tu trabajo es validar hallazgos de una auditoría profesional y determinar si son VERDADEROS o FALSOS POSITIVOS.

Eres escéptico por naturaleza: si un hallazgo no tiene evidencia suficiente, márcalo como FALSO.
Usa tu criterio independiente — no te dejes influenciar por análisis previos.

{findings_summary}

Para cada hallazgo, responde en este formato JSON:
{{"veredicto": "VERDADERO/FALSO/INC", "razon": "...", "confianza": "alta/media/baja"}}

Si todo es correcto, responde: {{"veredicto": "TODO_CORRECTO", "razon": "Todos los hallazgos parecen válidos", "confianza": "alta"}}"""
        return self._call(prompt, temperature=0.05, max_tokens=1024)
