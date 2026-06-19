import os
from typing import Any

from skoll.config import (
    DEFAULT_GEMINI_MODEL,
    DEFAULT_GROQ_MODEL,
    GROQ_FAST_MODEL,
    RAPTOR_SYSTEM_PROMPT,
    get_fast_model,
)


class _GroqStreamChunk:
    def __init__(self, text: str):
        self.text = text


class GroqClient:
    """Multi-model Groq client — main model for analysis, fast model for simple tasks."""

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError(
                "No se ha proporcionado una API Key de Groq. "
                "Configúrala en GROQ_API_KEY o en .env"
            )

        try:
            from groq import Groq
            self._client = Groq(api_key=self.api_key)
        except ImportError:
            raise RuntimeError("Groq no está instalado. pip install groq")
        except Exception as e:
            raise RuntimeError(f"Error al inicializar Groq: {e}")

    @property
    def groq_client(self):
        return self._client

    def _call(self, prompt: str, model: str, temperature: float = 0.2) -> str:
        """Unified completion call — returns full response text."""
        from groq import Groq as _Groq
        response = self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": RAPTOR_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
        )
        return response.choices[0].message.content or ""

    def analizar_codigo_stream(self, prompt_usuario: str, model: str | None = None):
        """Streaming completion for UI display."""
        model = model or DEFAULT_GROQ_MODEL
        stream = self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": RAPTOR_SYSTEM_PROMPT},
                {"role": "user", "content": prompt_usuario},
            ],
            stream=True,
            temperature=0.2,
        )
        for chunk in stream:
            delta = chunk.choices[0].delta.content or ""
            yield _GroqStreamChunk(delta)

    def analyze(self, prompt: str, model: str | None = None) -> str:
        """Non-streaming analysis — returns full response."""
        return self._call(prompt, model or DEFAULT_GROQ_MODEL, temperature=0.2)

    def analyze_fast(self, prompt: str) -> str:
        """Quick analysis with fast model (8B) for simple tasks."""
        return self._call(prompt, GROQ_FAST_MODEL, temperature=0.1)

    def analyze_with_fallback(self, prompt: str) -> tuple[str, str]:
        """Try main model, fall back to fast model on failure.
        Returns (response_text, model_used)."""
        try:
            return self._call(prompt, DEFAULT_GROQ_MODEL), DEFAULT_GROQ_MODEL
        except Exception:
            try:
                return self._call(prompt, GROQ_FAST_MODEL), GROQ_FAST_MODEL
            except Exception:
                return "", "none"

    def iniciar_chat(self, model: str = DEFAULT_GROQ_MODEL):
        return GroqChatSession(self._client, model)


class GroqChatSession:
    def __init__(self, client, model: str):
        self._client = client
        self._model = model
        self._messages = [{"role": "system", "content": RAPTOR_SYSTEM_PROMPT}]

    def send_message_stream(self, message: str):
        self._messages.append({"role": "user", "content": message})
        stream = self._client.chat.completions.create(
            model=self._model,
            messages=self._messages,
            stream=True,
            temperature=0.3,
        )
        full = ""
        for chunk in stream:
            delta = chunk.choices[0].delta.content or ""
            full += delta
            yield _GroqStreamChunk(delta)
        self._messages.append({"role": "assistant", "content": full})


class GeminiClient:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("No se ha proporcionado una API Key de Gemini.")

        try:
            from google import genai
            from google.genai import types
            self._client = genai.Client(api_key=self.api_key)
            self._types = types
        except Exception as e:
            raise RuntimeError(f"Error al inicializar Gemini: {e}")

    def analizar_codigo_stream(self, prompt_usuario: str, model: str = DEFAULT_GEMINI_MODEL):
        config = self._types.GenerateContentConfig(
            system_instruction=RAPTOR_SYSTEM_PROMPT,
            temperature=0.2,
        )
        return self._client.models.generate_content_stream(
            model=model, contents=prompt_usuario, config=config
        )

    def analyze(self, prompt: str, model: str | None = None) -> str:
        config = self._types.GenerateContentConfig(
            system_instruction=RAPTOR_SYSTEM_PROMPT,
            temperature=0.2,
        )
        response = self._client.models.generate_content(
            model=model or DEFAULT_GEMINI_MODEL,
            contents=prompt,
            config=config,
        )
        return response.text or ""

    def analyze_fast(self, prompt: str) -> str:
        return self.analyze(prompt, model="gemini-2.5-flash")

    def analyze_with_fallback(self, prompt: str) -> tuple[str, str]:
        try:
            return self.analyze(prompt), DEFAULT_GEMINI_MODEL
        except Exception:
            return "", "none"

    def iniciar_chat(self, model: str = DEFAULT_GEMINI_MODEL):
        config = self._types.GenerateContentConfig(
            system_instruction=RAPTOR_SYSTEM_PROMPT,
            temperature=0.3,
        )
        return self._client.chats.create(model=model, config=config)


def crear_cliente(provider: str = "groq", api_key: str | None = None):
    p = provider.lower()
    if p == "groq":
        return GroqClient(api_key=api_key)
    if p == "openrouter":
        from skoll.client_openrouter import OpenRouterClient
        return OpenRouterClient(api_key=api_key)
    return GeminiClient(api_key=api_key)
