from skoll.config import (
    ANALYSIS_TEMPLATE_PROMPT,
    CHAT_WELCOME_MESSAGE,
    DEFAULT_GEMINI_MODEL,
    RAPTOR_SYSTEM_PROMPT,
)


def test_default_model():
    assert DEFAULT_GEMINI_MODEL is not None
    assert isinstance(DEFAULT_GEMINI_MODEL, str)
    assert DEFAULT_GEMINI_MODEL.startswith("gemini")


def test_raptor_system_prompt_contiene_etapas():
    assert "ETAPA A" in RAPTOR_SYSTEM_PROMPT
    assert "ETAPA B" in RAPTOR_SYSTEM_PROMPT
    assert "ETAPA C" in RAPTOR_SYSTEM_PROMPT
    assert "ETAPA D" in RAPTOR_SYSTEM_PROMPT
    assert "Ruido vs Realidad" in RAPTOR_SYSTEM_PROMPT
    assert "ESPAÑOL" in RAPTOR_SYSTEM_PROMPT


def test_analysis_template_contiene_placeholder():
    assert "{code_content}" in ANALYSIS_TEMPLATE_PROMPT


def test_analysis_template_contiene_raptor():
    assert "Etapa A" in ANALYSIS_TEMPLATE_PROMPT


def test_chat_welcome_message():
    assert "Skoll" in CHAT_WELCOME_MESSAGE
    assert "RAPTOR" in CHAT_WELCOME_MESSAGE
