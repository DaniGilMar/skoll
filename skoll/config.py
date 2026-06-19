import os

# Proveedor de IA por defecto: "gemini" (usa GEMINI_API_KEY del .env)
DEFAULT_PROVIDER = os.getenv("AI_PROVIDER", "gemini")

# Modelo Gemini por defecto (fallback si Groq no está disponible)
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Modelo OpenRouter por defecto
DEFAULT_OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")

# Modelo Groq — multi-model support (main + fast para tareas simples)
GROQ_MODELS = {
    "llama-3.3-70b-versatile": "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant": "llama-3.1-8b-instant",
    "llama-4-scout-17b": "meta-llama/llama-4-scout-17b-16e-instruct",
    "qwen-3-32b": "qwen/qwen3-32b",
    "mixtral-8x7b-32768": "mixtral-8x7b-32768",
    "llama3-70b-8192": "llama3-70b-8192",
    "llama3-8b-8192": "llama3-8b-8192",
}

# Modelo principal: análisis profundo (70B)
DEFAULT_GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Modelo rápido: tareas simples (8B) — para SAGE recall, errores, etc.
GROQ_FAST_MODEL = os.getenv("GROQ_FAST_MODEL", "llama-3.1-8b-instant")


def get_fast_model(provider: str | None = None) -> str:
    p = (provider or DEFAULT_PROVIDER).lower()
    if p == "groq":
        return GROQ_FAST_MODEL
    if p == "openrouter":
        return "microsoft/phi-4"
    return DEFAULT_GEMINI_MODEL


def get_default_model(provider: str | None = None) -> str:
    p = (provider or DEFAULT_PROVIDER).lower()
    if p == "groq":
        return DEFAULT_GROQ_MODEL
    if p == "openrouter":
        return DEFAULT_OPENROUTER_MODEL
    return DEFAULT_GEMINI_MODEL

# Prompts de Sistema inspirados en RAPTOR y localizados a Español

RAPTOR_SYSTEM_PROMPT = """
Eres Skoll (inspirado en el framework RAPTOR), un Ingeniero DevSecOps experto y Consultor de Ciberseguridad de élite.
Tu objetivo es realizar análisis de seguridad estáticos (SAST) y auditorías de código exhaustivas sobre los scripts y proyectos que proporcione el usuario.

IMPORTANTE: Opera estrictamente bajo principios defensivos y éticos:
1. No proporciones código de exploits funcionales ni payloads listos para atacar.
2. Enfócate exclusivamente en identificar vulnerabilidades, evaluar su impacto y sugerir parches seguros y de remediación.
3. Tus reportes y respuestas deben estar siempre en ESPAÑOL, estructurados, claros y listos para ser leídos por desarrolladores e ingenieros de seguridad.

Cuando audites un hallazgo, estructura tu análisis mental y tu reporte final bajo las siguientes ETAPAS DE RAPTOR:

- ETAPA A: Ruido vs Realidad
Evalúa si el posible fallo reportado es una vulnerabilidad real en el contexto de este código o si se trata de ruido del analizador (Falso Positivo). Justifica tu veredicto.

- ETAPA B: Requisitos de Explotación e Impacto
Describe qué condiciones técnicas, configuraciones especiales o nivel de acceso (ej. privilegios locales, red interna, etc.) necesitaría un atacante para detonar este fallo. Explica la gravedad real.

- ETAPA C: Alcanzabilidad del Flujo (Reachability)
Determina si los datos controlados por un usuario (entradas de API, parámetros de comandos, archivos de configuración, etc.) pueden viajar a través del flujo del programa hasta llegar al punto crítico (Sink) donde ocurre la vulnerabilidad.

- ETAPA D: Veredicto de Severidad y Solución Propuesta (Mitigación)
Asigna un nivel de severidad (Crítica, Alta, Media, Baja, Informativa). Proporciona explicaciones teóricas exhaustivas de por qué ocurre el problema y muestra el bloque de código corregido con las mejores prácticas aplicadas para mitigar el riesgo.
"""

ANALYSIS_TEMPLATE_PROMPT = """
Analiza el siguiente código fuente o resultado de escáner que te comparto.
Genera un reporte de seguridad extremadamente exhaustivo detallando todos los hallazgos en formato Markdown en ESPAÑOL.

Estructura el reporte para cada vulnerabilidad encontrada de la siguiente manera:

# [Severidad] - [Nombre de la Vulnerabilidad]
- **Archivo/Línea**: `ruta/del/archivo.py` (líneas correspondientes)
- **Descripción**: Breve descripción del fallo.

### Metodología de Auditoría RAPTOR:
1. **Etapa A (Ruido vs Realidad)**: [Tu análisis de si es real o falso positivo]
2. **Etapa B (Requisitos de Explotación)**: [Qué requiere un atacante para detonarla]
3. **Etapa C (Alcanzabilidad)**: [Análisis de flujo de datos del usuario al sink]

### Solución y Mitigación Propuesta:
- **Explicación Técnica**: Por qué la solución propuesta es segura.
- **Código Corregido**:
```[lenguaje]
[Código seguro corregido]
```

---
Código a analizar:
{code_content}
"""

CHAT_WELCOME_MESSAGE = """
[bold green]¡Bienvenido a Skoll CLI! 🛡️🤖[/bold green]
Iniciando chat interactivo de seguridad inspirado en el framework RAPTOR...
Las respuestas e instrucciones están adaptadas al español.
Escribe [bold cyan]'salir'[/bold cyan] o usa [bold cyan]Ctrl+D[/bold cyan] para finalizar la sesión de chat.
"""
