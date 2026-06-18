import asyncio
import json
import os
import uuid
from pathlib import Path

# Auto-load .env from project root
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    for _line in _env_path.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from skoll.client import crear_cliente
from skoll.config import (
    ANALYSIS_TEMPLATE_PROMPT,
    DEFAULT_PROVIDER,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_GROQ_MODEL,
    get_default_model,
)
from skoll.scanner import ejecutar_escaneo_sast
from skoll.utils import escanear_directorio, leer_archivo

app = FastAPI(title="Skoll Web")

from skoll.web_v2 import register_v2_routes
register_v2_routes(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PROYECTO_DIR = Path(__file__).resolve().parent
STATIC_DIR = PROYECTO_DIR / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

chat_sessions: dict[str, dict] = {}
_gemini_api_key: str = ""
_groq_api_key: str = ""


def _resolve_provider(provider: str | None = None) -> str:
    p = (provider or os.getenv("AI_PROVIDER") or DEFAULT_PROVIDER).lower()
    return "groq" if p == "groq" else "gemini"


def _resolve_model(provider: str, model: str | None = None) -> str:
    if model:
        return model
    env_model = os.getenv("AI_MODEL")
    if env_model:
        return env_model
    return get_default_model(provider)


def get_client(provider: str = "gemini"):
    p = _resolve_provider(provider)
    if p == "groq":
        key = _groq_api_key or os.getenv("GROQ_API_KEY") or ""
        if not key:
            raise HTTPException(status_code=500, detail="API Key de Groq no configurada.")
        try:
            return crear_cliente(provider="groq", api_key=key)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al conectar con Groq: {str(e)}")
    else:
        key = _gemini_api_key or os.getenv("GEMINI_API_KEY") or ""
        if not key:
            raise HTTPException(status_code=500, detail="API Key de Gemini no configurada.")
        try:
            return crear_cliente(provider="gemini", api_key=key)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al conectar con Gemini: {str(e)}")


async def sse_stream(prompt: str, model: str, client):
    try:
        stream = await asyncio.get_event_loop().run_in_executor(
            None, lambda: client.analizar_codigo_stream(prompt, model=model)
        )
        for chunk in stream:
            text = chunk.text if hasattr(chunk, "text") else str(chunk)
            if text:
                yield f"data: {json.dumps({'type': 'chunk', 'content': text})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"


async def sse_stream_chat(chat_session, message: str):
    try:
        stream = await asyncio.get_event_loop().run_in_executor(
            None, lambda: chat_session.send_message_stream(message)
        )
        for chunk in stream:
            text = chunk.text if hasattr(chunk, "text") else str(chunk)
            if text:
                yield f"data: {json.dumps({'type': 'chunk', 'content': text})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"


# ── Frontend ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(content=(STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/api/status")
async def status():
    gemini_ok = bool(_gemini_api_key or os.getenv("GEMINI_API_KEY"))
    groq_ok = bool(_groq_api_key or os.getenv("GROQ_API_KEY"))
    return {
        "status": "ok",
        "api_key_configured": gemini_ok or groq_ok,
        "gemini_configured": gemini_ok,
        "groq_configured": groq_ok,
    }


@app.post("/api/configure-key")
async def configure_key(request: Request):
    global _gemini_api_key, _groq_api_key
    body = await request.json()
    provider = (body.get("provider", "") or "gemini").lower()
    key = body.get("api_key", "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="API Key vacía.")
    if provider == "groq":
        _groq_api_key = key
    else:
        _gemini_api_key = key
    return {"status": "ok", "message": f"API Key de {provider.capitalize()} configurada correctamente."}


# ── Analyze: File Upload ──────────────────────────────────────────────────

@app.post("/api/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    model: str = Form(None),
    provider: str = Form(None),
):
    p = _resolve_provider(provider)
    m = _resolve_model(p, model)
    client = get_client(p)
    content = await file.read()
    try:
        code = content.decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(status_code=400, detail="No se pudo leer el archivo como texto.")
    prompt = ANALYSIS_TEMPLATE_PROMPT.format(code_content=code)
    return StreamingResponse(sse_stream(prompt, m, client), media_type="text/event-stream")


# ── Analyze: Local Path ───────────────────────────────────────────────────

@app.post("/api/analyze/path")
async def analyze_path(request: Request):
    body = await request.json()
    ruta = body.get("path", "").strip()
    p = _resolve_provider(body.get("provider"))
    m = _resolve_model(p, body.get("model"))
    if not os.path.exists(ruta):
        raise HTTPException(status_code=400, detail=f"La ruta '{ruta}' no existe.")
    client = get_client(p)
    if os.path.isdir(ruta):
        codigo = escanear_directorio(ruta)
    else:
        codigo = leer_archivo(ruta)
    if not codigo or codigo.strip() == "":
        raise HTTPException(status_code=400, detail="No se pudo extraer código de la ruta especificada.")
    prompt = ANALYSIS_TEMPLATE_PROMPT.format(code_content=codigo)
    return StreamingResponse(sse_stream(prompt, m, client), media_type="text/event-stream")


# ── Analyze: URL ──────────────────────────────────────────────────────────

@app.post("/api/analyze/url")
async def analyze_url(request: Request):
    body = await request.json()
    url = body.get("url", "").strip()
    p = _resolve_provider(body.get("provider"))
    m = _resolve_model(p, body.get("model"))
    if not url:
        raise HTTPException(status_code=400, detail="URL vacía.")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="La URL debe comenzar con http:// o https://")
    try:
        import requests
        from bs4 import BeautifulSoup
        client = get_client(p)
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text(separator='\n')[:15000]
        prompt = (
            "Analiza el contenido de esta página web en busca de vulnerabilidades, "
            "malas prácticas de seguridad, exposición de información sensible, etc. "
            "Genera un reporte estructurado según metodología RAPTOR (Etapas A-D) en ESPAÑOL:\n\n"
            f"{text_content}"
        )
        return StreamingResponse(sse_stream(prompt, m, client), media_type="text/event-stream")
    except ImportError:
        raise HTTPException(status_code=500, detail="Dependencias 'requests' y 'beautifulsoup4' requeridas para análisis de URL.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── SAST Scan ─────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def scan_sast(request: Request):
    body = await request.json()
    ruta = body.get("path", "").strip()
    tool = body.get("tool", "all")
    p = _resolve_provider(body.get("provider"))
    m = _resolve_model(p, body.get("model"))
    if not os.path.exists(ruta):
        raise HTTPException(status_code=400, detail=f"La ruta '{ruta}' no existe.")
    reportes_sast = ejecutar_escaneo_sast(ruta, tool=tool)
    sast_resumen = ""
    for clave, salida in reportes_sast.items():
        sast_resumen += f"=== REPORTE DE {clave.upper()} ===\n{salida}\n\n"
    client = get_client(p)
    prompt = (
        "Interpreta la salida de las siguientes herramientas SAST locales sobre el código del proyecto.\n"
        "Identifica los fallos reales de los falsos positivos y genera un reporte en ESPAÑOL "
        "estructurado según la metodología RAPTOR (Etapas A-D):\n\n"
        f"{sast_resumen}"
    )
    return StreamingResponse(sse_stream(prompt, m, client), media_type="text/event-stream")


# ── Chat ──────────────────────────────────────────────────────────────────

@app.post("/api/chat/start")
async def chat_start(request: Request):
    body = await request.json()
    p = _resolve_provider(body.get("provider"))
    m = _resolve_model(p, body.get("model"))
    client = get_client(p)
    session_id = str(uuid.uuid4())
    try:
        chat = client.iniciar_chat(model=m)
        chat_sessions[session_id] = {"chat": chat, "client": client, "provider": p}
        return {"session_id": session_id, "model": m, "provider": p}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"No se pudo iniciar el chat: {str(e)}")


@app.post("/api/chat/message")
async def chat_message(request: Request):
    body = await request.json()
    session_id = body.get("session_id", "")
    message = body.get("message", "").strip()
    if not session_id or session_id not in chat_sessions:
        raise HTTPException(status_code=400, detail="Sesión de chat no válida o expirada.")
    if not message:
        raise HTTPException(status_code=400, detail="Mensaje vacío.")
    chat = chat_sessions[session_id]["chat"]
    return StreamingResponse(sse_stream_chat(chat, message), media_type="text/event-stream")





if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
