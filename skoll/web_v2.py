"""Web UI endpoints para la nueva arquitectura Renacer — v2 simplificada."""

from __future__ import annotations

import json
import queue
import threading
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from skoll_agent.brain.reasoning_loop import ReasoningLoop
from skoll_agent.config.agent_config import CONFIG
from skoll.client import crear_cliente

router = APIRouter(prefix="/api/v2")

_v2_queues: dict[str, queue.Queue] = {}
_v2_results: dict[str, dict[str, Any]] = {}


def _make_emitter(q: queue.Queue):
    def emit(event_type: str, data: dict[str, Any]) -> None:
        q.put({"type": event_type, "data": data})
    return emit


@router.post("/start")
async def v2_start(request: Request):
    body = await request.json()
    target = body.get("target", "").strip()
    tier = body.get("tier", "agent")
    campaign_id = body.get("campaign_id", f"scan_{int(time.time())}")

    if not target:
        raise HTTPException(status_code=400, detail="El campo 'target' está vacío.")

    session_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()
    _v2_queues[session_id] = q
    emit = _make_emitter(q)

    def run():
        try:
            is_net = "." in target or "://" in target or "localhost" in target
            client = crear_cliente()
            loop = ReasoningLoop(
                client, target,
                event_callback=emit,
                is_network_target=is_net,
            )
            result = loop.run()
            emit("agent_complete", {"reasoning": "Pipeline completado"})
            _v2_results[session_id] = result
        except Exception as e:
            import traceback
            emit("agent_error", {"message": f"{type(e).__name__}: {e}"})
            emit("agent_complete", {"result": "error"})

    t = threading.Thread(target=run, daemon=True)
    t.start()

    return {
        "session_id": session_id,
        "status": "started",
        "target": target,
        "tier": tier,
    }


@router.get("/stream/{session_id}")
async def v2_stream(session_id: str):
    if session_id not in _v2_queues:
        raise HTTPException(status_code=404, detail="Sesión no encontrada o ya finalizada.")

    q = _v2_queues[session_id]

    def generate():
        try:
            while True:
                try:
                    evt = q.get(timeout=3)
                    yield f"data: {json.dumps(evt)}\n\n"
                    if evt.get("type") in ("agent_complete", "agent_error"):
                        break
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        except GeneratorExit:
            pass
        finally:
            _v2_queues.pop(session_id, None)

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.get("/result/{session_id}")
async def v2_result(session_id: str):
    result = _v2_results.get(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Resultado no disponible.")
    return result


def register_v2_routes(app):
    app.include_router(router)
