from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any

from core.logging import LogLevel, ProgressEvent, get_logger

logger = get_logger()


class ProgressEmitter:
    """Sistema de eventos de progreso para la web UI.

    Acumula eventos y los pone a disposición como SSE.
    """

    def __init__(self) -> None:
        self._queues: dict[str, queue.Queue] = {}
        self._lock = threading.Lock()
        self._history: list[dict[str, Any]] = []

    def _on_event(self, event: ProgressEvent) -> None:
        d = event.to_dict()
        self._history.append(d)
        # Mantener máximo 1000 eventos en historial
        if len(self._history) > 1000:
            self._history = self._history[-500:]
        with self._lock:
            for q in self._queues.values():
                try:
                    q.put_nowait(d)
                except queue.Full:
                    pass

    def listen(self) -> str:
        session_id = f"evt_{int(time.time() * 1000)}_{threading.get_ident()}"
        with self._lock:
            self._queues[session_id] = queue.Queue(maxsize=500)
        return session_id

    def get_events(self, session_id: str, timeout: float = 1.0) -> list[dict[str, Any]]:
        q = self._queues.get(session_id)
        if not q:
            return []
        events: list[dict[str, Any]] = []
        try:
            while True:
                ev = q.get(timeout=timeout)
                events.append(ev)
                if q.empty():
                    break
        except queue.Empty:
            pass
        return events

    def close(self, session_id: str) -> None:
        self._queues.pop(session_id, None)

    def sse_generator(self, session_id: str):
        """Generador de eventos SSE para FastAPI/Starlette."""
        while True:
            events = self.get_events(session_id, timeout=2.0)
            if events:
                for ev in events:
                    yield f"data: {json.dumps(ev)}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    @property
    def history(self) -> list[dict[str, Any]]:
        return list(self._history)


_emitter: ProgressEmitter | None = None


def get_emitter() -> ProgressEmitter:
    global _emitter
    if _emitter is None:
        _emitter = ProgressEmitter()
        get_logger().on_event(_emitter._on_event)
    return _emitter
