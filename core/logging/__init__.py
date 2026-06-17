from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    FATAL = 4


class ProgressEvent:
    """Evento de progreso para la pipeline."""

    def __init__(
        self,
        phase: str,
        message: str,
        done: int = 0,
        total: int = 0,
        level: LogLevel = LogLevel.INFO,
    ):
        self.timestamp = time.time()
        self.phase = phase
        self.message = message
        self.done = done
        self.total = total
        self.level = level

    @property
    def pct(self) -> float:
        return (self.done / self.total * 100) if self.total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.timestamp,
            "phase": self.phase,
            "message": self.message,
            "done": self.done,
            "total": self.total,
            "pct": self.pct,
            "level": self.level.name.lower(),
        }


class Logger:
    """Logger estructurado con soporte de eventos en tiempo real."""

    def __init__(self, name: str = "skoll"):
        self.name = name
        self._listeners: list[callable] = []
        self._lock = threading.Lock()

    def on_event(self, listener: callable) -> None:
        with self._lock:
            self._listeners.append(listener)

    def _emit(self, event: ProgressEvent) -> None:
        with self._lock:
            for listener in self._listeners:
                try:
                    listener(event)
                except Exception:
                    pass

    def _print(self, event: ProgressEvent) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        icon = {
            LogLevel.DEBUG: "🔍",
            LogLevel.INFO: "  ",
            LogLevel.WARNING: "⚠️",
            LogLevel.ERROR: "❌",
            LogLevel.FATAL: "💀",
        }.get(event.level, "●")
        msg = f"{ts} {icon} [{event.phase}] {event.message}"
        if event.total > 0:
            msg += f" ({event.done}/{event.total})"
        print(msg, file=sys.stderr, flush=True)

    def debug(self, phase: str, message: str) -> None:
        e = ProgressEvent(phase, message, level=LogLevel.DEBUG)
        self._emit(e)

    def info(self, phase: str, message: str, done: int = 0, total: int = 0) -> None:
        e = ProgressEvent(phase, message, done=done, total=total, level=LogLevel.INFO)
        self._print(e)
        self._emit(e)

    def warn(self, phase: str, message: str) -> None:
        e = ProgressEvent(phase, message, level=LogLevel.WARNING)
        self._print(e)
        self._emit(e)

    def error(self, phase: str, message: str) -> None:
        e = ProgressEvent(phase, message, level=LogLevel.ERROR)
        self._print(e)
        self._emit(e)

    def progress(self, phase: str, done: int, total: int, message: str = "") -> None:
        e = ProgressEvent(phase, message or f"Progreso", done=done, total=total)
        self._print(e)
        self._emit(e)

    def fatal(self, phase: str, message: str) -> None:
        e = ProgressEvent(phase, message, level=LogLevel.FATAL)
        self._print(e)
        self._emit(e)
        raise SystemExit(1)


_root_logger: Logger | None = None
_lock = threading.Lock()


def get_logger(name: str = "skoll") -> Logger:
    global _root_logger
    if _root_logger is None:
        with _lock:
            if _root_logger is None:
                _root_logger = Logger(name)
    return _root_logger
