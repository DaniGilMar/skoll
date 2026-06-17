from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

EVIDENCE_DB = Path("/tmp/skoll_evidence.db")


class EvidenceStore:
    """Almacén inmutable de evidencia cruda observada por las herramientas.

    Cada registro es un hecho observable: "en el host X, la herramienta Y
    observó Z". Nunca se modifica. Si se necesita reprocesar con reglas
    diferentes, se lee desde aquí sin re-ejecutar la herramienta.
    """

    def __init__(self, db_path: str | Path = EVIDENCE_DB):
        self._path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    data TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_campaign
                ON evidence(campaign_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_host
                ON evidence(host)
            """)
            conn.commit()
            conn.close()

    def save(self, campaign_id: str, host: str, tool: str, data: dict[str, Any]) -> int:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute(
                "INSERT INTO evidence (campaign_id, host, tool, timestamp, data) VALUES (?, ?, ?, ?, ?)",
                (campaign_id, host, tool, time.time(), json.dumps(data, default=str)),
            )
            conn.commit()
            row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.close()
            return row_id

    def get_by_campaign(self, campaign_id: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            rows = conn.execute(
                "SELECT id, host, tool, timestamp, data FROM evidence WHERE campaign_id = ? ORDER BY timestamp",
                (campaign_id,),
            ).fetchall()
            conn.close()
            return [
                {
                    "id": r[0], "host": r[1], "tool": r[2],
                    "timestamp": r[3], "data": json.loads(r[4]),
                }
                for r in rows
            ]

    def get_by_host(self, campaign_id: str, host: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            rows = conn.execute(
                "SELECT id, host, tool, timestamp, data FROM evidence WHERE campaign_id = ? AND host = ? ORDER BY timestamp",
                (campaign_id, host),
            ).fetchall()
            conn.close()
            return [
                {
                    "id": r[0], "host": r[1], "tool": r[2],
                    "timestamp": r[3], "data": json.loads(r[4]),
                }
                for r in rows
            ]

    def get_by_tool(self, campaign_id: str, tool: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            rows = conn.execute(
                "SELECT id, host, tool, timestamp, data FROM evidence WHERE campaign_id = ? AND tool = ? ORDER BY timestamp",
                (campaign_id, tool),
            ).fetchall()
            conn.close()
            return [
                {
                    "id": r[0], "host": r[1], "tool": r[2],
                    "timestamp": r[3], "data": json.loads(r[4]),
                }
                for r in rows
            ]

    def count(self, campaign_id: str) -> int:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            count = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE campaign_id = ?", (campaign_id,)
            ).fetchone()[0]
            conn.close()
            return count

    def clear_campaign(self, campaign_id: str) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute("DELETE FROM evidence WHERE campaign_id = ?", (campaign_id,))
            conn.commit()
            conn.close()
