from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from skoll_agent.utils.file_lock import FileLock

STATE_DIR = Path.home() / ".skoll" / "state"

PHASES = ["recon", "analyze", "exploit", "report"]

EMPTY_PHASE = {
    "status": "pending",
    "started": None,
    "completed": None,
    "duration": None,
    "summary": "",
    "findings_count": 0,
    "error": "",
}


def _hash_target(target: str) -> str:
    return hashlib.sha256(target.encode()).hexdigest()[:16]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    """Persist pipeline state per target + session.

    Layout under STATE_DIR/<hash>/<session_id>/:
      state.json       – phase status, timestamps, metrics (small, fast)
      findings.jsonl   – every finding as a JSON line (append-only)

    All writes are protected by fcntl.flock via FileLock.
    """

    def __init__(self, target: str, session_id: str = ""):
        self.target = target
        self._hash = _hash_target(target)
        subdir = session_id if session_id else "default"
        self._dir = STATE_DIR / self._hash / subdir
        self._state_path = self._dir / "state.json"
        self._findings_path = self._dir / "findings.jsonl"
        self._existing_keys: set[tuple[str, str, str]] = set()
        self._load_existing_keys()

    # ── public API ──────────────────────────────────────────────

    def exists(self) -> bool:
        return self._state_path.exists()

    def load(self) -> dict:
        with self._lock():
            if not self._state_path.exists():
                return self._new_state()
            with open(self._state_path) as f:
                return json.load(f)

    def save(self, state: dict) -> None:
        with self._lock():
            self._dir.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(state, f, indent=2, default=str)
            tmp.replace(self._state_path)

    def append_finding(self, finding: dict) -> None:
        with self._lock():
            self._dir.mkdir(parents=True, exist_ok=True)
            key = (str(finding.get("title", "")), str(finding.get("description", "")), str(finding.get("tool", "")))
            if key in self._existing_keys:
                return
            self._existing_keys.add(key)
            with open(self._findings_path, "a") as f:
                f.write(json.dumps(finding, default=str) + "\n")

    def read_findings(self) -> list[dict]:
        if not self._findings_path.exists():
            return []
        with self._lock():
            with open(self._findings_path) as f:
                return [json.loads(line) for line in f if line.strip()]

    # ── phase helpers ───────────────────────────────────────────

    def phase_status(self, phase: str) -> str:
        return self.load().get("phases", {}).get(phase, {}).get("status", "pending")

    def mark_started(self, phase: str) -> None:
        st = self.load()
        st["phases"][phase]["status"] = "running"
        st["phases"][phase]["started"] = _now()
        self.save(st)

    def mark_completed(self, phase: str, summary: str = "", findings_count: int = 0, error: str = "") -> None:
        st = self.load()
        p = st["phases"][phase]
        p["status"] = "failed" if error else "completed"
        p["completed"] = _now()
        if p["started"]:
            start = datetime.fromisoformat(p["started"])
            p["duration"] = int((datetime.now(timezone.utc) - start).total_seconds())
        p["summary"] = summary
        p["findings_count"] = findings_count
        p["error"] = error
        st["updated"] = _now()
        self._update_overall(st)
        self.save(st)

    def update_context(self, key: str, data: Any) -> None:
        st = self.load()
        st["context"][key] = data
        self.save(st)

    def resume_from(self) -> Optional[str]:
        """Return the name of the first pending phase, or None if every phase is done."""
        st = self.load()
        for name in PHASES:
            if st.get("phases", {}).get(name, {}).get("status") == "pending":
                return name
        return None

    # ── internals ──────────────────────────────────────────────

    def _load_existing_keys(self) -> None:
        if not self._findings_path.exists():
            return
        with self._lock():
            with open(self._findings_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        key = (str(finding.get("title", "")), str(finding.get("description", "")), str(finding.get("tool", "")))
                        self._existing_keys.add(key)
                    except Exception:
                        pass

    def _new_state(self) -> dict:
        return {
            "target": self.target,
            "created": _now(),
            "updated": _now(),
            "status": "pending",
            "phases": {p: dict(EMPTY_PHASE) for p in PHASES},
            "context": {"target_ip": "", "open_ports": [], "web_services": [], "credentials": [], "findings_count": 0},
        }

    def _lock(self) -> FileLock:
        return FileLock(self._state_path, timeout=60)

    def _update_overall(self, st: dict) -> None:
        statuses = [st["phases"][p]["status"] for p in PHASES]
        if all(s == "completed" for s in statuses):
            st["status"] = "completed"
        elif any(s == "failed" for s in statuses):
            st["status"] = "partial"
