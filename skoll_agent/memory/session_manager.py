from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skoll_agent.memory.state import AgentState
from skoll_agent.memory.task_queue import TaskQueue


def _sessions_dir() -> str:
    return os.environ.get("SKOLL_SESSIONS_DIR") or os.path.expanduser("~/.skoll/sessions")


class SessionManager:
    def __init__(self, sessions_dir: str | None = None):
        self.sessions_dir = sessions_dir or _sessions_dir()
        os.makedirs(self.sessions_dir, exist_ok=True)

    def _path(self, session_id: str) -> str:
        return os.path.join(self.sessions_dir, f"{session_id}.json")

    def _list_meta(self) -> list[dict[str, Any]]:
        meta_path = os.path.join(self.sessions_dir, "_index.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save_meta(self, entries: list[dict[str, Any]]) -> None:
        meta_path = os.path.join(self.sessions_dir, "_index.json")
        with open(meta_path, "w") as f:
            json.dump(entries, f, indent=2)

    def list_sessions(self) -> list[dict[str, Any]]:
        return self._list_meta()

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        path = self._path(session_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def save(self, agent_state: AgentState, task_queue: TaskQueue | None = None,
             session_id: str | None = None, name: str = "", target: str = "",
             phase: str = "") -> str:
        sid = session_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Load existing session if updating
        existing = self.get_session(sid) or {}

        session = {
            "session_id": sid,
            "created_at": existing.get("created_at", now),
            "updated_at": now,
            "name": name or existing.get("name", ""),
            "target": target or existing.get("target", agent_state.project_path),
            "phase": phase or existing.get("phase", "recon"),
            "state": agent_state.save_dict(),
            "tasks": task_queue.to_dict_list() if task_queue else [],
        }

        with open(self._path(sid), "w") as f:
            json.dump(session, f, indent=2)

        # Update index
        meta = self._list_meta()
        found = False
        for entry in meta:
            if entry["session_id"] == sid:
                entry["updated_at"] = now
                entry["phase"] = phase
                entry["name"] = name or entry["name"]
                entry["iteration"] = agent_state.iteration
                entry["findings"] = len(agent_state.findings)
                found = True
                break

        if not found:
            meta.append({
                "session_id": sid,
                "created_at": existing.get("created_at", now),
                "updated_at": now,
                "name": name or target or sid[:8],
                "target": target or agent_state.project_path,
                "phase": phase,
                "iteration": agent_state.iteration,
                "findings": len(agent_state.findings),
                "completed": agent_state.completed,
            })

        self._save_meta(meta)
        return sid

    def load(self, session_id: str) -> tuple[AgentState, TaskQueue] | None:
        data = self.get_session(session_id)
        if not data:
            return None
        agent_state = AgentState.load_dict(data["state"])
        task_queue = TaskQueue.from_dict_list(data.get("tasks", []))
        return agent_state, task_queue

    def delete(self, session_id: str) -> bool:
        path = self._path(session_id)
        if os.path.exists(path):
            os.remove(path)
        meta = [e for e in self._list_meta() if e["session_id"] != session_id]
        self._save_meta(meta)
        return True
