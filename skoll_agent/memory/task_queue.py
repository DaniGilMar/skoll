from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TaskPriority(Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(order=True)
class Task:
    priority: TaskPriority
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    skill: str = ""
    action: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    status: TaskStatus = TaskStatus.PENDING
    depends_on: list[str] = field(default_factory=list)
    result: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.priority, str):
            self.priority = TaskPriority[self.priority.upper()]
        if isinstance(self.status, str):
            self.status = TaskStatus[self.status.upper()]


class TaskQueue:
    def __init__(self):
        self._tasks: list[Task] = []

    def push(self, task: Task) -> None:
        self._tasks.append(task)
        self._tasks.sort()

    def pop(self) -> Task | None:
        ready = [t for t in self._tasks if t.status == TaskStatus.PENDING and not self._has_unmet_deps(t)]
        if not ready:
            return None
        self._tasks.remove(ready[0])
        ready[0].status = TaskStatus.RUNNING
        return ready[0]

    def peek(self) -> Task | None:
        ready = [t for t in self._tasks if t.status == TaskStatus.PENDING and not self._has_unmet_deps(t)]
        return ready[0] if ready else None

    def _has_unmet_deps(self, task: Task) -> bool:
        for dep_id in task.depends_on:
            dep = next((t for t in self._tasks if t.id == dep_id), None)
            if dep and dep.status != TaskStatus.COMPLETED:
                return True
        return False

    def complete(self, task_id: str, result: str = "") -> None:
        for t in self._tasks:
            if t.id == task_id:
                t.status = TaskStatus.COMPLETED
                t.result = result
                break

    def fail(self, task_id: str, result: str = "") -> None:
        for t in self._tasks:
            if t.id == task_id:
                t.status = TaskStatus.FAILED
                t.result = result
                break

    def cancel_all(self) -> None:
        for t in self._tasks:
            if t.status == TaskStatus.PENDING:
                t.status = TaskStatus.SKIPPED

    def pending_count(self) -> int:
        return sum(1 for t in self._tasks if t.status == TaskStatus.PENDING)

    def all_tasks(self) -> list[Task]:
        return list(self._tasks)

    def to_dict_list(self) -> list[dict[str, Any]]:
        result = []
        for t in self._tasks:
            d = asdict(t)
            d["priority"] = t.priority.name.lower()
            d["status"] = t.status.value
            result.append(d)
        return result

    @classmethod
    def from_dict_list(cls, items: list[dict[str, Any]]) -> "TaskQueue":
        q = cls()
        for item in items:
            t = Task(**item)
            q._tasks.append(t)
        q._tasks.sort()
        return q

    def summary(self) -> str:
        return (
            f"Tasks: {len(self._tasks)} total, "
            f"{self.pending_count()} pending, "
            f"{sum(1 for t in self._tasks if t.status == TaskStatus.COMPLETED)} completed, "
            f"{sum(1 for t in self._tasks if t.status == TaskStatus.FAILED)} failed"
        )
