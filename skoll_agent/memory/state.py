from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingStatus(Enum):
    OPEN = "open"
    VERIFIED = "verified"
    PATCHED = "patched"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    id: str
    file_path: str
    line_start: int
    line_end: int
    severity: Severity
    title: str
    description: str
    tool: str
    rule_id: str = ""
    status: FindingStatus = FindingStatus.OPEN
    remediation: str = ""
    patched: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        d["status"] = FindingStatus(d["status"])
        return cls(**d)


@dataclass
class ActionLog:
    iteration: int
    action: str
    params: dict[str, Any]
    reasoning: str
    result: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AgentState:
    project_path: str = ""
    iteration: int = 0
    max_iterations: int = 15
    max_depth: int = 3
    findings: list[Finding] = field(default_factory=list)
    action_log: list[ActionLog] = field(default_factory=list)
    scanned_files: set[str] = field(default_factory=set)
    current_depth: int = 0
    completed: bool = False
    summary: str = ""

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def log_action(self, entry: ActionLog) -> None:
        self.action_log.append(entry)

    def mark_scanned(self, file_path: str) -> None:
        self.scanned_files.add(file_path)

    def is_complete(self) -> bool:
        return self.completed or self.iteration >= self.max_iterations or self.current_depth >= self.max_depth

    def get_open_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.OPEN]

    def get_critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "findings_count": len(self.findings),
            "open_findings": len(self.get_open_findings()),
            "critical_findings": len(self.get_critical_findings()),
            "scanned_files": len(self.scanned_files),
            "completed": self.completed,
            "action_log": [asdict(a) for a in self.action_log[-5:]],
        }

    def exploits_generated(self) -> bool:
        return any("exploit" in a.action.lower() or "simulate" in a.action.lower() for a in self.action_log)

    def save_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "max_depth": self.max_depth,
            "findings": [f.to_dict() for f in self.findings],
            "action_log": [asdict(a) for a in self.action_log],
            "scanned_files": list(self.scanned_files),
            "current_depth": self.current_depth,
            "completed": self.completed,
            "summary": self.summary,
        }

    @classmethod
    def load_dict(cls, d: dict[str, Any]) -> "AgentState":
        state = cls(
            project_path=d.get("project_path", ""),
            iteration=d.get("iteration", 0),
            max_iterations=d.get("max_iterations", 15),
            max_depth=d.get("max_depth", 3),
            current_depth=d.get("current_depth", 0),
            completed=d.get("completed", False),
            summary=d.get("summary", ""),
        )
        for f in d.get("findings", []):
            state.findings.append(Finding.from_dict(f))
        for a in d.get("action_log", []):
            state.action_log.append(ActionLog(**a))
        state.scanned_files = set(d.get("scanned_files", []))
        return state

    def summary_text(self) -> str:
        has_exploits = self.exploits_generated()
        lines = [
            f"Iteración: {self.iteration}/{self.max_iterations}",
            f"Profundidad: {self.current_depth}/{self.max_depth}",
            f"Archivos escaneados: {len(self.scanned_files)}",
            f"Hallazgos totales: {len(self.findings)}",
            f"  - Críticos/Altos: {len(self.get_critical_findings())}",
            f"  - Abiertos: {len(self.get_open_findings())}",
        ]
        # Include recent findings (last 8) with port/service details
        if self.findings:
            lines.append("Últimos hallazgos:")
            for f in self.findings[-8:]:
                lines.append(f"  [{f.severity.value}] {f.title} — {f.description[:100]}")
        lines.append(f"Exploits generados: {'✅' if has_exploits else '❌ Pendiente'}")
        return "\n".join(lines)
