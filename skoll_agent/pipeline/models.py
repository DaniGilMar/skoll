from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class PhaseId(Enum):
    RECON = "recon"
    ENUM = "enum"
    VALIDATE = "validate"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    CHAIN = "chain"
    REPORT = "report"
    COMPLETE = "complete"


class PhaseStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class PortInfo:
    port: int
    protocol: str
    service: str
    product: str = ""
    version: str = ""
    state: str = "open"
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class WebInfo:
    url: str
    title: str = ""
    tech: list[str] = field(default_factory=list)
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class FlagFinding:
    value: str
    source: str
    pattern: str
    context: str = ""


@dataclass
class PhaseResult:
    phase_id: PhaseId
    status: PhaseStatus = PhaseStatus.PENDING
    started_at: str = ""
    ended_at: str = ""
    summary: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    web: list[WebInfo] = field(default_factory=list)
    flags: list[FlagFinding] = field(default_factory=list)
    raw_outputs: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def start(self) -> None:
        self.status = PhaseStatus.RUNNING
        self.started_at = datetime.now(timezone.utc).isoformat()

    def complete(self, summary: str = "") -> None:
        self.status = PhaseStatus.COMPLETED
        self.ended_at = datetime.now(timezone.utc).isoformat()
        if summary:
            self.summary = summary

    def skip(self, reason: str = "") -> None:
        self.status = PhaseStatus.SKIPPED
        self.ended_at = datetime.now(timezone.utc).isoformat()
        self.summary = reason

    def fail(self, error: str) -> None:
        self.status = PhaseStatus.FAILED
        self.ended_at = datetime.now(timezone.utc).isoformat()
        self.error = error


@dataclass
class PipelineState:
    target: str
    is_network: bool = False
    current_phase: PhaseId = PhaseId.RECON
    phases: dict[str, PhaseResult] = field(default_factory=dict)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    all_flags: list[FlagFinding] = field(default_factory=list)
    completed: bool = False
    iteration: int = 0

    def get_phase(self, phase_id: PhaseId) -> PhaseResult:
        key = phase_id.value
        if key not in self.phases:
            self.phases[key] = PhaseResult(phase_id=phase_id)
        return self.phases[key]

    def all_ports(self) -> list[PortInfo]:
        ports: list[PortInfo] = []
        seen = set()
        for p in self.phases.values():
            for port in p.ports:
                key = (port.port, port.protocol)
                if key not in seen:
                    seen.add(key)
                    ports.append(port)
        return ports

    def open_ports(self) -> list[PortInfo]:
        return [p for p in self.all_ports() if p.state == "open"]

    def all_web(self) -> list[WebInfo]:
        web: list[WebInfo] = []
        seen = set()
        for p in self.phases.values():
            for w in p.web:
                if w.url not in seen:
                    seen.add(w.url)
                    web.append(w)
        return web

    def has_service(self, service: str) -> bool:
        return any(service in p.service.lower() for p in self.all_ports())

    def has_flag(self) -> bool:
        return len(self.all_flags) > 0
