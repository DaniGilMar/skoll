from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Target:
    """Representa un objetivo de análisis."""
    raw: str
    ip: str = ""
    hostname: str = ""
    port: int = 0
    protocol: str = "tcp"
    is_url: bool = False
    is_ip: bool = False

    @classmethod
    def parse(cls, raw: str) -> Target:
        from urllib.parse import urlparse
        import re

        raw = raw.strip()
        t = cls(raw=raw)

        # Es URL?
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            t.hostname = parsed.hostname or ""
            t.port = parsed.port or (443 if parsed.scheme == "https" else 80)
            t.protocol = parsed.scheme
            t.is_url = True
            return t

        # Es IP?
        ip_match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", raw)
        if ip_match:
            t.ip = raw.split("/")[0]
            t.is_ip = True
            return t

        # Es hostname?
        if "." in raw:
            t.hostname = raw
            return t

        t.ip = raw
        t.is_ip = True
        return t


@dataclass
class Observation:
    """Una observación cruda de una herramienta sobre un puerto/servicio."""
    port: int = 0
    service: str = ""
    protocol: str = "tcp"
    state: str = "open"
    flags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    """Evidencia cruda: lo que la herramienta observó, nunca se modifica."""
    campaign_id: str = ""
    host: str = ""
    tool: str = ""
    timestamp: float = 0.0
    observations: list[Observation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "tool": self.tool,
            "observations": [
                {
                    "port": o.port,
                    "service": o.service,
                    "protocol": o.protocol,
                    "state": o.state,
                    "flags": o.flags,
                    "raw": o.raw,
                }
                for o in self.observations
            ],
        }


@dataclass
class Finding:
    """Hallazgo determinista generado por reglas + evidencia."""
    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "low"
    host: str = ""
    port: int = 0
    service: str = ""
    mitre: str = ""
    cve_refs: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    recommendation: str = ""
    confidence: str = "deterministic"
    source: str = "rules_engine"
    first_seen: float = 0.0
    last_seen: float = 0.0
    count: int = 1

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}:{self.rule_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "mitre": self.mitre,
            "cve_refs": self.cve_refs,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class ScanRun:
    """Una ejecución del pipeline contra un objetivo."""
    campaign_id: str = ""
    target: str = ""
    tier: str = "fast"
    started_at: float = 0.0
    finished_at: float = 0.0
    status: str = "pending"
    findings_count: int = 0
    error: str = ""


@dataclass
class Campaign:
    """Campaña: agrupa múltiples escaneos contra uno o varios objetivos."""
    id: str = ""
    target_range: str = ""
    created_at: float = 0.0
    status: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_range": self.target_range,
            "created_at": self.created_at,
            "status": self.status,
        }
