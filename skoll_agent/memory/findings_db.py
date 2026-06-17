from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from skoll_agent.memory.state import Finding, FindingStatus, Severity


class FindingsDB:
    def __init__(self, storage_path: str = "./findings_db.json"):
        self.storage_path = storage_path
        self._findings: dict[str, Finding] = {}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path) as f:
                    data = json.load(f)
                for item in data:
                    f_id = item["id"]
                    item["severity"] = Severity(item["severity"])
                    item["status"] = FindingStatus(item["status"])
                    self._findings[f_id] = Finding(**item)
            except (json.JSONDecodeError, KeyError):
                self._findings = {}

    def _save(self) -> None:
        data = []
        for f in self._findings.values():
            d = {
                "id": f.id,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "tool": f.tool,
                "rule_id": f.rule_id,
                "status": f.status.value,
                "remediation": f.remediation,
                "patched": f.patched,
                "created_at": f.created_at,
                "metadata": f.metadata,
            }
            data.append(d)
        os.makedirs(os.path.dirname(self.storage_path) or ".", exist_ok=True)
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2)

    def add(self, finding: Finding) -> None:
        self._findings[finding.id] = finding
        self._save()

    def add_many(self, findings: list[Finding]) -> None:
        for f in findings:
            self._findings[f.id] = f
        self._save()

    def get(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def get_all(self) -> list[Finding]:
        return list(self._findings.values())

    def get_by_file(self, file_path: str) -> list[Finding]:
        return [f for f in self._findings.values() if f.file_path == file_path]

    def get_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self._findings.values() if f.severity == severity]

    def get_open(self) -> list[Finding]:
        return [f for f in self._findings.values() if f.status == FindingStatus.OPEN]

    def update_status(self, finding_id: str, status: FindingStatus) -> None:
        if finding_id in self._findings:
            self._findings[finding_id].status = status
            self._save()

    def update_remediation(self, finding_id: str, remediation: str) -> None:
        if finding_id in self._findings:
            self._findings[finding_id].remediation = remediation
            self._save()

    def mark_patched(self, finding_id: str) -> None:
        if finding_id in self._findings:
            self._findings[finding_id].patched = True
            self._findings[finding_id].status = FindingStatus.PATCHED
            self._save()

    def stats(self) -> dict[str, Any]:
        all_f = self._findings.values()
        return {
            "total": len(all_f),
            "open": sum(1 for f in all_f if f.status == FindingStatus.OPEN),
            "patched": sum(1 for f in all_f if f.status == FindingStatus.PATCHED),
            "false_positive": sum(1 for f in all_f if f.status == FindingStatus.FALSE_POSITIVE),
            "critical": sum(1 for f in all_f if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in all_f if f.severity == Severity.HIGH),
            "medium": sum(1 for f in all_f if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in all_f if f.severity == Severity.LOW),
        }

    def clear(self) -> None:
        self._findings.clear()
        if os.path.exists(self.storage_path):
            os.remove(self.storage_path)
