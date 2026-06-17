from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from skoll_agent.memory.state import Finding, Severity


class SARIFBuilder:
    def __init__(self):
        self._doc: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "skoll-agent", "version": "0.1.0", "informationUri": "https://github.com/skoll/skoll"}},
                    "results": [],
                    "artifacts": [],
                }
            ],
        }
        self._artifact_index: dict[str, int] = {}

    def add_tool(self, name: str, version: str, uri: str = "") -> None:
        driver = self._doc["runs"][0]["tool"]["driver"]
        driver["name"] = name
        driver["version"] = version
        if uri:
            driver["informationUri"] = uri

    def _get_artifact_index(self, file_path: str) -> int:
        if file_path not in self._artifact_index:
            idx = len(self._artifact_index)
            self._artifact_index[file_path] = idx
            self._doc["runs"][0]["artifacts"].append({
                "location": {"uri": file_path},
                "length": -1,
            })
        return self._artifact_index[file_path]

    def add_result(self, finding: Finding) -> None:
        _severity_map: dict[Severity, str] = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }

        result: dict[str, Any] = {
            "ruleId": finding.rule_id or finding.title,
            "level": _severity_map.get(finding.severity, "warning"),
            "message": {"text": finding.description or finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path, "index": self._get_artifact_index(finding.file_path)},
                        "region": {
                            "startLine": finding.line_start,
                            "endLine": max(finding.line_end, finding.line_start),
                        },
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "tool": finding.tool,
                "status": finding.status.value,
                "finding_id": finding.id,
            },
        }

        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {"text": "Suggested remediation"},
                    "artifactChanges": [
                        {
                            "artifactLocation": {"uri": finding.file_path},
                            "replacements": [{"deletedRegion": {"startLine": finding.line_start}, "insertedContent": {"text": finding.remediation}}],
                        }
                    ],
                }
            ]

        self._doc["runs"][0]["results"].append(result)

    def build(self) -> dict[str, Any]:
        run = self._doc["runs"][0]
        run["results"] = sorted(run["results"], key=lambda r: r["properties"]["severity"])
        return self._doc
