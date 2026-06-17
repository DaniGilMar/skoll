from __future__ import annotations

import json
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class SemgrepEngine(BaseEngine):
    name = "semgrep"
    description = "Semgrep SAST scanner with auto rules"
    capabilities = ["sast", "multi_language", "code_scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        try:
            process = subprocess.run(
                ["semgrep", "scan", "--config", "auto", target, "--json", "--quiet"],
                capture_output=True, text=True, timeout=kwargs.get("timeout", 120),
            )
            raw = process.stdout.strip()
            if not raw:
                return EngineResult(success=True, raw_output="No findings", summary="Semgrep: clean")

            findings = self.parse_output(raw)
            return EngineResult(
                success=True,
                raw_output=raw,
                findings=findings,
                summary=f"Semgrep: {len(findings)} findings",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary="Semgrep: timeout", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="Semgrep: not installed", error="Semgrep not found")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"Semgrep: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw_output)
            findings = []
            for result in data.get("results", []):
                findings.append({
                    "file_path": result.get("path", ""),
                    "line_start": result.get("start", {}).get("line", 0),
                    "line_end": result.get("end", {}).get("line", 0),
                    "severity": result.get("extra", {}).get("severity", "medium").lower(),
                    "title": result.get("check_id", "Unknown").split(".")[-1],
                    "description": result.get("extra", {}).get("message", ""),
                    "rule_id": result.get("check_id", ""),
                    "tool": self.name,
                })
            return findings
        except (json.JSONDecodeError, KeyError):
            return []
