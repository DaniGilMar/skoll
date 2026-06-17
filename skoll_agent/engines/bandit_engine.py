from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class BanditEngine(BaseEngine):
    name = "bandit"
    description = "Bandit SAST scanner for Python security issues"
    capabilities = ["sast", "python_security", "code_scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        try:
            process = subprocess.run(
                [sys.executable, "-m", "bandit", "-r", target, "-f", "json", "-q"],
                capture_output=True, text=True, timeout=kwargs.get("timeout", 60),
            )
            raw = process.stdout.strip()
            if not raw:
                return EngineResult(success=True, raw_output="No findings", summary="Bandit: clean")

            findings = self.parse_output(raw)
            return EngineResult(
                success=True,
                raw_output=raw,
                findings=findings,
                summary=f"Bandit: {len(findings)} findings",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary="Bandit: timeout", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="Bandit: not installed", error="Bandit not found")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"Bandit: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw_output)
            findings = []
            for result in data.get("results", []):
                findings.append({
                    "file_path": result.get("filename", ""),
                    "line_start": result.get("line_number", 0),
                    "line_end": result.get("line_number", 0),
                    "severity": result.get("issue_severity", "medium").lower(),
                    "title": result.get("test_name", "Unknown"),
                    "description": result.get("issue_text", ""),
                    "rule_id": result.get("test_id", ""),
                    "tool": self.name,
                })
            return findings
        except (json.JSONDecodeError, KeyError):
            return []
