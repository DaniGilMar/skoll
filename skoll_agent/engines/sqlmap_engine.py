from __future__ import annotations

import subprocess
import re
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class SqlmapEngine(BaseEngine):
    name = "sqlmap"
    description = "SQL injection automation tool. Detecta y explota inyecciones SQL automáticamente."
    capabilities = ["sqli_detection", "database_exploit", "web_exploit"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        args = ["sqlmap", "-u", target, "--batch", "--random-agent", "--output-dir=/tmp/sqlmap"]
        if kwargs.get("data"):
            args.extend(["--data", kwargs["data"]])
        if kwargs.get("cookie"):
            args.extend(["--cookie", kwargs["cookie"]])
        if kwargs.get("level"):
            args.extend(["--level", str(kwargs["level"])])
        if kwargs.get("risk"):
            args.extend(["--risk", str(kwargs["risk"])])
        if kwargs.get("forms"):
            args.append("--forms")
        elif kwargs.get("dbs", True):
            args.append("--dbs")

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=kwargs.get("timeout", 120))
            raw = result.stdout + result.stderr
            if not raw.strip():
                return EngineResult(success=True, raw_output="", summary="sqlmap: no injection found")
            findings = self.parse_output(raw)
            return EngineResult(
                success=True, raw_output=raw, findings=findings,
                summary=f"sqlmap: {len(findings)} findings on {target}",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary="sqlmap: timeout", error="Timeout (300s)")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="sqlmap: not installed", error="Install sqlmap")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"sqlmap: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        lines = raw_output.split("\n")
        for i, line in enumerate(lines):
            line = line.strip()
            if re.search(r"is vulnerable|injectable|parameter.*(GET|POST).*seems", line, re.IGNORECASE):
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "critical",
                    "title": "SQL Injection detected",
                    "description": line[:300],
                    "tool": self.name,
                    "rule_id": "sqli-vulnerable",
                })
            elif re.search(r"available databases|Database:", line, re.IGNORECASE):
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": "Database enumeration",
                    "description": line[:300],
                    "tool": self.name,
                    "rule_id": "sqli-dbs",
                })
            elif re.search(r"current user:|user.*@", line, re.IGNORECASE):
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"DB user: {line[:60]}",
                    "description": line[:300],
                    "tool": self.name,
                    "rule_id": "sqli-user",
                })
            elif re.search(r"table|dump|entries", line, re.IGNORECASE) and re.search(r"\d+", line):
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Data extracted: {line[:80]}",
                    "description": line[:300],
                    "tool": self.name,
                    "rule_id": "sqli-data",
                })
        return findings
