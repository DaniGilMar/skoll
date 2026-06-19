from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class NiktoEngine(BaseEngine):
    name = "nikto"
    description = "Web vulnerability scanner. Detecta configuraciones inseguras, archivos peligrosos y vulnerabilidades web."
    capabilities = ["web_vuln_scan", "web_security", "cgi_scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout = kwargs.get("timeout", 60)
        args = [
            "nikto", "-h", target,
            "-C", "all",
            "-Tuning", "1234589abcde",
            "-maxtime", "15m",
            "-o", "nikto_thm.txt",
            "-Format", "txt",
            "-nointeractive", "-nocheck",
        ]
        if kwargs.get("ssl"):
            args.append("-ssl")
        if kwargs.get("port"):
            args.extend(["-p", str(kwargs["port"])])

        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout,
            )
            full = result.stdout + result.stderr
            if not full.strip():
                full = "nikto: no output"
            findings = self.parse_output(full) if full.strip() else []
            return EngineResult(
                success=True, raw_output=full, findings=findings,
                summary=f"nikto: {len(findings)} issues on {target}",
                error="",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                success=False, raw_output="",
                summary=f"nikto: timeout ({timeout}s) on {target}",
                error=f"Timeout ({timeout}s)",
            )
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="nikto: not installed", error="Install nikto")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"nikto: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        _meta_keys = {"target ip", "target hostname", "target port", "start time", "platform"}
        for line in raw_output.split("\n"):
            line = line.strip()
            m = re.match(r"^\+ (.*?):\s*(.*)", line)
            if m:
                vuln_type = m.group(1).strip().lower()
                detail = m.group(2).strip()
                if vuln_type in _meta_keys:
                    continue
                sev = "high" if any(w in vuln_type for w in ["error", "critical", "vulnerable", "xss", "sqli", "rce", "exec"]) else "medium"
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": sev,
                    "title": f"nikto: {m.group(1).strip()}",
                    "description": detail,
                    "tool": self.name,
                    "rule_id": f"nikto-{m.group(1).strip()[:30]}",
                })
            elif line.startswith("/") and "?" in line:
                findings.append({
                    "file_path": line.split()[0] if line.split() else line,
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"Potentially interesting file: {line[:60]}",
                    "description": line[:200],
                    "tool": self.name,
                    "rule_id": "nikto-interesting-file",
                })
        return findings
