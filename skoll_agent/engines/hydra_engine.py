from __future__ import annotations

import subprocess
import re
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class HydraEngine(BaseEngine):
    name = "hydra"
    description = "Password brute-forcer. Ataca servicios como SSH, HTTP, FTP, SMB, MySQL, etc."
    capabilities = ["bruteforce", "password_attack", "auth_bypass"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        service = kwargs.get("service", "ssh")
        userlist = kwargs.get("userlist", "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt")
        passlist = kwargs.get("passlist", "/usr/share/wordlists/fasttrack.txt")
        port = kwargs.get("port", "")

        args = ["hydra", "-L", userlist, "-P", passlist, target]
        if port:
            args.extend(["-s", str(port)])
        args.append(service)

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=kwargs.get("timeout", 300))
            raw = result.stdout + result.stderr
            if not raw.strip():
                return EngineResult(success=True, raw_output="", summary="hydra: no credentials found")
            findings = self.parse_output(raw)
            return EngineResult(
                success=True, raw_output=raw, findings=findings,
                summary=f"hydra: {len(findings)} credentials found on {target}",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary="hydra: timeout", error="Timeout (300s)")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="hydra: not installed", error="Install hydra")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"hydra: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.split("\n"):
            line = line.strip()
            m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line, re.IGNORECASE)
            if m:
                username, password = m.group(1), m.group(2)
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "critical",
                    "title": f"Credentials found: {username}:{password}",
                    "description": f"Valid credentials discovered: {username} / {password}",
                    "tool": self.name,
                    "rule_id": "hydra-creds",
                    "username": username,
                    "password": password,
                })
            elif re.search(r"(\d+)\s+valid\s+password", line, re.IGNORECASE):
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Hydra result: {line[:80]}",
                    "description": line[:300],
                    "tool": self.name,
                    "rule_id": "hydra-summary",
                })
        return findings
