from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class Enum4linuxEngine(BaseEngine):
    name = "enum4linux"
    description = "Enumeración SMB/SAMBA completa: usuarios, grupos, shares, política de passwords, OS info."
    capabilities = ["smb_enum", "user_enum", "share_enum", "os_detection"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout_s = int(kwargs.get("timeout", 120))
        args = ["enum4linux", "-a", target]

        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout_s,
            )
            raw = result.stdout + result.stderr
            findings = []
            sections = {
                "users": [],
                "shares": [],
                "os": [],
                "policy": [],
                "groups": [],
            }

            current_section = None
            for line in raw.splitlines():
                lower = line.lower()
                if "user:" in lower and "rid:" in lower:
                    m = re.search(r"user:\s*(\S+)", line, re.IGNORECASE)
                    if m:
                        sections["users"].append(m.group(1))
                        findings.append({
                            "file_path": "", "line_start": 0, "line_end": 0,
                            "severity": "high",
                            "title": f"SMB user: {m.group(1)}",
                            "description": line.strip()[:200],
                            "tool": self.name,
                            "rule_id": f"enum4linux-user-{m.group(1)}",
                        })
                elif "disk" in lower or "share" in lower:
                    if "|" in line or "\\" in line:
                        parts = re.split(r"\s{2,}|\|", line)
                        for p in parts:
                            p = p.strip()
                            if p and p not in ("Sharename", "Type", "Comment", "", "-"):
                                sections["shares"].append(p)
                                findings.append({
                                    "file_path": f"//{p}", "line_start": 0, "line_end": 0,
                                    "severity": "medium",
                                    "title": f"SMB share: {p}",
                                    "description": p,
                                    "tool": self.name,
                                    "rule_id": f"enum4linux-share-{p}",
                                })
                elif "os:" in lower or "os version" in lower or "server" in lower:
                    m = re.search(r"(os|server|version)[:\s]+(\S.+)", line, re.IGNORECASE)
                    if m:
                        sections["os"].append(m.group(2).strip())
                        findings.append({
                            "file_path": "", "line_start": 0, "line_end": 0,
                            "severity": "info",
                            "title": f"SMB OS: {m.group(2).strip()}",
                            "description": line.strip()[:200],
                            "tool": self.name,
                            "rule_id": "enum4linux-os",
                        })
                elif "password" in lower or "policy" in lower:
                    sections["policy"].append(line.strip())
                    if "min" in lower and "length" in lower:
                        findings.append({
                            "file_path": "", "line_start": 0, "line_end": 0,
                            "severity": "low",
                            "title": f"SMB policy: {line.strip()}",
                            "description": line.strip(),
                            "tool": self.name,
                            "rule_id": "enum4linux-policy",
                        })
                elif "group:" in lower and "rid:" in lower:
                    m = re.search(r"group:\s*(\S+)", line, re.IGNORECASE)
                    if m:
                        sections["groups"].append(m.group(1))

            summary = (
                f"enum4linux: {len(sections['users'])} users, "
                f"{len(sections['shares'])} shares, {len(sections['groups'])} groups"
            )
            return EngineResult(
                success=len(findings) > 0, raw_output=raw,
                findings=findings, summary=summary, error="",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary=f"enum4linux: timeout {target}", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="enum4linux: not installed", error="Install enum4linux")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"enum4linux: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
