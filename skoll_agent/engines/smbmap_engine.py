from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class SmbmapEngine(BaseEngine):
    name = "smbmap"
    description = "SMB enumeration: shares, permisos, recursive listing."
    capabilities = ["smb_enum", "share_discovery"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        user = kwargs.get("user", "")
        passwd = kwargs.get("password", "")
        timeout_s = int(kwargs.get("timeout", 60))
        args = [
            "smbmap", "-H", target, "-u", user, "-p", passwd,
            "--depth", "3", "--no-color",
        ]

        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout_s,
            )
            raw = result.stdout + result.stderr
            findings: list[dict[str, Any]] = []

            if "0 hosts serving SMB" in raw:
                findings.append({
                    "file_path": target, "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "SMB not reachable on target",
                    "description": "smbmap detected 0 hosts serving SMB",
                    "tool": self.name,
                    "rule_id": "smbmap-no-hosts",
                })
                summary = "smbmap: no SMB hosts reachable"
                return EngineResult(success=True, raw_output=raw, findings=findings, summary=summary)

            if "READ" in raw or "WRITE" in raw:
                for line in raw.splitlines():
                    m = re.search(
                        r"^\s*(Disk|IPC|Printer|ADMIN|C\$|IPC\$|print\$)\s+(READ(?:\s+ONLY)?|WRITE)\s*$",
                        line, re.IGNORECASE,
                    )
                    if m:
                        share = m.group(1)
                        perm = m.group(2).strip().upper()
                        findings.append({
                            "file_path": f"//{share}", "line_start": 0, "line_end": 0,
                            "severity": "critical" if "WRITE" in perm else "high",
                            "title": f"SMB share: {share} ({perm})",
                            "description": f"Share {share} accessible as {user} — {perm}",
                            "tool": self.name,
                            "rule_id": f"smbmap-{share}",
                            "share": share, "permission": perm,
                        })
                    else:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            perm_part = parts[-1].upper()
                            if perm_part in ("READ", "WRITE", "READ ONLY"):
                                share_name = parts[0].strip()
                                findings.append({
                                    "file_path": f"//{share_name}",
                                    "line_start": 0, "line_end": 0,
                                    "severity": "critical" if "WRITE" in perm_part else "high",
                                    "title": f"SMB share: {share_name} ({perm_part})",
                                    "description": f"Share accessible as {user} — {perm_part}",
                                    "tool": self.name,
                                    "rule_id": f"smbmap-{share_name}",
                                    "share": share_name, "permission": perm_part,
                                })

            summary = f"smbmap: {len(findings)} shares on {target}"
            return EngineResult(
                success=len(findings) > 0, raw_output=raw,
                findings=findings, summary=summary,
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary=f"smbmap: timeout {target}", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="smbmap: not installed", error="Install smbmap")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"smbmap: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
