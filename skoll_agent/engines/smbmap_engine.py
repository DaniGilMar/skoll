from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class SmbmapEngine(BaseEngine):
    name = "smbmap"
    description = "SMB enumeration completo: shares, permisos, recursive listing, descarga."
    capabilities = ["smb_enum", "share_discovery", "recursive_list"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        user = kwargs.get("user", "guest")
        passwd = kwargs.get("password", "")
        timeout_s = int(kwargs.get("timeout", 60))
        args = [
            "smbmap", "-H", target, "-u", user, "-p", passwd,
            "-R", "--depth", "5",
        ]

        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout_s,
            )
            raw = result.stdout + result.stderr
            findings = []
            has_access = False

            for line in raw.splitlines():
                m = re.search(r"(\w+)\s+(\w+)\s+(READ|WRITE|READ ONLY)", line, re.IGNORECASE)
                if m:
                    has_access = True
                    share = m.group(1)
                    perm = m.group(3)
                    findings.append({
                        "file_path": f"//{share}", "line_start": 0, "line_end": 0,
                        "severity": "high" if "WRITE" in perm.upper() else "medium",
                        "title": f"SMB share: {share} ({perm})",
                        "description": f"Share {share} accessible as {user} — permission {perm}",
                        "tool": self.name,
                        "rule_id": f"smbmap-{share}",
                        "share": share, "permission": perm,
                    })
                if line.strip() and not line.startswith("[") and not has_access:
                    if "SMB" in line or "smb" in line:
                        pass

            if not findings:
                for line in raw.splitlines():
                    if "READ" in line or "WRITE" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            findings.append({
                                "file_path": f"//{parts[0]}", "line_start": 0, "line_end": 0,
                                "severity": "info",
                                "title": f"SMB: {line.strip()}",
                                "description": line.strip(),
                                "tool": self.name,
                                "rule_id": "smbmap-fallback",
                            })

            summary = f"smbmap: {len(findings)} accessible shares on {target}"
            return EngineResult(
                success=len(findings) > 0, raw_output=raw,
                findings=findings, summary=summary, error="",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary=f"smbmap: timeout {target}", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="smbmap: not installed", error="Install smbmap")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"smbmap: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
