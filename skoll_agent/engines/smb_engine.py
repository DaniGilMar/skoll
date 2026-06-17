from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class SMBEngine(BaseEngine):
    name = "smb"
    description = "SMB enum scanner — enum4linux, smbclient, smbmap"
    capabilities = ["network", "service-scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings: list[dict[str, Any]] = []
        raw_parts: list[str] = []

        # 1. smbclient -L to list shares
        try:
            result = subprocess.run(
                ["smbclient", "-L", target, "-N", "-U", ""],
                capture_output=True, text=True, timeout=30,
            )
            output = (result.stdout or "") + (result.stderr or "")
            raw_parts.append(f"=== smbclient -L ===\n{output[:2000]}")
            shares: list[str] = []

            for line in output.split("\n"):
                line_s = line.strip()
                if line_s and not line_s.startswith("\\"):
                    share_name = line_s.split()[0] if line_s.split() else ""
                    if share_name and share_name.endswith("$"):
                        continue
                    if share_name and share_name not in ("Anonymous", "", "Disk", "IPC"):
                        shares.append(share_name)

            if shares:
                findings.append({
                    "service": "smb",
                    "title": f"SMB shares found: {', '.join(shares)}",
                    "description": f"Shares: {', '.join(shares)}",
                    "severity": "high",
                    "rule_id": "smb-shares-found",
                })

            raw_parts.append(f"Shares: {shares}")

            # Try anonymous access on each share
            for share in shares[:5]:
                try:
                    ls_result = subprocess.run(
                        ["smbclient", f"//{target}/{share}", "-N", "-c", "ls"],
                        capture_output=True, text=True, timeout=15,
                    )
                    ls_out = (ls_result.stdout or "") + (ls_result.stderr or "")
                    if "NT_STATUS_ACCESS_DENIED" not in ls_out and ls_out.strip():
                        raw_parts.append(f"=== {share} (accessible) ===\n{ls_out[:2000]}")
                        findings.append({
                            "service": "smb",
                            "title": f"SMB share {share} accessible anonymously",
                            "description": f"Share {share} allows anonymous read access",
                            "severity": "critical",
                            "rule_id": f"smb-share-open-{share}",
                        })
                        # Download files from accessible share
                        try:
                            get_result = subprocess.run(
                                ["smbclient", f"//{target}/{share}", "-N",
                                 "-c", "recurse; ls"],
                                capture_output=True, text=True, timeout=15,
                            )
                            files = (get_result.stdout or "") + (get_result.stderr or "")
                            raw_parts.append(f"=== {share} files ===\n{files[:2000]}")
                        except Exception:
                            pass
                except Exception:
                    continue

        except FileNotFoundError:
            raw_parts.append("smbclient not found")
        except subprocess.TimeoutExpired:
            raw_parts.append("smbclient timed out")
        except Exception as e:
            raw_parts.append(f"smbclient error: {e}")

        # 2. Flag detection in all output
        all_text = "\n".join(raw_parts)
        for pattern, pname in [
            (r"flag\{[^}]+\}", "flag"),
            (r"CTF\{[^}]+\}", "ctf"),
            (r"HTB\{[^}]+\}", "htb"),
            (r"THM\{[^}]+\}", "thm"),
        ]:
            for m in re.finditer(pattern, all_text, re.IGNORECASE):
                findings.append({
                    "service": "smb",
                    "title": f"FLAG found via SMB: {m.group()}",
                    "description": f"Flag value: {m.group()}",
                    "severity": "critical",
                    "rule_id": "smb-flag-found",
                    "flag_value": m.group(),
                })

        if not findings:
            findings.append({
                "service": "smb",
                "title": "SMB scan complete — no shares accessible",
                "description": "No accessible SMB shares without credentials",
                "severity": "info",
                "rule_id": "smb-no-access",
            })

        return EngineResult(
            success=True,
            raw_output="\n".join(raw_parts),
            findings=findings,
            summary=f"SMB scan on {target}: {len(findings)} findings",
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
