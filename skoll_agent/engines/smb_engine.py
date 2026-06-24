from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult

HEADERS = {"sharename", "---------", "disk", "ipc", "comment", "type"}


class SMBEngine(BaseEngine):
    name = "smb"
    description = "SMB enumeration and exploitation — smbclient anónimo, descarga de archivos."
    capabilities = ["network", "service-scan", "exploitation"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        action = kwargs.get("action", "enum")
        if action == "download":
            return self._download(target, kwargs.get("share", ""))
        return self._enum(target, **kwargs)

    # ── enumeration phase (analyze) ───────────────────────────────

    def _enum(self, target: str, **kwargs: Any) -> EngineResult:
        findings: list[dict[str, Any]] = []
        raw_parts: list[str] = []

        shares = self._list_shares(target, raw_parts)
        if shares:
            findings.append({
                "tool": self.name,
                "title": f"SMB shares: {', '.join(shares)}",
                "description": f"Shares discovered: {', '.join(shares)}",
                "severity": "high",
                "rule_id": "smb-shares-found",
            })

            for share in shares:
                accessible, ls_out = self._try_access(target, share)
                if accessible:
                    raw_parts.append(f"=== {share} (files) ===\n{ls_out[:2000]}")
                    findings.append({
                        "tool": self.name,
                        "title": f"SMB share {share} accessible anonymously",
                        "description": f"Share {share} allows anonymous read access. Files: {ls_out[:300]}",
                        "severity": "critical",
                        "rule_id": f"smb-share-open-{share}",
                        "share": share,
                        "files_preview": ls_out[:500],
                    })

        if not findings:
            findings.append({
                "tool": self.name,
                "title": "No SMB shares accessible",
                "description": "No accessible SMB shares without credentials",
                "severity": "info",
                "rule_id": "smb-no-access",
            })

        all_text = "\n".join(raw_parts)
        self._detect_flags(all_text, findings)
        raw_parts.append(f"\nShares found: {shares}")

        return EngineResult(
            success=True,
            raw_output="\n".join(raw_parts),
            findings=findings,
            summary=f"SMB enum on {target}: {len(findings)} findings",
        )

    def _list_shares(self, target: str, raw: list[str]) -> list[str]:
        try:
            result = subprocess.run(
                ["smbclient", "-L", target, "-N", "-U", ""],
                capture_output=True, text=True, timeout=30,
            )
            output = (result.stdout or "") + (result.stderr or "")
            raw.append(f"=== smbclient -L ===\n{output[:2000]}")

            shares = []
            in_table = False
            for line in output.split("\n"):
                line_s = line.strip()
                if not line_s:
                    if in_table:
                        break  # empty line marks end of share table
                    continue
                if line_s.startswith("Sharename") and "Type" in line_s:
                    in_table = True
                    continue
                if not in_table or line_s.startswith("---"):
                    continue
                # Post-table noise (smbclient error messages after the listing)
                if any(line_s.startswith(w) for w in ("Reconnecting", "Unable", "Protocol", "session", "do_connect", "smbXcli")):
                    break
                parts = line_s.split()
                if not parts:
                    continue
                name = parts[0]
                if name.lower() in HEADERS or name.endswith("$"):
                    continue
                shares.append(name)
            return shares
        except Exception as e:
            raw.append(f"smbclient -L error: {e}")
            return []

    def _try_access(self, target: str, share: str) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                ["smbclient", f"//{target}/{share}", "-N", "-c", "ls"],
                capture_output=True, text=True, timeout=15,
            )
            out = (result.stdout or "") + (result.stderr or "")
            if "NT_STATUS_ACCESS_DENIED" not in out and "NT_STATUS_OBJECT_NAME_NOT_FOUND" not in out:
                return True, out
            return False, ""
        except Exception:
            return False, ""

    # ── exploitation phase: download files ────────────────────────

    def _download(self, target: str, share: str) -> EngineResult:
        findings: list[dict[str, Any]] = []
        raw_parts: list[str] = []

        if not share:
            share = self._find_accessible_share(target, raw_parts)
        if not share:
            findings.append({
                "tool": self.name,
                "title": "No accessible SMB share to download from",
                "description": "Tried anonymous access but no share was accessible",
                "severity": "info",
                "rule_id": "smb-dl-no-share",
            })
            return EngineResult(success=True, raw_output="\n".join(raw_parts), findings=findings,
                                summary="smb download: no accessible share")

        raw_parts.append(f"Downloading from share: {share}")

        # List all files recursively
        try:
            result = subprocess.run(
                ["smbclient", f"//{target}/{share}", "-N", "-c", "recurse; ls"],
                capture_output=True, text=True, timeout=30,
            )
            listing = (result.stdout or "") + (result.stderr or "")
            raw_parts.append(f"=== {share} file listing ===\n{listing[:3000]}")

            # Parse file paths from the listing
            files = self._parse_file_list(listing)
            downloaded = []
            for fpath in files[:20]:
                dl_path = self._download_file(target, share, fpath)
                if dl_path:
                    downloaded.append({"path": fpath, "local": dl_path})
                    raw_parts.append(f"  Downloaded: {fpath} → {dl_path}")

            if downloaded:
                # Flag detection in downloaded content
                for dl in downloaded:
                    if os.path.exists(dl["local"]):
                        try:
                            with open(dl["local"]) as fh:
                                content = fh.read(5000)
                            self._detect_flags(content, findings)
                            findings.append({
                                "tool": self.name,
                                "title": f"Downloaded: {dl['path']}",
                                "description": f"Downloaded from {share}: {dl['path']} → {dl['local']}",
                                "severity": "high",
                                "rule_id": f"smb-dl-{dl['path'].replace('/','-')}",
                                "share": share,
                                "file_path": dl["local"],
                                "local_path": dl["local"],
                            })
                        except Exception:
                            pass

                findings.append({
                    "tool": self.name,
                    "title": f"SMB download: {len(downloaded)} files from {share}",
                    "description": f"Downloaded {len(downloaded)} files from {share} anonymously. "
                                   f"Files: {[d['path'] for d in downloaded]}",
                    "severity": "critical",
                    "rule_id": "smb-downloaded",
                    "share": share,
                    "downloaded_files": [d["path"] for d in downloaded],
                })
            else:
                findings.append({
                    "tool": self.name,
                    "title": f"SMB share {share} accessible but no downloadable files",
                    "description": "Anonymous access confirmed but no files found in share",
                    "severity": "high",
                    "rule_id": "smb-dl-empty",
                })
        except Exception as e:
            raw_parts.append(f"Download error: {e}")
            findings.append({
                "tool": self.name,
                "title": "SMB download error",
                "description": str(e),
                "severity": "info",
                "rule_id": "smb-dl-error",
            })

        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_parts),
            findings=findings,
            summary=f"SMB download from {share}: {len(findings)} findings",
        )

    def _find_accessible_share(self, target: str, raw: list[str]) -> str:
        shares = self._list_shares(target, raw)
        for share in shares:
            ok, _ = self._try_access(target, share)
            if ok:
                return share
        return ""

    def _parse_file_list(self, listing: str) -> list[str]:
        files = []
        current_dir = ""
        for line in listing.split("\n"):
            line_s = line.strip()
            if line_s.startswith("\\") or line_s.startswith("//"):
                # smbclient recurse dir marker
                current_dir = line_s.strip("\\").strip()
                continue
            if not line_s or line_s.startswith(".") or line_s.lower().endswith("d"):
                continue
            parts = line_s.split()
            if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit():
                filename = " ".join(parts[3:])
                if filename not in (".", ".."):
                    if current_dir:
                        files.append(f"{current_dir}\\{filename}")
                    else:
                        files.append(filename)
        return files

    def _download_file(self, target: str, share: str, fpath: str) -> str:
        try:
            tmp = tempfile.mkdtemp(prefix="skoll_smb_")
            local = os.path.join(tmp, os.path.basename(fpath))
            cmd = ["smbclient", f"//{target}/{share}", "-N",
                   "-c", f'get "{fpath}" "{local}"']
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if os.path.exists(local) and os.path.getsize(local) > 0:
                return local
            return ""
        except Exception:
            return ""

    # ── flag detection ────────────────────────────────────────────

    def _detect_flags(self, text: str, findings: list[dict]) -> None:
        for pattern, pname in [
            (r"flag\{[^}]+\}", "flag"),
            (r"CTF\{[^}]+\}", "ctf"),
            (r"HTB\{[^}]+\}", "htb"),
            (r"THM\{[^}]+\}", "thm"),
        ]:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                findings.append({
                    "tool": self.name,
                    "title": f"FLAG: {m.group()}",
                    "description": f"Flag found: {m.group()}",
                    "severity": "critical",
                    "rule_id": f"smb-flag-{pname}",
                    "flag_value": m.group(),
                })

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
