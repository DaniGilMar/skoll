from __future__ import annotations

import re
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class FTPEngine(BaseEngine):
    name = "ftp"
    description = "FTP anonymous login scanner — prueba anonymous, lista archivos, descarga hints"
    capabilities = ["network", "service-scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        port = int(kwargs.get("port", 21))
        import socket as _socket
        import ftplib as _ftplib

        files_found: list[str] = []
        downloaded: list[dict[str, str]] = []
        messages: list[str] = []

        # Try anonymous login
        ftp = _ftplib.FTP()
        try:
            ftp.connect(target, port, timeout=10)
        except (_socket.timeout, ConnectionRefusedError, TimeoutError, OSError) as e:
            return EngineResult(
                success=False,
                raw_output=str(e),
                summary=f"FTP {target}:{port} — connection failed: {e}",
                findings=[{
                    "port": port, "service": "ftp",
                    "title": "FTP connection failed",
                    "description": str(e),
                    "severity": "info",
                    "rule_id": "ftp-connection-failed",
                }],
            )

        try:
            ftp.login("anonymous", "anonymous@test.com")
            messages.append("Anonymous login successful")
        except _ftplib.error_perm as e:
            msgs = []
            for err in ("530", "500", "550"):
                if err in str(e):
                    msgs.append(err)
                    break
            if not msgs:
                msgs.append("login_failed")
            ftp.quit()
            return EngineResult(
                success=False,
                raw_output=f"FTP anonymous login failed: {e}",
                summary=f"FTP {target}:{port} — anonymous login denied",
                findings=[{
                    "port": port, "service": "ftp",
                    "title": "FTP anonymous login denied",
                    "description": f"Server rejected anonymous login: {e}",
                    "severity": "info",
                    "rule_id": "ftp-anonymous-denied",
                }],
            )

        files_found.append("(anonymous login OK)")

        # List root directory
        try:
            listing: list[str] = []
            ftp.dir("-la", listing.append)
            files_found.extend(listing)
        except Exception as e:
            messages.append(f"dir failed: {e}")

        # Try to download common CTF files
        for fname in ("flag.txt", "flag", "note.txt", "notes.txt", "hint.txt",
                       "readme.txt", "README.txt", "welcome.txt",
                       ".flag", ".hint", ".note", "message.txt"):
            try:
                data: list[bytes] = []
                ftp.retrbinary(f"RETR {fname}", data.append)
                content = b"".join(data).decode("utf-8", errors="replace")
                downloaded.append({"file": fname, "content": content[:2000]})
                messages.append(f"Downloaded: {fname}")
            except Exception:
                pass

        ftp.quit()

        raw_output = "\n".join([
            f"FTP {target}:{port}",
            f"Anonymous: OK",
            f"Files: {len(files_found)}",
            f"Downloaded: {len(downloaded)}",
            *([f"--- {d['file']} ---\n{d['content']}" for d in downloaded]),
        ])

        findings: list[dict[str, Any]] = [{
            "port": port, "service": "ftp",
            "title": "FTP anonymous login enabled",
            "description": "Anonymous FTP login is allowed — can list and download files",
            "severity": "high",
            "rule_id": "ftp-anonymous-enabled",
        }]

        for d in downloaded:
            for pattern, pname in [
                (r"flag\{[^}]+\}", "flag"),
                (r"CTF\{[^}]+\}", "ctf"),
                (r"HTB\{[^}]+\}", "htb"),
                (r"THM\{[^}]+\}", "thm"),
            ]:
                for m in re.finditer(pattern, d["content"]):
                    findings.append({
                        "port": port, "service": "ftp",
                        "title": f"FLAG found in {d['file']}",
                        "description": f"Flag: {m.group()}",
                        "severity": "critical",
                        "rule_id": "ftp-flag-found",
                        "flag_value": m.group(),
                    })

            findings.append({
                "port": port, "service": "ftp",
                "title": f"Downloaded: {d['file']}",
                "description": d["content"][:500],
                "severity": "high" if "flag" in d["file"].lower() else "info",
                "rule_id": f"ftp-downloaded-{d['file']}",
            })

        return EngineResult(
            success=True,
            raw_output=raw_output,
            findings=findings,
            summary=f"FTP {target}:{port} — anonymous OK, descargados {len(downloaded)} archivos",
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
