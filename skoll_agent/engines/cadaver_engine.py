from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class CadaverEngine(BaseEngine):
    name = "cadaver"
    description = "WebDAV client para subir/bajar archivos. Prueba PUT y listado de directorios."
    capabilities = ["webdav_client", "put_test", "directory_listing"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout_s = int(kwargs.get("timeout", 30))
        path = kwargs.get("path", "/")
        user = kwargs.get("user", "")
        passwd = kwargs.get("password", "")

        url = target.rstrip("/") + path
        test_file = "/tmp/cadaver_test.txt"
        remote_name = "skoll_cadaver_test.txt"

        # Crear archivo de prueba
        try:
            with open(test_file, "w") as f:
                f.write("skoll-webdav-test")
        except Exception:
            pass

        # Comandos para cadaver vía stdin
        commands = f"ls /\nput {test_file} {remote_name}\nrm {remote_name}\nquit\n"
        args = ["cadaver", url]

        try:
            proc = subprocess.Popen(
                args, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(input=commands, timeout=timeout_s)
            raw = stdout + stderr
            findings = []

            # Detectar si el servidor WebDAV respondió
            if "dav:" in raw.lower() or "webdav" in raw.lower() or "succeeded" in raw.lower() or "connecting" in raw.lower():
                if "could not open" in raw.lower() or "not found" in raw.lower() or "503" in raw:
                    findings.append({
                        "file_path": "", "line_start": 0, "line_end": 0,
                        "severity": "low",
                        "title": "WebDAV accessible (read-only or restricted)",
                        "description": f"WebDAV on {url} responded but upload may be restricted",
                        "tool": self.name,
                        "rule_id": "cadaver-restricted",
                    })
                else:
                    find_put = re.search(r"(upload|put|succeeded|sending)", raw, re.IGNORECASE)
                    find_ls = re.search(r"(listing|collection|contents|file)", raw, re.IGNORECASE)
                    findings.append({
                        "file_path": "", "line_start": 0, "line_end": 0,
                        "severity": "high" if find_put else "medium",
                        "title": "WebDAV upload" if find_put else "WebDAV accessible",
                        "description": f"WebDAV at {url}: {'PUT/upload possible' if find_put else 'listing available'}",
                        "tool": self.name,
                        "rule_id": "cadaver-access",
                        "recommendation": "Disable WebDAV PUT if not needed" if find_put else "",
                    })
                    if find_put:
                        findings[-1]["severity"] = "critical"

            summary = f"cadaver: {'uploads possible' if any('upload' in str(f) for f in findings) else 'read-only'} on {url}"
            return EngineResult(
                success=len(findings) > 0, raw_output=raw,
                findings=findings, summary=summary, error="",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary=f"cadaver: timeout {url}", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="cadaver: not installed", error="Install cadaver")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"cadaver: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
