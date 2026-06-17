from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class DavtestEngine(BaseEngine):
    name = "davtest"
    description = "WebDAV scanner. Detecta métodos PUT/PROPFIND y archivos subibles."
    capabilities = ["webdav_scan", "put_check", "upload_test"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout_s = int(kwargs.get("timeout", 60))
        path = kwargs.get("path", "/")
        url = target.rstrip("/") + path
        args = ["davtest", "-url", url, "-cleanup"]

        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout_s,
            )
            raw = result.stdout + result.stderr
            findings = []

            if "SUCCEED" in raw or "SUCCESS" in raw:
                for line in raw.splitlines():
                    if "SUCCEED" in line or "SUCCESS" in line:
                        m = re.search(r"(exec|PUT|DELETE|PROPFIND|MOVE|COPY)\s+(\w+)", line, re.IGNORECASE)
                        method = m.group(1) if m else "unknown"
                        ext = m.group(2) if m else ""
                        sev = "critical" if method.upper() in ("PUT", "DELETE", "EXEC") else "medium"
                        findings.append({
                            "file_path": "", "line_start": 0, "line_end": 0,
                            "severity": sev,
                            "title": f"WebDAV {method} SUCCEED ({ext})",
                            "description": line.strip(),
                            "tool": self.name,
                            "rule_id": f"davtest-{method}",
                            "method": method, "extension": ext,
                            "recommendation": "Disable WebDAV or restrict methods to read-only",
                        })

            if not findings and "FAIL" not in raw.upper() and raw.strip():
                for line in raw.splitlines():
                    if "attempt" in line.lower() or "testing" in line.lower():
                        findings.append({
                            "file_path": "", "line_start": 0, "line_end": 0,
                            "severity": "info",
                            "title": line.strip(),
                            "description": line.strip(),
                            "tool": self.name,
                            "rule_id": "davtest-info",
                        })

            summary = f"davtest: {len(findings)} findings for {url}"
            return EngineResult(
                success=len(findings) > 0, raw_output=raw,
                findings=findings, summary=summary, error="",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary=f"davtest: timeout {url}", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="davtest: not installed", error="Install davtest")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"davtest: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
