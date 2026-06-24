from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult

TOOL_ALIASES: dict[str, list[str]] = {
    "httpx": ["httpx-toolkit", "httpx"],
}


class HttpxEngine(BaseEngine):
    name = "httpx"
    description = "HTTP probing tool. Detecta tecnologías web, status codes, titles y más."
    capabilities = ["web_scan", "fingerprinting", "tech_detect"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        binary = self._find_binary()
        if not binary:
            return EngineResult(
                success=False, raw_output="",
                summary="httpx: not installed",
                error="httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            )

        args = ["-u", target, "-j", "-silent", "-sc", "-title", "-td"]
        if kwargs.get("follow_redirects"):
            args.append("-follow-redirects")
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])

        try:
            result = subprocess.run(
                [binary, *args],
                capture_output=True, text=True,
                timeout=kwargs.get("timeout", 120),
            )
            stdout = result.stdout.strip()
            if not stdout:
                return EngineResult(success=True, raw_output="", summary="httpx: no endpoints found")
            findings = self.parse_output(stdout)
            return EngineResult(
                success=True, raw_output=stdout, findings=findings,
                summary=f"httpx: {len(findings)} endpoints on {target}",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                success=False, raw_output="", summary="httpx: timeout",
                error="Timeout",
            )
        except FileNotFoundError:
            return EngineResult(
                success=False, raw_output="", summary="httpx: not installed",
                error="Install httpx",
            )
        except Exception as e:
            return EngineResult(
                success=False, raw_output="", summary=f"httpx: {e}",
                error=str(e),
            )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                if url:
                    techs = obj.get("tech", [])
                    title = obj.get("title", "")
                    status = obj.get("status_code", 0)
                    desc_parts = []
                    if title:
                        desc_parts.append(f"Title: {title}")
                    if techs:
                        desc_parts.append(f"Tech: {', '.join(techs)}")
                    if status:
                        desc_parts.append(f"Status: {status}")
                    findings.append({
                        "file_path": url,
                        "line_start": 0, "line_end": 0,
                        "severity": "info",
                        "title": f"Web: {url}",
                        "description": " | ".join(desc_parts) if desc_parts else f"Web endpoint: {url}",
                        "tool": self.name,
                        "rule_id": "httpx-endpoint",
                        "url": url,
                        "technologies": techs,
                        "title_text": title,
                        "status_code": status,
                    })
            except json.JSONDecodeError:
                pass
        return findings

    def _find_binary(self) -> str | None:
        candidates = TOOL_ALIASES.get("httpx", ["httpx"])
        for name in candidates:
            path = shutil.which(name)
            if path:
                return path
        return None
