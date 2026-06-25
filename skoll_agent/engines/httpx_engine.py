from __future__ import annotations

import json
import shutil
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult
from skoll_agent.utils.dependency_checker import TOOL_ALIASES


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

        url = kwargs.get("url", target)
        args = ["-u", url, "-j", "-silent", "-sc", "-title", "-td"]
        if kwargs.get("follow_redirects"):
            args.append("-follow-redirects")
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])

        tout = kwargs.get("timeout", 120)
        stdout, _stderr, timed_out = self.run_subprocess(
            [binary, *args], timeout=tout,
        )
        stdout = stdout.strip()

        if not stdout:
            if timed_out:
                return EngineResult(
                    success=False, raw_output="", summary="httpx: timeout",
                    error="Timeout",
                )
            return EngineResult(success=True, raw_output="", summary="httpx: no endpoints found")

        findings = self.parse_output(stdout)
        summary = f"httpx: {len(findings)} endpoints on {target}"
        if timed_out:
            summary += " (timeout, partial)"
        return EngineResult(
            success=True, raw_output=stdout, findings=findings,
            summary=summary,
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
