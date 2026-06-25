from __future__ import annotations

import json
import shutil
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class KatanaEngine(BaseEngine):
    name = "katana"
    description = "Crawling profundo de endpoints web (ProjectDiscovery). Priorizar sobre gobuster."
    capabilities = ["web_scan", "crawling", "enumeration"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        binary = shutil.which("katana")
        if not binary:
            return EngineResult(
                success=False, raw_output="", summary="katana: not installed",
                error="katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
            )

        url = kwargs.get("url", target)
        args = ["-u", url, "-j", "-silent", "-jc"]
        args.extend(["-d", str(kwargs.get("depth", 1))])
        args.extend(["-f", "qurl"])
        if kwargs.get("known_files"):
            args.append("-known-files")
        if kwargs.get("no_crawl"):
            args.append("-no-crawl")
        if kwargs.get("headless"):
            args.append("-headless")
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        tout = kwargs.get("timeout", 60)
        args.extend(["-timeout", str(tout)])

        stdout, _stderr, timed_out = self.run_subprocess(
            [binary, *args], timeout=tout,
        )
        stdout = stdout.strip()

        if not stdout:
            if timed_out:
                return EngineResult(
                    success=False, raw_output="",
                    summary=f"katana: timeout ({tout}s), no endpoints",
                    error=f"Timeout ({tout}s)",
                )
            return EngineResult(success=True, raw_output="", summary="katana: no endpoints found")

        findings = self.parse_output(stdout)
        summary = f"katana: {len(findings)} endpoints en {target}"
        if timed_out:
            summary += f" (timeout, parcial)"
        return EngineResult(
            success=True, raw_output=stdout, findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                req = obj.get("request", {})
                url = req.get("endpoint", "") if isinstance(req, dict) else ""
                if not url:
                    url = obj.get("url", "")
                if url:
                    endpoint = url.split("?")[0]
                    findings.append({
                        "file_path": endpoint,
                        "line_start": 0, "line_end": 0,
                        "severity": "info",
                        "title": f"Endpoint: {endpoint}",
                        "description": f"Endpoint descubierto por crawling: {url}",
                        "tool": self.name,
                        "rule_id": "katana-endpoint",
                        "url": url,
                        "path": endpoint,
                    })
            except json.JSONDecodeError:
                pass
        return findings
