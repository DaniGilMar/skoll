from __future__ import annotations

import json
import shutil
import subprocess
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
        args.extend(["-d", str(kwargs.get("depth", 3))])
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

        try:
            result = subprocess.run(
                [binary, *args], capture_output=True, text=True,
                timeout=tout,
            )
            stdout = result.stdout.strip()
            if not stdout:
                return EngineResult(success=True, raw_output="", summary="katana: no endpoints found")
            findings = self.parse_output(stdout)
            return EngineResult(
                success=True, raw_output=stdout, findings=findings,
                summary=f"katana: {len(findings)} endpoints en {target}",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                success=False, raw_output="", summary=f"katana: timeout ({tout}s), no endpoints",
                error=f"Timeout ({tout}s)",
            )
        except FileNotFoundError:
            return EngineResult(
                success=False, raw_output="", summary="katana: not installed",
                error="Install katana",
            )
        except Exception as e:
            return EngineResult(
                success=False, raw_output="", summary=f"katana: {e}",
                error=str(e),
            )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url", obj.get("request", ""))
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
