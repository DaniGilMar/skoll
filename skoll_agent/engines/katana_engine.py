from __future__ import annotations

from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult
from skoll_agent.workers import KatanaWorker


class KatanaEngine(BaseEngine):
    name = "katana"
    description = "Crawling profundo de endpoints web (ProjectDiscovery). Priorizar sobre gobuster."
    capabilities = ["web_scan", "crawling", "enumeration"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        worker = KatanaWorker()
        result = worker.run(target, **kwargs)
        findings = self.parse_output(result.raw_output) if result.success else []
        return EngineResult(
            success=result.success,
            raw_output=result.raw_output,
            findings=findings,
            summary=f"katana: {len(findings)} endpoints en {target}",
            error=result.error,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        import json
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
