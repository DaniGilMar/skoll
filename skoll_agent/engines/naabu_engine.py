from __future__ import annotations

from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult
from skoll_agent.workers import NaabuWorker


class NaabuEngine(BaseEngine):
    name = "naabu"
    description = "Escaneo de puertos ultrarrápido (ProjectDiscovery). Priorizar sobre nmap."
    capabilities = ["port_scan", "recon", "fast_scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        worker = NaabuWorker()
        result = worker.run(target, **kwargs)
        findings = self.parse_output(result.raw_output) if result.success else []
        return EngineResult(
            success=result.success,
            raw_output=result.raw_output,
            findings=findings,
            summary=f"naabu: {len(findings)} puertos en {target}",
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
                port = obj.get("port")
                if port:
                    addr = obj.get("address", "")
                    findings.append({
                        "file_path": addr,
                        "line_start": 0, "line_end": 0,
                        "severity": "medium",
                        "title": f"Puerto {port}/{obj.get('protocol', 'tcp')}",
                        "description": f"Puerto abierto: {port}/{obj.get('protocol', 'tcp')} en {addr}",
                        "tool": self.name,
                        "rule_id": f"port-{port}",
                        "port": port,
                        "protocol": obj.get("protocol", "tcp"),
                        "service": obj.get("service", ""),
                        "state": "open",
                    })
            except json.JSONDecodeError:
                pass
        return findings
