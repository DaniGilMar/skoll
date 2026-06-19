from __future__ import annotations

import json
import time
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult
from skoll_agent.workers.manager import WorkflowManager


class RagnarokEngine(BaseEngine):
    name = "ragnarok"
    description = (
        "Workflow completo de reconocimiento y enumeración Ragnarök. "
        "Orquesta: subfinder -> amass -> naabu -> httpx -> katana -> ffuf -> nuclei. "
        "Usa herramientas externas de alto rendimiento (ProjectDiscovery suite + ffuf) "
        "y normaliza toda la salida a un esquema común para análisis por IA."
    )
    capabilities = [
        "dns_recon", "port_scan", "web_fingerprint", "crawling",
        "fuzzing", "vuln_scan", "recon", "enumeration",
    ]

    def scan(self, target: str, event_queue: Any = None, session_id: str | None = None, **kwargs: Any) -> EngineResult:
        manager = WorkflowManager()
        start = time.time()

        results = manager.run_all(target, event_queue=event_queue, session_id=session_id, **kwargs)
        elapsed = time.time() - start

        all_findings: list[dict[str, Any]] = []
        raw_parts: list[str] = []
        worker_summaries: list[str] = []

        for key, res in results.items():
            if res.raw_output:
                raw_parts.append(f"=== {key} ===\n{res.raw_output[:2000]}")
            for f in res.findings:
                normalized = self._normalize_worker_finding(f, key)
                all_findings.append(normalized)
            wname = key.split(":", 1)[0]
            status = "OK" if res.success else "FAIL"
            worker_summaries.append(f"{wname}: {status} ({len(res.findings)} findings)")

        # Add credentials to findings
        for url, creds in manager._credentials.items():
            all_findings.append({
                "file_path": url,
                "line_start": 0,
                "line_end": 0,
                "severity": "info",
                "title": "Credenciales encontradas",
                "description": f"Credenciales para {url}: {creds['username']}:{creds['password']}",
                "tool": "credentials",
                "rule_id": "creds-found",
                "type": "credentials",
                "raw_data": str(creds),
            })

        summary = manager.summary()
        total_duration = summary.get("duration", elapsed)

        return EngineResult(
            success=True,
            raw_output="\n\n".join(raw_parts),
            findings=all_findings,
            summary=(
                f"Ragnarök workflow completado en {total_duration:.1f}s. "
                f"{summary['total_workers']} workers, {summary['successful']} exitosos, "
                f"{summary['total_findings']} hallazgos. "
                f"Credenciales obtenidas para {len(manager._credentials)} servicios. "
                f"Workers: {' | '.join(worker_summaries)}"
            ),
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    def _normalize_worker_finding(self, f: dict[str, Any], source_key: str) -> dict[str, Any]:
        sev = self._map_severity(f.get("severity", "info"))
        title = f.get("name", "Unknown")
        desc = f.get("description", "")
        ftype = f.get("type", "generic")
        tool = source_key.split(":", 1)[0]
        rule_id = f.get("data", {}).get("template-id") or f.get("template", "") or ftype
        return {
            "file_path": f.get("name", ""),
            "line_start": 0,
            "line_end": 0,
            "severity": sev,
            "title": title,
            "description": desc,
            "tool": tool,
            "rule_id": str(rule_id),
            "type": ftype,
            "raw_data": json.dumps(f.get("data", {}), default=str)[:2000],
        }

    def _map_severity(self, sev: str) -> str:
        m = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        return m.get(sev.lower(), "info")

    def get_structured_data(self, target: str, **kwargs: Any) -> dict[str, Any]:
        manager = WorkflowManager()
        manager.run_all(target, skip_credentials=True, **kwargs)
        return manager.to_structured()
