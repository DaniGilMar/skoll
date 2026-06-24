from __future__ import annotations

import json
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult
from skoll_agent.pipeline.orchestrator import PipelineOrchestrator


class RagnarokEngine(BaseEngine):
    name = "ragnarok"
    description = (
        "Workflow completo adaptivo: recon → analyze → exploit → report. "
        "Usa StateStore + AdaptiveRouter para decidir qué herramientas ejecutar "
        "basado en el contexto del target."
    )
    capabilities = [
        "dns_recon", "port_scan", "web_fingerprint", "crawling",
        "fuzzing", "vuln_scan", "recon", "enumeration",
    ]

    def scan(self, target: str, event_queue: Any = None, session_id: str | None = None, **kwargs: Any) -> EngineResult:
        resume = kwargs.get("resume", False)

        def emit(event_type: str, data: dict[str, Any]) -> None:
            if event_queue:
                event_queue.put({"type": event_type, "data": data})

        orchestrator = PipelineOrchestrator(
            target=target,
            is_network=True,
            llm_client=None,
            event_callback=emit,
            session_id=session_id or "",
            resume=resume,
        )

        orchestrator.run()

        findings = orchestrator.store.read_findings()
        state_data = orchestrator.store.load()
        context = state_data.get("context", {})

        worker_summaries = []
        for phase_name in orchestrator.PHASES:
            ps = state_data.get("phases", {}).get(phase_name, {})
            status = ps.get("status", "?")
            count = ps.get("findings_count", 0)
            worker_summaries.append(f"{phase_name}: {status} ({count} findings)")

        return EngineResult(
            success=True,
            raw_output=json.dumps(state_data, indent=2, default=str),
            findings=findings,
            summary=(
                f"Pipeline completado. "
                f"{len(findings)} hallazgos totales. "
                f"Workers: {' | '.join(worker_summaries)}"
            ),
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    def get_structured_data(self, target: str, **kwargs: Any) -> dict[str, Any]:
        store = __import__("skoll_agent.pipeline.state_store", fromlist=["StateStore"]).StateStore(target)
        if not store.exists():
            return {"error": "No scan data for this target"}
        state = store.load()
        findings = store.read_findings()
        return {
            "target": target,
            "status": state.get("status", "unknown"),
            "phases": state.get("phases", {}),
            "open_ports": state.get("context", {}).get("open_ports", []),
            "web_services": state.get("context", {}).get("web_services", []),
            "credentials": state.get("context", {}).get("credentials", []),
            "total_findings": len(findings),
            "findings": findings,
        }
