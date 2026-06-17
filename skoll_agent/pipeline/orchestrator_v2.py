from __future__ import annotations

import json
import time
from typing import Any

from skoll_agent.evidence import EvidenceStore
from skoll_agent.evidence.memory import CampaignMemory, get_campaign_memory
from skoll_agent.llm import get_llm_router
from skoll_agent.report.report_v2 import ReportGeneratorV2
from skoll_agent.rules.findings import FindingsEngine, get_findings_engine


class OrchestratorV2:
    """Orquestador v2 simplificado.

    Pipeline: Evidence Store → Findings Engine → Campaign Memory → LLM → Report
    Sin agentes, sin complejidad. Capas deterministas primero, LLM al final.
    """

    def __init__(self) -> None:
        self.evidence = EvidenceStore()
        self.memory = get_campaign_memory()
        self.findings_engine = get_findings_engine()
        self.llm = get_llm_router()

    def run(
        self,
        campaign_id: str,
        target: str = "",
        evidence_list: list[dict[str, Any]] | None = None,
        skip_llm: bool = False,
        skip_judge: bool = False,
    ) -> dict[str, Any]:
        """Ejecuta el pipeline completo.

        Args:
            campaign_id: ID único de la campaña
            target: IP/rango objetivo
            evidence_list: lista de evidencia pre-cargada. Si es None,
                           se lee del Evidence Store.
            skip_llm: saltar análisis LLM
            skip_judge: saltar validación Gemini

        Returns:
            dict con resultados del pipeline
        """
        campaign = self.memory.create_campaign(campaign_id, target)
        scan = self.memory.start_scan(campaign_id, target)
        scan_run_id = scan["scan_run_id"]

        # 1. Obtener evidencia
        if evidence_list is None:
            evidence_list = self.evidence.get_by_campaign(campaign_id)
            if not evidence_list:
                return {
                    "error": "No evidence found. Load evidence first via EvidenceStore.save()",
                    "campaign_id": campaign_id,
                }

        print(f"  [v2] Procesando {len(evidence_list)} evidencias...")

        # 2. Findings Engine (0 tokens)
        findings = self.findings_engine.process_evidence(evidence_list)
        print(f"  [v2] {len(findings)} hallazgos deterministas generados")

        # 3. Guardar en Campaign Memory
        for f in findings:
            self.memory.remember_finding(campaign_id, scan_run_id, f)

        # Extraer hosts de la evidencia
        hosts_seen: dict[str, dict[str, Any]] = {}
        for ev in evidence_list:
            h = ev.get("host", "")
            if h and h not in hosts_seen:
                obs = ev.get("observations", [])
                ports = len(obs)
                services = len({o.get("service", "") for o in obs if o.get("service")})
                hosts_seen[h] = {
                    "ip": h,
                    "hostname": "",
                    "os": "",
                    "port_count": ports,
                    "service_count": services,
                }
                self.memory.upsert_host(campaign_id, h, port_count=ports, service_count=services)

        # 4. Correlación entre hosts
        correlations = self.memory.correlate_hosts(campaign_id)
        print(f"  [v2] {len(correlations)} correlaciones entre hosts")

        # 5. Campaign summary
        summary = self.memory.campaign_summary(campaign_id)

        # 6. LLM analysis (solo findings severidad high+)
        llm_text = ""
        high_findings = [f for f in findings if f.get("severity", "low").lower() in ("high", "critical")]
        if high_findings and not skip_llm:
            print(f"  [v2] Analizando {len(high_findings)} hallazgos con LLM...")
            findings_summary = "\n".join(
                f"- [{f['severity']}] {f['title']} en {f['host']}:{f.get('port','')}"
                for f in high_findings
            )
            llm_prompt = f"""Eres un analista de seguridad senior. Revisa estos hallazgos y proporciona:
1. Evaluación de riesgo global
2. Prioridad de remediación
3. Recomendaciones específicas

Campaign: {campaign_id}
Target: {target}

Hallazgos:
{findings_summary}

Proporciona análisis en lenguaje natural, sin JSON."""
            llm_text = self.llm.chat(llm_prompt, model="llama-3.3-70b-versatile")
            print(f"  [v2] Análisis LLM: {len(llm_text)} chars")

        # 7. Judge Gemini
        judge_text = ""
        if not skip_judge:
            print("  [v2] Validando con juez Gemini...")
            findings_for_judge = "\n".join(
                f"- [{f['severity']}] {f['title']} en {f['host']}:{f.get('port','')} - {f['description']}"
                for f in findings[:15]  # top 15 max
            )
            try:
                judge_text = self.llm.judge(findings_for_judge)
                print(f"  [v2] Juez: {judge_text[:100]}...")
            except Exception as e:
                judge_text = json.dumps({"veredicto": "ERROR", "razon": str(e), "confianza": "baja"})

        # 8. Finalizar scan
        self.memory.finish_scan(scan_run_id, len(findings))

        # 9. Generar reporte
        report = ReportGeneratorV2(campaign_id)
        files = report.generate(
            findings=findings,
            campaign_summary=summary,
            llm_analysis=llm_text,
            judge_verdict=judge_text,
            scan_target=target,
            hosts=list(hosts_seen.values()),
        )
        print(f"  [v2] Reporte generado: {files.get('markdown', 'N/A')}")

        return {
            "campaign_id": campaign_id,
            "scan_run_id": scan_run_id,
            "total_evidence": len(evidence_list),
            "total_findings": len(findings),
            "high_findings": len(high_findings),
            "correlations": len(correlations),
            "llm_analysis": llm_text,
            "judge_verdict": judge_text,
            "report_files": files,
            "summary": summary,
        }


def run_v2_pipeline(
    campaign_id: str,
    target: str = "",
    evidence_list: list[dict[str, Any]] | None = None,
    skip_llm: bool = False,
    skip_judge: bool = False,
) -> dict[str, Any]:
    orch = OrchestratorV2()
    return orch.run(
        campaign_id=campaign_id,
        target=target,
        evidence_list=evidence_list,
        skip_llm=skip_llm,
        skip_judge=skip_judge,
    )
