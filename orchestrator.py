from __future__ import annotations

import json
import queue
import time
from typing import Any

from core.config import get_config
from core.evidence import EvidenceStore, get_campaign_memory
from core.llm import get_llm_router
from core.logging import get_logger
from core.rules import get_findings_engine
from core.schema import Finding, Target
from tiers import get_tier

logger = get_logger()
cfg = get_config()


class Orchestrator:
    def __init__(self) -> None:
        self.evidence_store = EvidenceStore(cfg.evidence_db)
        self.memory = get_campaign_memory()
        self.findings_engine = get_findings_engine()
        self.llm = get_llm_router()

    def run(
        self,
        target_raw: str,
        campaign_id: str = "",
        tier_name: str = "fast",
        skip_llm: bool = False,
        progress_queue: queue.Queue | None = None,
    ) -> dict[str, Any]:
        def emit(typ: str, data: dict | None = None):
            if progress_queue is not None:
                progress_queue.put({"type": typ, "data": data or {}})

        if not campaign_id:
            campaign_id = f"scan_{int(time.time())}"

        target = Target.parse(target_raw)
        tier = get_tier(tier_name)
        target_str = target.hostname or target.ip

        logger.info("pipeline", f"Iniciando campaña {campaign_id}")
        emit("agent_log", {"message": f"📋 Iniciando escaneo contra {target_str} (perfil: {tier.name})"})

        # 1. Campaña
        self.memory.create_campaign(campaign_id, target_raw)
        scan = self.memory.start_scan(campaign_id, target_raw)
        scan_run_id = scan["scan_run_id"]

        # 2. Ejecutar nmap
        emit("agent_log", {"message": "🔧 Ejecutando nmap..."})
        emit("agent_tool_start", {"tool": "nmap", "target": target_str, "params": {"flags": tier.nmap_flags}})
        logger.info("engines", f"nmap {target_str} {tier.nmap_flags}")
        nmap_result = self._run_nmap(target_str, tier.nmap_flags)
        if nmap_result:
            self.evidence_store.save(campaign_id, target_str, "nmap", nmap_result)
            obs = nmap_result.get("observations", [])
            emit("agent_tool_result", {"tool": "nmap", "target": target_str, "summary": f"{len(obs)} puertos encontrados"})
        else:
            emit("agent_tool_result", {"tool": "nmap", "target": target_str, "summary": "Sin resultados"})

        evidence_list = [{"host": target_str, "tool": "nmap", "observations": nmap_result.get("observations", [])}]

        # 3. whatweb
        if tier.whatweb:
            emit("agent_log", {"message": "🔧 Ejecutando whatweb..."})
            emit("agent_tool_start", {"tool": "whatweb", "target": target_str, "params": {}})
            logger.info("engines", f"whatweb {target_str}")
            ww_result = self._run_whatweb(target_str)
            if ww_result:
                self.evidence_store.save(campaign_id, target_str, "whatweb", ww_result)
                evidence_list.append({"host": target_str, "tool": "whatweb", "observations": ww_result.get("observations", [])})
                emit("agent_tool_result", {"tool": "whatweb", "target": target_str, "summary": "Web detectada"})
            else:
                emit("agent_tool_result", {"tool": "whatweb", "target": target_str, "summary": "Sin respuesta web"})

        # 4. Findings Engine
        emit("agent_log", {"message": "🔍 Analizando hallazgos (0 tokens)..."})
        findings_data = self.findings_engine.process_evidence(evidence_list)
        findings = [Finding(**f) if not isinstance(f, Finding) else f for f in findings_data]
        emit("agent_log", {"message": f"📊 {len(findings)} hallazgos deterministas"})

        # 5. Guardar en memoria
        for f in findings:
            self.memory.remember_finding(campaign_id, scan_run_id, f.to_dict() if hasattr(f, "to_dict") else f)

        # 6. Hosts
        for ev in evidence_list:
            h = ev.get("host", "")
            obs = ev.get("observations", [])
            self.memory.upsert_host(campaign_id, h, port_count=len(obs), service_count=len({o.get("service", "") for o in obs if o.get("service")}))
        correlations = self.memory.correlate_hosts(campaign_id)
        if correlations:
            emit("agent_log", {"message": f"🔗 {len(correlations)} correlaciones entre servicios"})

        # 7. LLM
        llm_text = ""
        critical = [f for f in findings if f.severity in ("critical", "high")]
        if critical and not skip_llm and cfg.has_groq:
            emit("agent_log", {"message": f"🧠 Analizando {len(critical)} hallazgos con LLM..."})
            summary = "\n".join(f"- [{f.severity}] {f.title} en {f.host}:{f.port}" for f in critical)
            prompt = f"Eres un analista de seguridad. Revisa:\n{summary}\n\nProporciona análisis en lenguaje natural."
            llm_text = self.llm.chat(prompt, model="llama-3.3-70b-versatile")
            emit("agent_log", {"message": "✅ Análisis LLM completado"})

        self.memory.finish_scan(scan_run_id, len(findings))
        summary = self.memory.campaign_summary(campaign_id)

        # 8. Reporte
        report_files = {}
        if findings:
            from core.report import ReportGenerator
            report = ReportGenerator(campaign_id, cfg.reports_dir)
            report_files = report.generate(
                findings=[f.to_dict() for f in findings],
                campaign_summary=summary,
                llm_analysis=llm_text,
                scan_target=target_raw,
                hosts=self.memory.get_hosts(campaign_id),
            )
            emit("agent_log", {"message": f"📄 Reporte: {report_files.get('markdown', '')}"})

        result = {
            "campaign_id": campaign_id,
            "target": target_raw,
            "tier": tier.name,
            "total_evidence": len(evidence_list),
            "total_findings": len(findings),
            "critical_findings": len(critical),
            "report_files": report_files,
        }

        emit("agent_summary", {"message": f"✅ {len(findings)} hallazgos ({len(critical)} críticos)"})
        logger.info("pipeline", f"Completado: {len(findings)} hallazgos")
        return result

    def _run_nmap(self, target: str, flags: str) -> dict[str, Any]:
        from core.run import run_command
        cmd = ["nmap", *flags.split(), target, "-oX", "-"]
        result = run_command(cmd, description=f"nmap {target} {flags}", timeout=600)
        if result["returncode"] != 0 and not result["timed_out"]:
            logger.error("nmap", f"Error: {result['stderr'][:200]}")
            return {}
        stdout = result["stdout"]
        if not stdout.strip():
            return {}
        return self._parse_nmap_xml(stdout)

    def _parse_nmap_xml(self, xml_text: str) -> dict[str, Any]:
        import xml.etree.ElementTree as ET
        observations = []
        try:
            root = ET.fromstring(xml_text)
            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    port_id = port.get("port", "0")
                    protocol = port.get("protocol", "tcp")
                    state_el = port.find("state")
                    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                    service_el = port.find("service")
                    service = service_el.get("name", "") if service_el is not None else ""
                    flags = []
                    for script in port.findall(".//script"):
                        output = script.get("output", "").lower()
                        if "disabled" in output and "signing" in output:
                            flags.append("SMB_SIGNING_DISABLED")
                        if "anonymous" in output:
                            flags.append("ANONYMOUS_LOGIN")
                    observations.append({
                        "port": int(port_id) if port_id.isdigit() else 0,
                        "service": service, "protocol": protocol,
                        "state": state, "flags": flags,
                    })
        except ET.ParseError:
            return {}
        return {"observations": observations}

    def _run_whatweb(self, target: str) -> dict[str, Any]:
        from core.run import run_command
        url = f"http://{target}" if not target.startswith("http") else target
        cmd = ["whatweb", "--no-errors", "-a", "3", url]
        result = run_command(cmd, description=f"whatweb {url}", timeout=120)
        if result["returncode"] not in (0, 1):
            return {}
        output = result["stdout"].strip()
        if not output:
            return {}
        observations = [{
            "port": 80 if url.startswith("http://") else 443,
            "service": "http" if url.startswith("http://") else "https",
            "state": "open", "flags": [],
            "raw": {"whatweb_output": output},
        }]
        return {"observations": observations}
