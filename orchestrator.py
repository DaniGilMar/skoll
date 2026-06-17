from __future__ import annotations

import time
from typing import Any

from core.config import get_config
from core.evidence import EvidenceStore, get_campaign_memory
from core.llm import get_llm_router
from core.logging import get_logger
from core.progress import get_emitter
from core.rules import get_findings_engine
from core.schema import Evidence, Finding, Observation, ScanRun, Target
from tiers import TIERS, TierConfig, get_tier

logger = get_logger()
cfg = get_config()


class Orchestrator:
    """Orquestador principal de Skoll.

    Pipeline:
    1. Seleccionar tier → determinar qué engines ejecutar
    2. Ejecutar engines → recolectar evidencia
    3. Evidence Store → guardar evidencia cruda
    4. Findings Engine → hallazgos deterministas (0 tokens)
    5. Campaign Memory → correlacionar entre hosts
    6. LLM → análisis solo de hallazgos críticos
    7. Report → generar informe
    """

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
    ) -> dict[str, Any]:
        phase = "pipeline"
        if not campaign_id:
            campaign_id = f"scan_{int(time.time())}"

        target = Target.parse(target_raw)
        tier = get_tier(tier_name)

        logger.info(phase, f"Iniciando campaña {campaign_id} contra {target_raw}")
        logger.info(phase, f"Perfil: {tier.name} — {tier.description}")

        # 1. Crear campaña en memoria
        campaign = self.memory.create_campaign(campaign_id, target_raw)
        scan = self.memory.start_scan(campaign_id, target_raw)
        scan_run_id = scan["scan_run_id"]

        # 2. Ejecutar engines según el tier
        evidence_list = self._run_engines(target, tier, campaign_id)

        # 3. Findings Engine (0 tokens)
        findings_data = self.findings_engine.process_evidence(evidence_list)
        findings = [Finding(**f) if not isinstance(f, Finding) else f for f in findings_data]

        # 4. Guardar en memoria
        for f in findings:
            self.memory.remember_finding(
                campaign_id, scan_run_id,
                f.to_dict() if hasattr(f, "to_dict") else f,
            )

        # Registrar hosts
        hosts_seen: set[str] = set()
        for ev in evidence_list:
            h = ev.get("host", "")
            if h and h not in hosts_seen:
                hosts_seen.add(h)
                obs = ev.get("observations", [])
                ports = len(obs)
                services = len({o.get("service", "") for o in obs if o.get("service")})
                self.memory.upsert_host(campaign_id, h, port_count=ports, service_count=services)

        # Correlaciones
        correlations = self.memory.correlate_hosts(campaign_id)

        # 5. LLM (solo si hay hallazgos críticos y no se saltó)
        llm_text = ""
        critical = [f for f in findings if f.severity in ("critical", "high")]
        if critical and not skip_llm and cfg.has_groq:
            logger.info(phase, f"Analizando {len(critical)} hallazgos con LLM...")
            summary = "\n".join(
                f"- [{f.severity}] {f.title} en {f.host}:{f.port}" for f in critical
            )
            prompt = (
                f"Eres un analista de seguridad. Revisa estos hallazgos:\n{summary}\n\n"
                "Proporciona análisis en lenguaje natural: riesgo global, prioridad, recomendaciones."
            )
            llm_text = self.llm.chat(prompt, model="llama-3.3-70b-versatile")

        # 6. Finalizar
        self.memory.finish_scan(scan_run_id, len(findings))
        summary = self.memory.campaign_summary(campaign_id)

        # 7. Report (si hay hallazgos)
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

        result = {
            "campaign_id": campaign_id,
            "target": target_raw,
            "tier": tier.name,
            "total_evidence": len(evidence_list),
            "total_findings": len(findings),
            "critical_findings": len(critical),
            "correlations": len(correlations),
            "llm_analysis": llm_text,
            "report_files": report_files,
            "summary": summary,
        }

        logger.info(phase, f"Pipeline completado: {len(findings)} hallazgos")
        return result

    def _run_engines(
        self, target: Target, tier: TierConfig, campaign_id: str
    ) -> list[dict[str, Any]]:
        """Ejecuta los engines según la config del tier."""
        phase = "engines"
        evidence_list: list[dict[str, Any]] = []

        target_str = target.hostname or target.ip

        # nmap siempre
        logger.info(phase, f"Ejecutando nmap contra {target_str}")
        nmap_result = self._run_nmap(target_str, tier.nmap_flags)
        if nmap_result:
            self.evidence_store.save(campaign_id, target_str, "nmap", nmap_result)
            evidence_list.append({
                "host": target_str,
                "tool": "nmap",
                "observations": nmap_result.get("observations", []),
            })

        # whatweb siempre
        if tier.whatweb:
            logger.info(phase, "Ejecutando whatweb")
            ww_result = self._run_whatweb(target_str)
            if ww_result:
                self.evidence_store.save(campaign_id, target_str, "whatweb", ww_result)
                evidence_list.append({
                    "host": target_str,
                    "tool": "whatweb",
                    "observations": ww_result.get("observations", []),
                })

        return evidence_list

    def _run_nmap(self, target: str, flags: str) -> dict[str, Any]:
        """Ejecuta nmap y parsea resultado."""
        from core.run import run_command

        # Construir comando nmap con output XML
        cmd = ["nmap", *flags.split(), target, "-oX", "-"]
        result = run_command(cmd, description=f"nmap {target}", timeout=600)

        if result["returncode"] != 0 and not result["timed_out"]:
            logger.error("nmap", f"Error: {result['stderr'][:200]}")
            return {}

        stdout = result["stdout"]
        if not stdout.strip():
            logger.warn("nmap", "Sin output de nmap")
            return {}

        return self._parse_nmap_xml(stdout)

    def _parse_nmap_xml(self, xml_text: str) -> dict[str, Any]:
        """Parse básico de output XML de nmap."""
        import xml.etree.ElementTree as ET

        observations = []
        try:
            root = ET.fromstring(xml_text)
            for host in root.findall(".//host"):
                host_addr = host.findtext("./address/@addr", "")
                for port in host.findall(".//port"):
                    port_id = port.get("port", "0")
                    protocol = port.get("protocol", "tcp")
                    state_el = port.find("state")
                    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                    service_el = port.find("service")
                    service = service_el.get("name", "") if service_el is not None else ""

                    flags = []
                    # Detectar flags de scripts
                    for script in port.findall(".//script"):
                        script_id = script.get("id", "")
                        output = script.get("output", "").lower()
                        if "disabled" in output and "signing" in output:
                            flags.append("SMB_SIGNING_DISABLED")
                        if "anonymous" in output:
                            flags.append("ANONYMOUS_LOGIN")

                    observations.append({
                        "port": int(port_id) if port_id.isdigit() else 0,
                        "service": service,
                        "protocol": protocol,
                        "state": state,
                        "flags": flags,
                    })
        except ET.ParseError as e:
            logger.warn("nmap", f"Error parseando XML: {e}")
            return {}

        return {"observations": observations}

    def _run_whatweb(self, target: str) -> dict[str, Any]:
        """Ejecuta whatweb y parsea resultado."""
        from core.run import run_command

        url = f"http://{target}" if not target.startswith("http") else target
        cmd = ["whatweb", "--no-errors", "-a", "3", url]
        result = run_command(cmd, description=f"whatweb {url}", timeout=120)

        if result["returncode"] not in (0, 1):
            logger.warn("whatweb", f"Error: {result['stderr'][:200]}")
            return {}

        output = result["stdout"].strip()
        if not output:
            return {}

        observations = [{
            "port": 80 if url.startswith("http://") else 443,
            "service": "http" if url.startswith("http://") else "https",
            "state": "open",
            "flags": [],
            "raw": {"whatweb_output": output},
        }]
        return {"observations": observations}
