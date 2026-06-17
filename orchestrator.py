from __future__ import annotations

import json
import queue
import time
from typing import Any

from core.config import get_config
from core.evidence import EvidenceStore, get_campaign_memory
from core.llm import get_llm_router
from core.logging import get_logger
from core.osint import subfinder_enum, theharvester_collect, crt_lookup, dns_enum
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
        self._progress_queue = progress_queue
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

        # 1b. OSINT (solo si es dominio, no IP)
        if "." in target_raw and not target_raw[0].isdigit():
            emit("agent_log", {"message": "🔍 Fase OSINT: recopilando información pasiva..."})

            emit("agent_tool_start", {"tool": "subfinder_enum", "target": target_str, "params": {}})
            sf_res = subfinder_enum(target_str)
            emit("agent_tool_result", {"tool": "subfinder_enum", "target": target_str, "summary": sf_res.get("result", "")[:150]})

            emit("agent_tool_start", {"tool": "theharvester_collect", "target": target_str, "params": {}})
            th_res = theharvester_collect(target_str)
            emit("agent_tool_result", {"tool": "theharvester_collect", "target": target_str, "summary": th_res.get("result", "")[:150]})

            emit("agent_tool_start", {"tool": "crt_lookup", "target": target_str, "params": {}})
            crt_res = crt_lookup(target_str)
            emit("agent_tool_result", {"tool": "crt_lookup", "target": target_str, "summary": crt_res.get("result", "")[:150]})

            emit("agent_tool_start", {"tool": "dns_enum", "target": target_str, "params": {}})
            dns_res = dns_enum(target_str)
            emit("agent_tool_result", {"tool": "dns_enum", "target": target_str, "summary": dns_res.get("result", "")[:150]})

            emit("agent_log", {"message": "✅ OSINT completado — pasando a escaneo activo"})

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

        has_web = False

        # 3. whatweb
        if tier.whatweb:
            emit("agent_log", {"message": "🔧 Ejecutando whatweb..."})
            emit("agent_tool_start", {"tool": "whatweb", "target": target_str, "params": {}})
            logger.info("engines", f"whatweb {target_str}")
            ww_result = self._run_whatweb(target_str)
            if ww_result:
                self.evidence_store.save(campaign_id, target_str, "whatweb", ww_result)
                evidence_list.append({"host": target_str, "tool": "whatweb", "observations": ww_result.get("observations", [])})
                has_web = True
                emit("agent_tool_result", {"tool": "whatweb", "target": target_str, "summary": "Web detectada"})
            else:
                emit("agent_tool_result", {"tool": "whatweb", "target": target_str, "summary": "Sin respuesta web"})

        # 3b. sqlmap
        if has_web and tier.sqlmap:
            emit("agent_log", {"message": "💉 Ejecutando sqlmap..."})
            emit("agent_tool_start", {"tool": "sqlmap", "target": target_str, "params": {}})
            logger.info("engines", f"sqlmap {target_str}")
            sqlmap_result = self._run_sqlmap(target_str)
            if sqlmap_result:
                self.evidence_store.save(campaign_id, target_str, "sqlmap", sqlmap_result)
                evidence_list.append({"host": target_str, "tool": "sqlmap", "observations": sqlmap_result.get("observations", [])})
                vuln_count = len(sqlmap_result.get("observations", []))
                emit("agent_tool_result", {"tool": "sqlmap", "target": target_str, "summary": f"{vuln_count} posibles vulnerabilidades"})
            else:
                emit("agent_tool_result", {"tool": "sqlmap", "target": target_str, "summary": "Sin inyecciones detectadas"})

        # 3c. nikto
        if has_web and tier.nikto:
            emit("agent_log", {"message": "🔧 Ejecutando nikto..."})
            emit("agent_tool_start", {"tool": "nikto", "target": target_str, "params": {}})
            logger.info("engines", f"nikto {target_str}")
            nikto_result = self._run_nikto(target_str)
            if nikto_result:
                self.evidence_store.save(campaign_id, target_str, "nikto", nikto_result)
                evidence_list.append({"host": target_str, "tool": "nikto", "observations": nikto_result.get("observations", [])})
                emit("agent_tool_result", {"tool": "nikto", "target": target_str, "summary": "Escaneo nikto completado"})
            else:
                emit("agent_tool_result", {"tool": "nikto", "target": target_str, "summary": "Sin resultados"})

        # 3d. gobuster
        if has_web and tier.gobuster:
            emit("agent_log", {"message": "🔧 Ejecutando gobuster..."})
            emit("agent_tool_start", {"tool": "gobuster", "target": target_str, "params": {}})
            logger.info("engines", f"gobuster {target_str}")
            gb_result = self._run_gobuster(target_str)
            if gb_result:
                self.evidence_store.save(campaign_id, target_str, "gobuster", gb_result)
                evidence_list.append({"host": target_str, "tool": "gobuster", "observations": gb_result.get("observations", [])})
                emit("agent_tool_result", {"tool": "gobuster", "target": target_str, "summary": f"{len(gb_result.get('observations', []))} rutas encontradas"})
            else:
                emit("agent_tool_result", {"tool": "gobuster", "target": target_str, "summary": "Sin rutas descubiertas"})

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
        import re
        cmd = ["nmap", *flags.split(), target, "-oX", "-"]

        def on_line(line: str):
            m = re.search(r"About\s+([\d.]+)%", line)
            if m:
                pct = m.group(1)
                if self._progress_queue is not None:
                    self._progress_queue.put({"type": "agent_log", "data": {"message": f"⏳ nmap: {pct}% completado"}})

        result = run_command(cmd, description=f"nmap {target} {flags}", timeout=600, line_callback=on_line)
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

    def _run_sqlmap(self, target: str) -> dict[str, Any]:
        from core.run import run_command
        observations = []
        for scheme, port in [("http", 80), ("https", 443)]:
            url = f"{scheme}://{target}:{port}/"
            cmd = [
                "sqlmap", "-u", url,
                "--batch", "--random-agent",
                "--level", "1", "--risk", "1",
                "--time-sec", "3",
                "--forms", "--crawl", "1",
                "--output-dir", "/tmp/skoll_sqlmap",
            ]
            result = run_command(cmd, description=f"sqlmap {url}", timeout=180)
            stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
            if "parameter" in stdout.lower() and "vulnerable" in stdout.lower():
                observations.append({"port": port, "service": scheme, "state": "open", "flags": ["SQLI_DETECTED"]})
        return {"observations": observations} if observations else {}

    def _run_nikto(self, target: str) -> dict[str, Any]:
        from core.run import run_command
        import uuid
        outfile = f"/tmp/skoll_nikto_{uuid.uuid4().hex[:8]}.txt"
        url = f"http://{target}" if not target.startswith("http") else target
        cmd = ["nikto", "-h", url, "-o", outfile, "-Format", "txt", "-Tuning", "123467"]
        result = run_command(cmd, description=f"nikto {url}", timeout=600)
        try:
            with open(outfile) as f:
                output = f.read()
            return {"observations": [{"port": 80, "service": "http", "state": "open", "flags": [], "raw": {"nikto_output": output[:5000]}}]}
        except (FileNotFoundError, PermissionError):
            return {"observations": []}
        finally:
            import os
            try: os.remove(outfile)
            except: pass

    def _run_gobuster(self, target: str) -> dict[str, Any]:
        from skoll_agent.config.wordlists import resolve_wordlist
        from core.run import run_command
        wordlist = resolve_wordlist("web_directories_common")
        url = f"http://{target}" if not target.startswith("http") else target
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "20", "--timeout", "5s"]
        result = run_command(cmd, description=f"gobuster {url}", timeout=300)
        output = (result.get("stdout") or "") + (result.get("stderr") or "")
        observations = []
        for line in output.split("\n"):
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].startswith("/"):
                observations.append({"port": 80, "service": "http", "state": "open", "flags": ["DIR_ENUM"], "raw": {"path": parts[0], "status": parts[1]}})
        return {"observations": observations} if observations else {}
