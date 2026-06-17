from __future__ import annotations

import json
import queue
import re
import textwrap
import time
from typing import Any

from core.agent.tools import TOOL_DESCRIPTIONS, format_tools_for_llm, run_tool
from core.evidence import EvidenceStore, get_campaign_memory
from core.llm import get_llm_router
from core.logging import get_logger
from core.config import get_config

logger = get_logger()
cfg = get_config()

SYSTEM_PROMPT = textwrap.dedent("""\
Eres Skoll, un agente de pentesting autónomo e inteligente.

MISIÓN:
0. FASE OSINT: amass_enum + subfinder_enum + theharvester_collect para mapear superficie
1. crt_lookup + dns_enum para infraestructura expuesta (gratis, sin API key)
2. git_leaks para descubrir filtraciones de código
3. Analiza el target con scan_ports para descubrir servicios
4. Identifica tecnologías y servicios (web, AD, cloud, etc.)
5. Elige un vector de ataque basado en lo que encuentres
6. Ejecuta la herramienta adecuada y evalúa resultados
7. Si falla, cambia de estrategia (pivota). Si acierta, profundiza.
8. Cuando encuentres una vulnerabilidad o agotes vectores, llama a done()

VECTORES DE ATAQUE POR TECNOLOGÍA DETECTADA:

🔹 WEB (puertos 80, 443, 8080, 8443, 3000, 5000):
  - whatweb → identifica tecnologías (WordPress, Apache, Node, etc.)
  - gobuster → descubre rutas (/admin, /api, /ws, /chat, /graphql)
  - fetch_page → extrae WebSockets, forms, endpoints JS del HTML
  - websocket_test → si hay ws:// o wss:// en el HTML
  - sql_injection → si hay formularios o parámetros GET
  - nikto → configuraciones inseguras, cabeceras
  - http_request → prueba endpoints específicos, métodos HTTP

🔹 WEB (React/SPA con APIs):
  - fetch_page → busca endpoints REST/GraphQL en JS
  - http_request → prueba /graphql, /api/v1, /rest
  - custom_script → genera script para probar GraphQL injection
  - ffuf_enum → fuzzing de parámetros y endpoints API
  - nuclei_scan → CVEs y misconfiguraciones en APIs

🔹 WEB (OWASP Top 10 - cuando hay parámetros o formularios):
  - nuclei_scan → escaneo masivo de templates de vulnerabilidad
  - ffuf_enum → fuzzing de directorios y parámetros
  - xss_test → prueba payloads XSS en parámetros
  - sql_injection → sqlmap en parámetros GET/POST
  - commix_test → inyección de comandos en parámetros
  - idor_test → manipulación de IDs numéricos en URLs
  - jwt_attack → análisis de tokens JWT (alg=none, KID, HMAC débil)
  - ssl_scan → Heartbleed, POODLE, cifrados débiles, protocolos

🔹 WEBSOCKET (detectado en HTML o puerto):
  - websocket_test → conecta y prueba inyección en mensajes
  - custom_script → manipulación avanzada (handshake hijacking, ping/pong)

🔹 BASE DE DATOS (puertos 1433, 3306, 5432, 27017):
  - custom_script → script Python con pymongo, psycopg2 para NoSQL/SQL

🔹 SMB (puerto 445):
  - smb_enum → usuarios, shares, OS, null session
  - banner_grab → versión SMB (para EternalBlue, MS17-010)
  - custom_script → script para probar CVE específicos

🔹 LDAP (puertos 389, 636, 3268):
  - ldap_enum → namingContexts, usuarios, grupos, admins
  - Si hay bind anónimo → extraer todo el directorio

🔹 SNMP (puerto 161):
  - snmp_enum → comunidades abiertas, sysDescr, interfaces, procesos
  - Si community es "public" → información sensible del sistema

🔹 BASES DE DATOS (3306 MySQL, 5432 PostgreSQL, 27017 MongoDB, 6379 Redis, 1433 MSSQL):
  - banner_grab → versión exacta
  - custom_script → script Python con librería específica para probar credenciales por defecto

🔹 SSH (puerto 22):
  - banner_grab → versión OpenSSH
  - custom_script → script para probar credenciales comunes o CVE

🔹 FTP (puerto 21):
  - banner_grab → versión vsftpd/proftpd
  - custom_script → anonymous login test

🔹 AD/WINDOWS (puertos 445, 389, 636, 3268, 88):
  - (próximamente) crackmapexec, bloodhound, certipy, impacket

ESTRATEGIA:
- Tras cada herramienta, evalúa los resultados con cuidado
- Si una herramienta no encuentra nada, prueba otra completamente diferente
- Si encuentras algo, profundiza con herramientas más específicas
- NO te rindas después de un intento fallido
- Máximo 15 iteraciones, sé eficiente

FORMATO DE RESPUESTA (obligatorio):
THOUGHT: tu razonamiento aquí
ACTION: nombre_de_herramienta
ARGS: clave=valor, clave=valor
""")

MAX_ITERATIONS = 15


class SkollAgent:
    def __init__(self, progress_queue: queue.Queue | None = None) -> None:
        self.llm = get_llm_router()
        self.evidence_store = EvidenceStore(cfg.evidence_db)
        self.memory = get_campaign_memory()
        self.progress_queue = progress_queue
        self._history: list[dict[str, Any]] = []
        self._findings: list[str] = []

    def _emit(self, typ: str, data: dict | None = None):
        if self.progress_queue is not None:
            self.progress_queue.put({"type": typ, "data": data or {}})

    def run(self, target_raw: str, campaign_id: str = "") -> dict[str, Any]:
        if not campaign_id:
            campaign_id = f"agent_{int(time.time())}"

        target = target_raw.strip()
        self._emit("agent_log", {"message": f"🤖 Iniciando agente inteligente contra {target}"})
        logger.info("agent", f"Iniciando agente para {target}")

        self.memory.create_campaign(campaign_id, target)
        scan = self.memory.start_scan(campaign_id, target)
        scan_run_id = scan["scan_run_id"]

        context = {
            "target": target,
            "history": [],
        }

        for iteration in range(1, MAX_ITERATIONS + 1):
            self._emit("agent_log", {"message": f"🔄 Iteración {iteration}/{MAX_ITERATIONS}"})

            prompt = self._build_prompt(context)
            self._emit("agent_log", {"message": "🧠 Pensando..."})

            response = self.llm.chat(
                prompt=prompt,
                model="llama-3.3-70b-versatile",
                temperature=0.3,
                max_tokens=4000,
                system_prompt=SYSTEM_PROMPT,
            )

            if not response:
                self._emit("agent_log", {"message": "⚠️ LLM no respondió, terminando"})
                break

            thought, action_name, action_args = self._parse_response(response)

            self._emit("agent_log", {"message": f"💭 {thought[:200]}" if thought else "💭 (sin razonamiento)"})

            if action_name == "done":
                self._emit("agent_log", {"message": f"✅ {action_args.get('summary', 'Objetivo completado')}"})
                self._findings.append(action_args.get("summary", ""))
                break

            if not action_name:
                self._emit("agent_log", {"message": "⚠️ No se pudo parsear acción, reintentando"})
                continue

            self._emit("agent_tool_start", {"tool": action_name, "target": target, "params": action_args})
            logger.info("agent", f"Ejecutando {action_name} con args={action_args}")

            tool_result = run_tool(action_name, action_args)

            status = tool_result.get("status", "error")
            result_text = tool_result.get("result", tool_result.get("error", "Sin resultado"))

            step = {
                "iteration": iteration,
                "thought": thought,
                "action": action_name,
                "args": action_args,
                "result": f"[{status}] {result_text[:1500]}",
            }
            context["history"].append(step)
            self._history.append(step)

            self._emit("agent_tool_result", {"tool": action_name, "target": target, "summary": result_text[:200]})

            if "vulnerable" in result_text.lower() or "sqli" in result_text.lower() or "flag{" in result_text.lower():
                self._findings.append(result_text[:500])
                self._emit("agent_log", {"message": "🚩 ¡Posible vulnerabilidad encontrada!"})

        summary_text = self._generate_summary()
        self._emit("agent_log", {"message": f"📊 {summary_text}"})

        report_files = {}
        if self._findings:
            from core.report import ReportGenerator
            report = ReportGenerator(campaign_id, cfg.reports_dir)
            agent_findings = []
            for i, f in enumerate(self._findings):
                if isinstance(f, dict):
                    agent_findings.append(f)
                else:
                    agent_findings.append({"rule_id": f"AGENT-{i}", "title": f[:100], "severity": "high", "host": target, "description": f})
            report_files = report.generate(
                findings=agent_findings,
                campaign_summary={"campaign_id": campaign_id, "target": target, "findings_count": len(self._findings)},
                llm_analysis="\n".join([f if isinstance(f, str) else f.get("title", str(f)) for f in self._findings]),
                scan_target=target,
                hosts=[target],
            )
            self._emit("agent_log", {"message": f"📄 Reporte: {report_files.get('markdown', '')}"})

        self.memory.finish_scan(scan_run_id, len(self._findings))

        self._emit("agent_summary", {"message": summary_text})
        self._emit("agent_complete", {"data": {"result": "ok"}})

        return {
            "campaign_id": campaign_id,
            "target": target,
            "iterations": len(self._history),
            "findings": self._findings,
            "summary": summary_text,
            "report_files": report_files,
        }

    def _build_prompt(self, context: dict) -> str:
        lines = [f"TARGET: {context['target']}", ""]
        lines.append("HISTORIAL:")
        if not context["history"]:
            lines.append("  (ninguno aún - primer análisis)")
        else:
            for h in context["history"]:
                lines.append(f"  Iteración {h['iteration']}:")
                lines.append(f"    Pensaste: {h['thought'][:200]}")
                lines.append(f"    Acción: {h['action']}({h['args']})")
                lines.append(f"    Resultado: {h['result'][:300]}")
                lines.append("")

        lines.append("")
        lines.append(format_tools_for_llm())
        lines.append("")
        lines.append("¿Qué haces ahora? Piensa (THOUGHT) y decide tu próxima ACCIÓN (ACTION) o llama a done() si has terminado.")

        return "\n".join(lines)

    def _parse_response(self, response: str) -> tuple[str, str, dict[str, Any]]:
        thought = ""
        action_name = ""
        action_args: dict[str, Any] = {}

        t_match = re.search(r"THOUGHT:\s*(.+?)(?=ACTION:|$)", response, re.DOTALL)
        if t_match:
            thought = t_match.group(1).strip()

        a_match = re.search(r"ACTION:\s*(\w+)", response)
        if a_match:
            action_name = a_match.group(1).strip().lower()

        args_match = re.search(r"ARGS:\s*(.+)", response, re.DOTALL)
        if args_match:
            args_text = args_match.group(1).strip()
            for kv in re.findall(r"(\w+)\s*=\s*([^,\n]+)", args_text):
                action_args[kv[0]] = kv[1].strip().strip("\"'")

        tool_names = {t["name"] for t in TOOL_DESCRIPTIONS}
        if action_name and action_name not in tool_names:
            for name in tool_names:
                if action_name in name:
                    action_name = name
                    break

        return thought, action_name, action_args

    def _generate_summary(self) -> str:
        if not self._findings:
            return f"Agente completó {len(self._history)} iteraciones. No se encontraron vulnerabilidades."
        return f"Agente completó {len(self._history)} iteraciones. {len(self._findings)} hallazgos."
