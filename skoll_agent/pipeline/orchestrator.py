from __future__ import annotations

import json
import os
import re
import subprocess
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from skoll_agent.brain.context import ProjectContext, context_to_prompt
from skoll_agent.config.agent_config import CONFIG
from skoll_agent.config.skill_registry import get_all_skills, get_skill
from skoll_agent.engines.registry import get_engine
from skoll_agent.memory.session_manager import SessionManager
from skoll_agent.memory.state import AgentState, ActionLog, Finding, Severity, FindingStatus
from skoll_agent.memory.sage import (
    format_sage_context, store_scan_result, recall_context_for_scan,
)
from skoll_agent.skills.skill_registry import get_registry as get_skill_registry
from skoll_agent.knowledge.knowledge_base import get_knowledge_base
from skoll_agent.metasploit.msf_manager import MSFManager
from skoll_agent.sandbox.human_in_loop import HumanInLoop
from skoll_agent.pipeline.models import (
    PhaseId, PhaseStatus, PhaseResult, PipelineState,
    PortInfo, WebInfo, FlagFinding,
)

console = Console()
EventCallback = Callable[[str, dict[str, Any]], None]


TIERS_DIR = Path(__file__).resolve().parent.parent / "tiers"


def _load_tier(name: str) -> str:
    path = TIERS_DIR / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _readable_phase(phase_id: PhaseId) -> str:
    names = {
        PhaseId.RECON: "RECON",
        PhaseId.ENUM: "ENUM",
        PhaseId.VALIDATE: "VALIDATE",
        PhaseId.ANALYZE: "ANALYZE",
        PhaseId.EXPLOIT: "EXPLOIT",
        PhaseId.CHAIN: "CHAIN",
        PhaseId.REPORT: "REPORT",
        PhaseId.COMPLETE: "COMPLETE",
    }
    return names.get(phase_id, phase_id.value.upper())


class PipelineOrchestrator:
    def __init__(
        self,
        target: str,
        is_network: bool = False,
        llm_client: Any = None,
        event_callback: EventCallback | None = None,
        session_id: str | None = None,
    ):
        # Sanitizar target: eliminar esquema http:// https:// para herramientas de red
        raw_target = target
        if is_network:
            target = re.sub(r"^https?://", "", target).rstrip("/")
            if not target:
                target = raw_target
        self.target = target
        self.is_network = is_network
        self.llm = llm_client
        self.event = event_callback
        self.pipeline = PipelineState(target=target, is_network=is_network)
        self.context: ProjectContext | None = None
        self.state = AgentState(project_path=target)
        self.session_mgr = SessionManager()
        self.session_id = session_id or ""
        self.human = HumanInLoop(enabled=CONFIG.human_in_loop)
        self._providers: list[str] = []
        self.msf_manager: MSFManager | None = None

        # Fase 4: chain of custody + cost tracking
        from skoll_agent.report.chain_of_custody import ChainOfCustody
        from skoll_agent.report.cost_tracker import CostTracker
        self._custody = ChainOfCustody(target=target, session_id=session_id or "")
        self._cost_tracker = CostTracker()

        # Asegurar que los directorios de reportes existen
        reports_dir = Path.home() / ".skoll" / "reports"
        costs_dir = Path.home() / ".skoll" / "costs"
        reports_dir.mkdir(parents=True, exist_ok=True)
        costs_dir.mkdir(parents=True, exist_ok=True)

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        if self.event:
            self.event(event_type, data)

    def _emit_log(self, msg: str) -> None:
        self._emit("agent_log", {"message": msg})

    def _emit_finding(self, finding: Finding) -> None:
        self._emit("agent_finding", {
            "id": finding.id,
            "file": finding.file_path,
            "line": finding.line_start,
            "severity": finding.severity.value,
            "title": finding.title,
            "tool": finding.tool,
        })

    def _run_tool(
        self, tool_name: str, target: str, phase: PhaseResult,
        extra: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        self._emit("agent_tool_start", {
            "tool": tool_name, "target": target,
            "params": extra or {},
        })

        engine_cls = get_engine(tool_name)
        engine = engine_cls()
        result = engine.scan(target, **(extra or {}))

        # Fase 4: log to chain of custody
        self._custody.log_tool_result(tool_name, target, extra, result)
        for raw_f in result.findings:
            self._custody.log_finding(raw_f)

        self._emit("agent_tool_result", {
            "tool": tool_name, "target": target,
            "summary": result.summary,
            "raw_output": result.raw_output[:2000],
        })

        phase.raw_outputs[tool_name] = result.raw_output[:5000]

        if not result.success:
            self._emit_log(f"\u26a0\ufe0f {tool_name} en {target}: {result.error}")
            return []

        new_findings: list[dict[str, Any]] = []
        for raw in result.findings:
            f_id = f"{tool_name}-{raw.get('rule_id', '')}-{raw.get('port', '')}-{raw.get('path', '')}".strip("-")
            finding = Finding(
                id=f_id,
                file_path=raw.get("file_path", target),
                line_start=raw.get("line_start", 0),
                line_end=raw.get("line_end", 0),
                severity=Severity.MEDIUM,
                title=raw.get("title", "Unknown"),
                description=raw.get("description", ""),
                tool=tool_name,
                rule_id=raw.get("rule_id", ""),
                status=FindingStatus.OPEN,
            )
            if f_id not in {f.id for f in self.state.findings}:
                self.state.add_finding(finding)
                self._emit_finding(finding)
                new_findings.append(raw)
                phase.findings.append(raw)

        self.pipeline.all_findings.extend(new_findings)
        return new_findings

    def _multi_agent_analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        """11 agentes especializados con modelo fijo + cerebro 70b.

        Cada agente tiene un rol único y un modelo asignado según su capacidad.
        Todos se ejecutan en paralelo vía ModelPool(max_workers=12).
        Los resultados se cruzan por votación: cada finding requiere ≥2 confirmaciones.
        El cerebro (70b) está reservado para funnel, consenso y resolver discrepancias.
        """
        if not self.llm:
            return {}

        ports_str = context.get("ports_str", "")
        cve_str = context.get("cve_str", "")
        web_str = context.get("web_str", "")
        findings_str = context.get("findings_str", "")
        funnel_str = context.get("funnel_str", "")

        from skoll_agent.model_pool import ModelPool
        openrouter_client = None
        if os.environ.get("OPENROUTER_API_KEY"):
            try:
                from skoll.client_openrouter import OpenRouterClient
                openrouter_client = OpenRouterClient()
            except Exception:
                pass
        pool = ModelPool(
            groq_client=self.llm if hasattr(self.llm, "_client") else None,
            openrouter_client=openrouter_client,
        )

        agent_results: dict[str, dict[str, Any]] = {}
        skills_text = ""
        try:
            reg = get_skill_registry()
            extra_kw = f"{ports_str} {web_str} {findings_str}"
            skills_text = reg.skill_context_for_phase("ANALYZE", extra_keywords=extra_kw, max_chars=3000)
        except Exception:
            pass
        kb_context = ""
        try:
            kb = get_knowledge_base()
            search_terms = [p.strip() for p in (web_str + " " + cve_str).split() if len(p.strip()) > 3][:5]
            for term in search_terms:
                results = kb.search(term, limit=2)
                if results:
                    kb_context += f"\n### KB: {term}\n"
                    for r in results:
                        kb_context += f"- {r['title']}: {r['content'][:200]}\n"
        except Exception:
            pass
        base_context = f"""
### Puertos y Servicios
{ports_str or '(ninguno)'}

### CVEs Identificados
{cve_str or '(ninguno)'}

### Servicios Web
{web_str or '(ninguno)'}

### Hallazgos de Herramientas
{findings_str or '(ninguno)'}

{funnel_str}
"""
        if skills_text:
            base_context += f"\n{skills_text}\n"
        if kb_context:
            base_context += f"\n### Knowledge Base Search Results\n{kb_context}\n"

        # 11 agentes especializados con modelo fijo — cerebro 70b reservado
        agents = [
            {
                "name": "web_security",
                "model": "qwen/qwen3-32b",
                "role": "Especialista en seguridad web. Analiza servidores web, aplicaciones, cabeceras, CMS, OWASP Top 10 (XSS, SQLi, SSRF, LFI, RCE).",
                "focus": "Si hay servicios web HTTP/HTTPS, analiza tecnologías, cabeceras de seguridad, directorios, formularios, parámetros. Busca vulnerabilidades OWASP.",
            },
            {
                "name": "network_infra",
                "model": "deepseek-r1-distill-llama-70b",
                "role": "Especialista en infraestructura de red. Analiza puertos, servicios, versiones, fingerprinting y topología.",
                "focus": "Prioriza servicios expuestos, versiones vulnerables, CVEs confirmados, firewalls, y vectores desde red perimetral.",
            },
            {
                "name": "cve_researcher",
                "model": "qwen/qwen3.6-27b",
                "role": "Especialista en investigación de vulnerabilidades. Correlaciona versiones exactas con CVEs y exploits públicos.",
                "focus": "Verifica cada CVE contra la versión exacta del servicio. Determina exploitabilidad real. Filtra CVEs que no aplican.",
            },
            {
                "name": "credential_auditor",
                "model": "mistral/mistral-nemo",
                "role": "Especialista en credenciales y control de acceso. Analiza autenticación, credenciales por defecto, acceso anónimo, fuerza bruta.",
                "focus": "Identifica servicios con autenticación débil, credenciales por defecto (MySQL root/blank, PostgreSQL postgres/postgres, Redis no-auth), accesos anónimos SMB/FTP, vectores de movimiento lateral.",
            },
            {
                "name": "exploit_planner",
                "model": "microsoft/phi-4",
                "role": "Especialista en explotación. Genera planes de ataque concretos con herramientas, comandos y payloads.",
                "focus": "Para cada vulnerabilidad confirmada, genera el comando exacto con la herramienta adecuada (metasploit, sqlmap, hydra, searchsploit). Incluye payloads y opciones.",
            },
            {
                "name": "config_auditor",
                "model": "llama-4-maverick-17b",
                "role": "Especialista en configuración insegura. Analiza malas configuraciones, servicios mal protegidos, información expuesta.",
                "focus": "Busca configuraciones débiles: directorios listables, backup files, información sensible en headers HTTP, servicios en puertos no estándar, cifrado débil.",
            },
            {
                "name": "fp_validator",
                "model": "deepseek/deepseek-chat",
                "role": "Especialista en validación de falsos positivos. Eres escéptico y riguroso — solo confirmas hallazgos con evidencia sólida.",
                "focus": "Para cada hallazgo: ¿tiene suficiente evidencia? ¿podría ser falso positivo del escáner? ¿hay confirmación por múltiples herramientas? Si no, márcalo como FP.",
            },
            {
                "name": "webapp_scanner",
                "model": "llama-4-scout-17b",
                "role": "Especialista en aplicaciones web. Analiza aplicaciones dinámicas, formularios, parámetros, APIs, vulnerabilidades de aplicación.",
                "focus": "Si hay aplicaciones web (CMS, formularios, login, APIs), analiza parámetros GET/POST, autenticación web, sesiones, cookies, vulnerabilidades de aplicación.",
            },
            {
                "name": "lateral_movement",
                "model": "google/gemini-2.0-flash-exp:free",
                "role": "Especialista en movimiento lateral y pivoting. Analiza cómo pasar de un servicio comprometido a otros internos.",
                "focus": "Identifica cadenas de ataque: desde servicio externo → interno → datos sensibles. Busca relaciones entre servicios, puertos que permiten acceso interno, rutas de pivoting.",
            },
            {
                "name": "quick_scanner",
                "model": "gemma2-9b-it",
                "role": "Escáner rápido de superficie. Detecta problemas obvios y low-hanging fruit en segundos.",
                "focus": "Identifica rápidamente: puertos inusuales, servicios sin autenticación, versiones EOL, información expuesta en banners.",
            },
            {
                "name": "extractor",
                "model": "llama-3.1-8b-instant",
                "role": "Extractor de datos estructurados. Parseas output de herramientas y extraes hallazgos en formato JSON.",
                "focus": "Del output de nmap, nikto, gobuster, whatweb, nuclei, extrae: servicios, versiones, tecnologías, directorios, hallazgos.",
            },
        ]

        agent_prompts: dict[str, str] = {}
        for agent in agents:
            is_small = agent["model"] in (
                "gemma2-9b-it", "llama-3.1-8b-instant", "llama-4-scout-17b"
            )
            if is_small:
                agent_prompts[agent["name"]] = f"""{agent['role']}

Contexto:
{base_context}

Como {agent['name']}, responde SOLO JSON:
{{"attack_vector": "...", "vulns": [{{"service": "...", "cve": "...", "description": "..."}}], "risk_rating": "CRITICAL/HIGH/MEDIUM/LOW"}}"""
            else:
                agent_prompts[agent["name"]] = f"""{agent['role']}

{agent['focus']}

## Contexto Actual
{base_context}

## Instrucciones
Como {agent['name']}, analiza desde TU PERSPECTIVA ESPECIALIZADA.
Responde SOLO JSON sin explicaciones:

{{"attack_vector": "...", "vulns": [{{"service": "...", "cve": "...", "description": "...", "confidence": "high/medium/low"}}], "exploit_plan": [{{"step": 1, "action": "...", "tool": "...", "command": "..."}}], "default_creds": ["..."], "risk_rating": "CRITICAL/HIGH/MEDIUM/LOW", "remediation_priority": ["..."]}}"""

        self._emit_log(f"  Lanzando {len(agents)} agentes especializados (cola priorizada + backoff)...")

        # Ordenar por peso: modelos más capaces primero
        from skoll_agent.model_pool import FREE_MODELS
        model_weights = {m["model"]: m["weight"] for m in FREE_MODELS}
        agents_sorted = sorted(agents, key=lambda a: model_weights.get(a["model"], 0), reverse=True)

        model_usage: dict[str, dict[str, str]] = {}

        for agent in agents_sorted:
            agent_name = agent["name"]
            assigned_model = agent["model"]
            resp = pool._query_one(assigned_model, agent_prompts[agent_name], self._cost_tracker)
            if resp:
                parsed = self._parse_json(resp) or {"raw": resp[:300]}
                agent_results[agent_name] = parsed
                model_usage[agent_name] = {"assigned": assigned_model, "used": assigned_model}
                self._emit_log(f"  {agent_name} ({assigned_model}): riesgo {parsed.get('risk_rating', 'N/A')}")
            else:
                resp2, _ = self._llm_analyze(agent_prompts[agent_name])
                parsed = self._parse_json(resp2) or {"raw": resp2[:300]}
                agent_results[agent_name] = parsed
                fallback_model = "llama-3.3-70b-versatile"
                model_usage[agent_name] = {"assigned": assigned_model, "used": fallback_model, "fallback": "rate_limit"}
                self._emit_log(f"  {agent_name} ({assigned_model}→{fallback_model} fallback): riesgo {parsed.get('risk_rating', 'N/A')}")

        # === CEREBRO 70b: Votación y consenso final ===
        import re as _cve_re
        _CVE_PATTERN = _cve_re.compile(r"CVE-\d{4}-\d{4,}", _cve_re.IGNORECASE)
        all_cves: dict[str, list[str]] = {}
        for agent_name, result in agent_results.items():
            for v in result.get("vulns", []):
                cve = v.get("cve", "")
                if cve and _CVE_PATTERN.fullmatch(cve.strip()):
                    all_cves.setdefault(cve.upper(), []).append(agent_name)

        confirmed = {cve for cve, agents_list in all_cves.items() if len(agents_list) >= 2}

        risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        risks = []
        for r in agent_results.values():
            rr = r.get("risk_rating", "MEDIUM").upper()
            if rr in risk_order:
                risks.append(rr)

        if risks:
            from collections import Counter
            risk_counts = Counter(risks)
            most_common_n = risk_counts.most_common(1)[0][1]
            tied = [r for r, c in risk_counts.items() if c == most_common_n]
            if len(tied) == 1:
                final_risk = tied[0]
            else:
                avg_risk_score = sum(risk_order[r] for r in risks) / len(risks)
                final_risk = next(
                    r for r, s in sorted(risk_order.items(), key=lambda x: -x[1])
                    if s <= avg_risk_score
                )
        else:
            final_risk = "MEDIUM"

        best_agent = max(agent_results.keys(), key=lambda a: len(
            [v for v in agent_results[a].get("vulns", [])
             if v.get("cve", "") in confirmed]
        )) if confirmed else "network_infra"
        attack_vector = agent_results.get(best_agent, {}).get("attack_vector", "")

        all_remediation = []
        for r in agent_results.values():
            all_remediation.extend(r.get("remediation_priority", []))
        remediation = list(dict.fromkeys(all_remediation))[:5]

        all_creds = []
        for r in agent_results.values():
            all_creds.extend(r.get("default_creds", []))
        default_creds = list(dict.fromkeys(all_creds))

        consensus: dict[str, Any] = {
            "agents_used": list(agent_results.keys()),
            "agent_results": agent_results,
            "confirmed_cves": list(confirmed),
            "total_cve_mentions": len(all_cves),
            "risk_rating": final_risk,
            "attack_vector": attack_vector,
            "remediation_priority": remediation,
            "default_creds": default_creds,
            "model_usage": model_usage,
        }

        self._emit_log(f"  Cerebro: {len(confirmed)} CVEs confirmados (≥2 agentes), riesgo {final_risk}")
        return consensus

    def _llm_analyze(self, prompt: str) -> tuple[str, str]:
        if not self.llm:
            return "", "none"

        if hasattr(self.llm, "analyze_with_fallback"):
            start = time.time()
            result, model = self.llm.analyze_with_fallback(prompt)
            elapsed = time.time() - start
            # Estimate tokens (avg ~4 chars/token)
            input_tokens = len(prompt) // 4
            output_tokens = len(result) // 4
            self._cost_tracker.record(
                model=model, input_tokens=input_tokens,
                output_tokens=output_tokens, endpoint="analyze_with_fallback",
            )
            return result, model

        if hasattr(self.llm, "groq_client"):
            try:
                start = time.time()
                result = self.llm.analizar_codigo(prompt) if hasattr(self.llm, "analizar_codigo") else (self.llm.analyze(prompt) if hasattr(self.llm, "analyze") else "")
                elapsed = time.time() - start
                input_tokens = len(prompt) // 4
                output_tokens = len(result) // 4
                self._cost_tracker.record(
                    model="main", input_tokens=input_tokens,
                    output_tokens=output_tokens, endpoint="analyze",
                )
                return result, "main"
            except Exception:
                pass

        try:
            if hasattr(self.llm, "analizar_codigo_stream"):
                collected = ""
                for chunk in self.llm.analizar_codigo_stream(prompt):
                    collected += chunk.text if hasattr(chunk, 'text') else str(chunk)
                input_tokens = len(prompt) // 4
                output_tokens = len(collected) // 4
                self._cost_tracker.record(
                    model="main-stream", input_tokens=input_tokens,
                    output_tokens=output_tokens, endpoint="stream",
                )
                return collected, "main-stream"
            result = self.llm.analizar_codigo(prompt)
            input_tokens = len(prompt) // 4
            output_tokens = len(result) // 4
            self._cost_tracker.record(
                model="main", input_tokens=input_tokens,
                output_tokens=output_tokens, endpoint="analyze",
            )
            return result, "main"
        except Exception:
            try:
                if hasattr(self.llm, "analyze_fast"):
                    self._emit_log("\u26a0\ufe0f LLM principal fall\u00f3, usando modelo r\u00e1pido")
                    start = time.time()
                    result = self.llm.analyze_fast(prompt)
                    elapsed = time.time() - start
                    input_tokens = len(prompt) // 4
                    output_tokens = len(result) // 4
                    self._cost_tracker.record(
                        model="fast", input_tokens=input_tokens,
                        output_tokens=output_tokens, endpoint="fast_fallback",
                    )
                    return result, "fast"
            except Exception:
                pass
            return "", "none"

    def _recover_phase(self, phase_id: PhaseId, error: str) -> None:
        recovery = _load_tier("recovery.md")
        self._emit_log(f"\u26a0\ufe0f Error en {_readable_phase(phase_id)}: {error}")
        if self.llm and recovery:
            recovery_prompt = f"""{recovery}

## Current Error
Phase: {_readable_phase(phase_id)}
Error: {error}

## Decision
What action to take? Respond with ONE word: RETRY, SKIP, or ABORT.
If RETRY, include a brief recovery command/approach.
"""
            resp, model = self._llm_analyze(recovery_prompt)
            decision = resp.strip().upper() if resp else "SKIP"
            self._emit_log(f"Recovery decision ({model}): {decision}")
            if decision.startswith("ABORT"):
                raise RuntimeError(f"Pipeline aborted by recovery: {error}")
        else:
            self._emit_log("Recovery: skipping failed phase (no LLM available)")

    def run(self) -> AgentState:
        self._emit_log(f"Iniciando pipeline {'de red' if self.is_network else 'local'} para {self.target}")

        # SAGE recall — check historical context
        if self.is_network:
            sage_ctx = recall_context_for_scan(self.target)
            if sage_ctx:
                sage_text = format_sage_context(self.target)
                self._emit_log(f"\U0001F4DA SAGE: {len(sage_ctx)} sesiones anteriores encontradas")
                self._emit("agent_log", {"message": sage_text[:500]})
            else:
                self._emit_log("\U0001F4DA SAGE: primera vez escaneando este target")

        if self.is_network:
            self.context = ProjectContext(
                root_path=self.target, total_files=0, total_lines=0,
                summary=f"Network target: {self.target}",
            )
        else:
            from skoll_agent.brain.context import index_project
            self.context = index_project(self.target, max_chars=CONFIG.project_max_chars)

        phases = [
            (PhaseId.RECON, self._phase_recon),
            (PhaseId.ENUM, self._phase_enum),
            (PhaseId.VALIDATE, self._phase_validate),
            (PhaseId.ANALYZE, self._phase_analyze),
            (PhaseId.EXPLOIT, self._phase_exploit),
            (PhaseId.CHAIN, self._phase_chain),
            (PhaseId.REPORT, self._phase_report),
            (PhaseId.COMPLETE, self._phase_complete),
        ]

        for phase_id, handler in phases:
            self.pipeline.current_phase = phase_id
            phase = self.pipeline.get_phase(phase_id)
            phase.start()
            readable = _readable_phase(phase_id)
            self._emit_log(f"\n{'='*50}\nFase {readable}\n{'='*50}")
            self.pipeline.iteration += 1
            self.state.iteration = self.pipeline.iteration

            try:
                if self.is_network or phase_id in (
                    PhaseId.RECON, PhaseId.ENUM, PhaseId.VALIDATE, PhaseId.REPORT, PhaseId.COMPLETE
                ):
                    handler()
                else:
                    self._emit_log(f"Fase {readable} requiere LLM — omitiendo en modo headless")
                    phase.skip("Requiere LLM")
                self._custody.log_phase(readable, str(phase.status), phase.summary)
            except Exception as e:
                self._emit("agent_error", {"message": f"Fase {readable} fall\u00f3: {e}"})
                traceback.print_exc()
                phase.fail(str(e))
                self._custody.log_phase(readable, "failed", str(e))
                # Recovery tier on failure
                self._recover_phase(phase_id, str(e))

            # SAGE store after each phase
            if self.is_network:
                try:
                    ports_dict = [
                        {"port": p.port, "protocol": p.protocol, "service": p.service}
                        for p in self.pipeline.open_ports()
                    ]
                    store_scan_result(
                        target=self.target,
                        phase=readable,
                        findings=self.pipeline.all_findings,
                        ports=ports_dict,
                        summary=phase.summary or phase.error or "",
                    )
                except Exception:
                    pass

            self._auto_save()

        self.pipeline.completed = True
        self.state.completed = True
        self._emit("agent_complete", {"reasoning": "Pipeline completado"})
        self._auto_save()
        return self.state

    # === PHASES ===

    def _phase_recon(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.RECON)
        self._emit_log("Fase 0: RECON — Descubrimiento de puertos y servicios")

        # Masscan pre-scan: puertos en segundos
        masscan_ports = None
        try:
            masscan_result = self._run_tool("masscan", self.target, phase, extra={"rate": 50000, "timeout": 60})
            masscan_open = [r.get("port", 0) for r in masscan_result if r.get("port")]
            if masscan_open:
                masscan_ports = ",".join(str(p) for p in sorted(masscan_open))
                self._emit_log(f"  masscan: {len(masscan_open)} puertos abiertos detectados")
        except Exception as e:
            self._emit_log(f"  masscan no disponible: {e}")

        # Naabu primero (más rápido que nmap)
        naabu_extra: dict[str, Any] = {"timeout": 120}
        if masscan_ports:
            naabu_extra["ports"] = masscan_ports
        elif os.environ.get("SKOLL_NAABU_TOP_PORTS"):
            naabu_extra["top_ports"] = os.environ["SKOLL_NAABU_TOP_PORTS"]
        else:
            naabu_extra["top_ports"] = 1000

        naabu_findings = []
        try:
            naabu_findings = self._run_tool("naabu", self.target, phase, extra=naabu_extra)
            if naabu_findings:
                self._emit_log(f"  naabu: {len(naabu_findings)} puertos abiertos detectados")
        except Exception as e:
            self._emit_log(f"  naabu no disponible: {e}")

        naabu_ports = [r.get("port", 0) for r in naabu_findings if r.get("port")]

        # Nmap: solo si naabu no encontró nada (fallback); si encontró, solo versionado rápido
        if not naabu_ports:
            self._emit_log("  naabu no encontró puertos → fallback a nmap completo")
            extra: dict[str, Any] = {"timeout": 600}
            if masscan_ports:
                extra["ports"] = masscan_ports
            elif os.environ.get("SKOLL_NMAP_QUICK_PORTS"):
                extra["ports"] = os.environ["SKOLL_NMAP_QUICK_PORTS"]
        else:
            ports_str = ",".join(str(p) for p in sorted(naabu_ports))
            self._emit_log(f"  naabu encontró {len(naabu_ports)} puertos → nmap solo versionado en: {ports_str}")
            extra = {"timeout": 300, "ports": ports_str}

        findings = self._run_tool("nmap", self.target, phase, extra=extra)

        seen_ports: set[int] = set()
        for raw in findings:
            pnum = raw.get("port", 0)
            if not pnum or pnum in seen_ports:
                continue
            svc = raw.get("service", "")
            if pnum and svc:
                seen_ports.add(pnum)
                port = PortInfo(
                    port=pnum,
                    protocol=raw.get("protocol", "tcp"),
                    service=svc,
                    product=raw.get("product", ""),
                    version=raw.get("version", ""),
                    state=raw.get("state", "open"),
                )
                phase.ports.append(port)
                state_tag = "🔒" if port.state == "filtered" else "🔓"
                self._emit_log(f"  {state_tag} Puerto {pnum}/{raw.get('protocol', 'tcp')}: {svc} {raw.get('product', '')} {raw.get('version', '')} [{port.state}]".strip())

        # Detectar si todos los puertos están filtrados
        open_count = sum(1 for p in phase.ports if p.state == "open")
        filtered_count = sum(1 for p in phase.ports if p.state == "filtered")
        if phase.ports and open_count == 0:
            self._emit_log(f"  ⚠️ TODOS los {len(phase.ports)} puertos están FILTRADOS por firewall")
            self._emit_log(f"  → El target {self.target} tiene un firewall perimetral que bloquea las conexiones")
            self._emit_log(f"  → Las herramientas de enumeración y explotación se saltarán estos puertos")

        # Feedback loop: nmap result puede sugerir más escaneos
        nmap_text = phase.raw_outputs.get("nmap", "")
        if nmap_text:
            self._feedback_loop(phase, "nmap", nmap_text[:3000])

        # WhatWeb en paralelo para todos los puertos HTTP/S
        http_ports = [p for p in phase.ports if p.service.lower() in ("http", "https", "http-proxy", "unknown") and p.state == "open"]
        if http_ports:
            parallel_tools = []
            for port_info in http_ports:
                proto = "https" if port_info.port in (443, 8443) else "http"
                url = f"{proto}://{self.target}:{port_info.port}"
                parallel_tools.append(("whatweb", url, {}))
            self._emit_log(f"  Detectando tecnologías web en {len(http_ports)} puertos (paralelo)")
            web_results = self._parallel_run_tools(parallel_tools, phase)
            for port_info in http_ports:
                # Match web findings to ports
                for wf in web_results:
                    if not wf:
                        continue
                    phase.web.append(WebInfo(
                        url=wf.get("url", f"{'https' if port_info.port in (443, 8443) else 'http'}://{self.target}:{port_info.port}"),
                        title=wf.get("title", ""),
                        tech=wf.get("technologies", []),
                        status=wf.get("status", 0),
                    ))

        phase.complete(f"Descubiertos {len(phase.ports)} puertos, {len(phase.web)} servicios web")

    def _phase_enum(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.ENUM)
        recon = self.pipeline.get_phase(PhaseId.RECON)

        if not recon.ports:
            self._emit_log("Fase 1: ENUM — Sin puertos descubiertos, saltando")
            phase.skip("No hay puertos disponibles")
            return

        # Contar puertos abiertos vs filtrados
        open_ports = [p for p in recon.ports if p.state == "open"]
        filtered_ports = [p for p in recon.ports if p.state == "filtered"]
        if not open_ports and filtered_ports:
            self._emit_log(f"  ⚠️ {len(filtered_ports)} puertos filtrados (firewall). Solo se enumerarán puertos abiertos.")

        self._emit_log("Fase 1: ENUM — Enumeración de servicios")

        parallel_tools: list[tuple[str, str, dict[str, Any]]] = []

        for port_info in recon.ports:
            service = port_info.service.lower()

            # Web services — katana primero (crawling rápido), gobuster como fallback
            if service in ("http", "https", "http-proxy", "unknown") and port_info.state == "open":
                proto = "https" if port_info.port in (443, 8443) else "http"
                url = f"{proto}://{self.target}:{port_info.port}"
                self._emit_log(f"  Web: {url}")
                parallel_tools.append(("katana", url, {"depth": 2}))
                parallel_tools.append(("ffuf", url, {}))
                parallel_tools.append(("nikto", url, {}))
                parallel_tools.append(("nuclei", url, {}))
                # Davtest si es WebDAV o siempre en puertos HTTP
                parallel_tools.append(("davtest", url, {"path": "/"}))

            # FTP
            if service == "ftp" and port_info.state == "open":
                self._emit_log(f"  FTP: {self.target}:{port_info.port}")
                parallel_tools.append(("ftp", self.target, {"port": port_info.port}))

            # SMB — smbmap + smbclient + enum4linux + msfconsole
            if service in ("microsoft-ds", "netbios-ssn") and port_info.state == "open":
                self._emit_log(f"  SMB: {self.target}")
                parallel_tools.append(("smb", self.target, {}))
                parallel_tools.append(("smbmap", self.target, {}))
                parallel_tools.append(("enum4linux", self.target, {}))
                parallel_tools.append((
                    "msfconsole", self.target,
                    {"services": [{"service": "smb", "port": port_info.port}]},
                ))

            # Redis
            if service == "redis" or port_info.port == 6379:
                self._emit_log(f"  Redis: {self.target}:{port_info.port}")
                parallel_tools.append(("redis", self.target, {"port": port_info.port}))

            # MySQL
            if service in ("mysql", "ms-sql-s") or port_info.port == 3306:
                self._emit_log(f"  MySQL: {self.target}:{port_info.port}")
                parallel_tools.append(("mysql", self.target, {"port": port_info.port}))

            # PostgreSQL
            if service in ("postgresql", "postgres") or port_info.port == 5432:
                self._emit_log(f"  PostgreSQL: {self.target}:{port_info.port}")
                parallel_tools.append(("postgres", self.target, {"port": port_info.port}))

        # Ejecutar tools en paralelo
        self._emit_log(f"  Ejecutando {len(parallel_tools)} herramientas en paralelo...")
        self._parallel_run_tools(parallel_tools, phase)

        # Fallback: si katana no encontró nada, ejecutar gobuster
        katana_output = phase.raw_outputs.get("katana", "")
        katana_findings = [f for f in phase.findings if f.get("tool") == "katana"]
        if not katana_findings and katana_output != "skip":
            self._emit_log("  katana no encontró endpoints → fallback a gobuster")
            for port_info in recon.ports:
                service = port_info.service.lower()
                if service in ("http", "https", "http-proxy", "unknown") and port_info.state == "open":
                    proto = "https" if port_info.port in (443, 8443) else "http"
                    url = f"{proto}://{self.target}:{port_info.port}"
                    self._run_tool("gobuster", url, phase, {})
        elif katana_findings:
            self._emit_log(f"  katana encontró {len(katana_findings)} endpoints → gobuster omitido")

        # Feedback loop: revisar resultados de cada tool
        for tool_name in ("gobuster", "katana", "ffuf", "nikto", "nuclei", "ftp", "smbmap", "redis", "mysql", "postgres"):
            raw_out = phase.raw_outputs.get(tool_name, "")
            if raw_out:
                self._feedback_loop(phase, tool_name, raw_out[:2000])

        phase.complete(f"Enumeración completada en {len(recon.ports)} puertos ({len(parallel_tools)} tools)")

    def _phase_validate(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.VALIDATE)
        self._emit_log("Fase 2: VALIDATE — Confirmación de hallazgos")

        # Funnel: clasificar hallazgos como TP/FP/INC
        self._funnel_findings(phase)

        phase.complete(f"Validados {len(self.pipeline.all_findings)} hallazgos")

    def _find_cves(self, open_ports: list[PortInfo]) -> list[dict[str, Any]]:
        services = []
        for p in open_ports:
            if p.product or p.version:
                services.append({
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                })
        if not services:
            return []
        from skoll_agent.engines.cve_engine import CVEEngine
        engine = CVEEngine()
        result = engine.scan("", services=services)
        if result.findings:
            for f in result.findings:
                self.pipeline.add_finding(f)
            return result.findings
        return []

    def _phase_analyze(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.ANALYZE)
        if not self.llm:
            phase.skip("No hay LLM")
            return

        self._emit_log("Fase 3: ANALYZE — Análisis de superficie de ataque")

        open_ports = self.pipeline.open_ports()
        ports_str = "\n".join(
            f"  {p.port}/{p.protocol} {p.service} {p.product} {p.version}".strip()
            for p in open_ports
        )

        # CVE lookup via searchsploit
        cve_results = self._find_cves(open_ports)
        cve_str = "\n".join(
            f"  {f.get('description', '')[:200]}"
            for f in cve_results
        ) if cve_results else "  (sin CVEs conocidos)"

        web_services = self.pipeline.all_web()
        web_str = "\n".join(
            f"  {w.url} — {w.title} [{', '.join(w.tech)}]".strip()
            for w in web_services
        )

        findings_str = "\n".join(
            f"  [{f.get('severity','info')}] {f.get('title','?')}: {f.get('description','')[:200]}"
            for f in self.pipeline.all_findings[-20:]
        )

        # Funnel data (TP/FP/INC) del VALIDATE phase
        validate_phase = self.pipeline.get_phase(PhaseId.VALIDATE)
        funnel_data = validate_phase.metadata.get("funnel", {})
        funnel_str = ""
        if funnel_data:
            tp_list = funnel_data.get("tp", [])
            fp_list = funnel_data.get("fp", [])
            inc_list = funnel_data.get("inc", [])
            tp_str = "\n".join(f"    {f.get('title', '?')}" for f in tp_list[:5])
            funnel_str = (
                f"\n### Funnel — Hallazgos Confirmados (TP={len(tp_list)}, FP={len(fp_list)}, INC={len(inc_list)})\n"
                f"{tp_str}\n"
            )

        context = {
            "ports_str": ports_str,
            "cve_str": cve_str,
            "web_str": web_str,
            "findings_str": findings_str,
            "funnel_str": funnel_str,
        }
        analysis: dict[str, Any] = {}
        try:
            analysis = self._multi_agent_analyze(context)
        except Exception as e:
            self._emit_log(f"\u26a0\ufe0f Error en análisis multi-agente: {e}")

        # Juez independiente (Gemini Flash) — siempre se ejecuta si hay análisis
        try:
            if analysis:
                analysis = self._judge_findings(analysis)
        except Exception as e:
            self._emit_log(f"\u26a0\ufe0f Error en juez Gemini: {e}")

        # Generar resumen en lenguaje natural
        if analysis:
            try:
                attack_vector = analysis.get("attack_vector", "No determinado")
                risk_rating = analysis.get("risk_rating", "MEDIUM")
                agents = analysis.get("agents_used", [])
                confirmed_cves = analysis.get("confirmed_cves", [])
                remediation = analysis.get("remediation_priority", [])
                default_creds = analysis.get("default_creds", [])

                summary_lines = [
                    f"## Análisis Multi-Agente",
                    f"**Riesgo general:** {risk_rating}",
                    f"**Vector de ataque:** {attack_vector}",
                    f"**Agentes participantes:** {', '.join(agents)}",
                ]
                if confirmed_cves:
                    summary_lines.append(f"**CVEs confirmados:** {', '.join(confirmed_cves)}")
                else:
                    summary_lines.append("**CVEs confirmados:** Ninguno")
                if remediation:
                    summary_lines.append("\n**Prioridades de remediación:**")
                    for i, r in enumerate(remediation[:5], 1):
                        summary_lines.append(f"  {i}. {r}")
                if default_creds:
                    summary_lines.append("\n**Credenciales por defecto a probar:**")
                    for c in default_creds[:5]:
                        summary_lines.append(f"  - {c}")

                agent_results = analysis.get("agent_results", {})
                for agent_name, agent_result in agent_results.items():
                    av = agent_result.get("attack_vector", "")
                    rr = agent_result.get("risk_rating", "N/A")
                    summary_lines.append(f"\n---\n### Agente: {agent_name} (riesgo: {rr})")
                    summary_lines.append(f"Vector: {av}")
                    for v in agent_result.get("vulns", [])[:3]:
                        cve = v.get("cve", "")
                        desc = v.get("description", "")[:150]
                        conf = v.get("confidence", "")
                        summary_lines.append(f"  - {cve}: {desc} (confianza: {conf})")
                    for step in agent_result.get("exploit_plan", [])[:2]:
                        action = step.get("action", "")[:100]
                        tool = step.get("tool", "")
                        cmd = step.get("command", "")[:80]
                        summary_lines.append(f"  → {tool}: {action}")
                        summary_lines.append(f"    `{cmd}`")

                readable = "\n".join(summary_lines)

                self._emit("agent_reasoning", {
                    "reasoning": readable,
                    "action": "analyze", "phase": "analyze",
                })
                phase.metadata["llm_analysis"] = analysis
                self._emit_log(f"\U0001F9E0 Vector de ataque: {attack_vector}")
                self._emit_log(f"\U0001F7E2 Riesgo: {risk_rating} ({len(agents)} agentes)")
                if confirmed_cves:
                    self._emit_log(f"\U0001F50D CVEs confirmados: {', '.join(confirmed_cves)}")

                phase.metadata["analysis_summary"] = readable
            except Exception as e:
                self._emit_log(f"\u26a0\ufe0f Error generando resumen: {e}")

        phase.complete("Análisis completado")

    def _extract_discovered_paths(self, port_url: str) -> list[str]:
        """Extrae paths descubiertos por ffuf/gobuster/nikto en ENUM."""
        enum = self.pipeline.get_phase(PhaseId.ENUM)
        paths: list[str] = []
        import re
        for tool_key, raw in enum.raw_outputs.items():
            if port_url in raw or self.target in raw:
                if tool_key.startswith(("gobuster", "ffuf")):
                    for line in raw.split("\n"):
                        parts = line.strip().split()
                        for part in parts:
                            if part.startswith("/") and len(part) > 1:
                                ext = part.rsplit(".", 1)[-1] if "." in part else ""
                                if ext in ("php", "asp", "aspx", "jsp", "py", "pl", "html", "htm", ""):
                                    paths.append(part if part != "/" else "")
                if tool_key.startswith("nikto"):
                    for m in re.finditer(r'/(?:[\w.-]+/)*[\w.-]+\.(?:php|asp|aspx|jsp|py|pl)', raw):
                        p = m.group()
                        if p not in paths:
                            paths.append(p)
        seen = set()
        unique = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique[:20]

    def _phase_exploit(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.EXPLOIT)
        self._emit_log("Fase 4: EXPLOIT — Explotación con recolección de evidencia")

        recon = self.pipeline.get_phase(PhaseId.RECON)
        enum = self.pipeline.get_phase(PhaseId.ENUM)
        previous_findings = list(self.pipeline.all_findings)
        collected_creds: list[dict[str, str]] = []

        # Arrancar msfrpcd para RPC API
        self._emit_log("  Iniciando msfrpcd para RPC...")
        try:
            self.msf_manager = MSFManager()
            self.msf_manager.start()
            if self.msf_manager.get_client():
                self._emit_log("  ✅ msfrpcd conectado vía RPC")
            else:
                self._emit_log("  ⚠️ msfrpcd no disponible, usando subprocess")
        except Exception as e:
            self._emit_log(f"  ⚠️ msfrpcd falló: {e}, usando subprocess")
            self.msf_manager = None

        # ── 1. WEB: sqlmap + nuclei contra cada URL y paths descubiertos ──
        for port_info in recon.ports:
            service = port_info.service.lower()
            if service not in ("http", "https"):
                continue
            proto = "https" if port_info.port in (443, 8443) else "http"
            base_url = f"{proto}://{self.target}:{port_info.port}"

            # sqlmap siempre en URL base
            self._emit_log(f"  sqlmap → {base_url}")
            self._run_tool("sqlmap", base_url, phase, extra={"batch": True})

            # Paths descubiertos por fuzzing
            discovered = self._extract_discovered_paths(base_url)
            if discovered:
                self._emit_log(f"  {len(discovered)} paths descubiertos, lanzando sqlmap contra cada uno")

                # Login pages prioritarias
                login_paths = [p for p in discovered if "login" in p.lower() or "admin" in p.lower()
                               or "signin" in p.lower() or "auth" in p.lower()]
                for lp in login_paths[:3]:
                    login_url = f"{base_url}{lp}"
                    self._emit_log(f"  sqlmap → {login_url} (login)")
                    self._run_tool("sqlmap", login_url, phase, extra={"batch": True})

                # Paths dinámicos (.php, .asp, etc)
                dynamic = [p for p in discovered if any(p.endswith(f".{e}") for e in ("php", "asp", "aspx", "jsp", "py", "pl"))]
                for dp in dynamic[:10]:
                    dyn_url = f"{base_url}{dp}"
                    self._emit_log(f"  sqlmap → {dyn_url}")
                    self._run_tool("sqlmap", dyn_url, phase, extra={"batch": True})

                # nuclei contra paths descubiertos
                for dp in (login_paths + dynamic)[:5]:
                    target_url = f"{base_url}{dp}"
                    self._emit_log(f"  nuclei → {target_url}")
                    self._run_tool("nuclei", target_url, phase, extra={"batch": True})

        # ── 2. AUTH SERVICES: hydra + default creds ──
        for port_info in recon.ports:
            service = port_info.service.lower()
            if service not in ("ssh", "ftp", "telnet", "mysql", "postgresql",
                               "imap", "imaps", "pop3", "pop3s", "smtp", "smtps",
                               "redis", "mongodb"):
                continue
            if port_info.state == "filtered":
                self._emit_log(f"  hydra saltado: {service}://{self.target}:{port_info.port} filtrado")
                continue
            self._emit_log(f"  hydra → {service}://{self.target}:{port_info.port}")
            result = self._run_tool("hydra", self.target, phase, extra={
                "service": service,
                "port": port_info.port,
            })
            if result:
                for f in result:
                    if f.get("username") and f.get("password"):
                        collected_creds.append({
                            "service": service,
                            "port": str(port_info.port),
                            "username": f["username"],
                            "password": f["password"],
                            "target": self.target,
                        })

        # ── 3. CROSS-SERVICE: creds descubiertas → probar en otros servicios ──
        if collected_creds:
            self._emit_log(f"  {len(collected_creds)} credenciales descubiertas, probando en otros servicios...")
            for cred in collected_creds:
                for port_info in recon.ports:
                    svc = port_info.service.lower()
                    if svc in ("ssh", "ftp", "postgresql", "mysql", "redis") and f"{svc}:{port_info.port}" != f"{cred['service']}:{cred['port']}":
                        self._emit_log(f"  reutilizando {cred['username']}:{cred['password']} → {svc}://{self.target}:{port_info.port}")
                        self._run_tool("hydra", self.target, phase, extra={
                            "service": svc,
                            "port": port_info.port,
                            "username": cred["username"],
                            "password": cred["password"],
                        })

        # ── 4. EXPLOIT DISPATCHER + FALLBACK ──
        analyze_phase = self.pipeline.get_phase(PhaseId.ANALYZE)
        analysis = analyze_phase.metadata.get("llm_analysis", {})
        confirmed_cves = analysis.get("confirmed_cves", [])
        if confirmed_cves:
            self._emit_log(f"  Exploit Dispatcher: {len(confirmed_cves)} CVEs confirmados")
            from skoll_agent.engines.exploit_dispatcher import ExploitDispatcher
            dispatcher = ExploitDispatcher()
            ports_dict = [
                {"port": p.port, "service": p.service, "product": p.product, "version": p.version}
                for p in recon.ports
            ]
            tasks = dispatcher.get_tasks(
                self.target,
                confirmed_cves=confirmed_cves,
                ports=ports_dict,
                agent_results=analysis.get("agent_results", {}),
            )
            if tasks:
                self._emit_log(f"  → {len(tasks)} tareas de exploit vía dispatcher")
            for task in tasks:
                self._emit_log(f"  → [{task.get('tool')}] {task.get('description', '')}")
                params = task.get("params", {})
                if task.get("tool") == "cve2msf" and self.msf_manager and self.msf_manager.get_client():
                    params["msf_client"] = self.msf_manager
                self._run_tool(task.get("tool", ""), self.target, phase, extra=params)

            # Fallback: searchsploit + nuclei para CVEs sin módulo
            executed_cves = {t.get("cve", "") for t in tasks}
            unmatched = [c for c in confirmed_cves if c not in executed_cves]
            if unmatched:
                self._emit_log(f"  → {len(unmatched)} CVEs sin módulo — fallback searchsploit/nuclei")
                for cve in unmatched[:5]:
                    try:
                        ss = subprocess.run(
                            ["searchsploit", "--cve", cve, "-j"],
                            capture_output=True, text=True, timeout=30
                        )
                        if ss.returncode == 0 and ss.stdout.strip():
                            ss_data = json.loads(ss.stdout)
                            if ss_data.get("RESULTS_EXPLOIT"):
                                self._emit_log(f"  → searchsploit: {len(ss_data['RESULTS_EXPLOIT'])} exploits para {cve}")
                    except Exception:
                        pass
                    # nuclei template para el CVE
                    self._run_tool("nuclei", self.target, phase, extra={"cve": cve})

        # ── 5. LLM: generar comandos de explotación reales ──
        if self.llm and self.pipeline.all_findings:
            exploit_guidance = _load_tier("exploit-guidance.md") or ""
            new_findings = [f for f in self.pipeline.all_findings
                           if f not in previous_findings] if previous_findings else self.pipeline.all_findings
            if new_findings:
                web_info = self.pipeline.all_web()
                web_summary = "\n".join(f"{w.url} [{w.tech} {w.version}]".strip() for w in web_info[:8]) or "Ninguno"
                findings_json = json.dumps(new_findings[-15:], indent=2, default=str)
                poc_prompt = f"""{exploit_guidance}

Eres un pentester ofensivo. Basado en los hallazgos reales, genera comandos de explotación concretos.

### Target: {self.target}
### Servicios web: 
{web_summary}
### Credenciales descubiertas: {json.dumps(collected_creds, indent=2) if collected_creds else "Ninguna"}
### CVEs confirmados: {json.dumps(confirmed_cves) if confirmed_cves else "Ninguno"}
### Hallazgos:
{findings_json}

Responde SOLO JSON array con comandos de explotación ejecutables:
[{{"tool": "sqlmap|hydra|nuclei|msfconsole|nmap|custom", "url": "...", "params": {{}}, "reason": "...", "expected_output": "..."}}]
Si no hay nada explotable, responde [].
"""
                try:
                    poc_response, model = self._llm_analyze(poc_prompt)
                    pocs = self._parse_json(poc_response) or []
                    if isinstance(pocs, list):
                        phase.metadata["llm_exploit_commands"] = pocs
                        self._emit_log(f"  LLM generó {len(pocs)} comandos de explotación ({model})")
                        for poc in pocs[:5]:
                            tool = poc.get("tool", "")
                            url = poc.get("url", self.target)
                            params = poc.get("params", {})
                            reason = poc.get("reason", "")
                            self._emit_log(f"  → [{tool}] {url}: {reason[:100]}")
                            if tool in ("sqlmap", "nuclei", "hydra", "nmap"):
                                self._run_tool(tool, url, phase, extra=params)
                except Exception as e:
                    self._emit_log(f"\u26a0\ufe0f Error en LLM exploitation: {e}")

        phase.complete(f"Explotación completada — {len(self.pipeline.all_findings)} hallazgos totales")

    def _phase_chain(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.CHAIN)

        self._emit_log("Fase 5: CHAIN — Análisis cruzado de hallazgos (RAPTOR-style)")

        real_sessions: list[dict[str, Any]] = []
        if self.msf_manager:
            try:
                sessions = self.msf_manager.get_sessions()
                if sessions:
                    real_sessions = [
                        {"id": sid, "type": s.get("type", "?"), "target": s.get("target_host", "?"),
                         "via": s.get("via_exploit", "?"), "info": s.get("info", "")}
                        for sid, s in sessions.items()
                    ]
                    self._emit_log(f"  📡 {len(real_sessions)} sesiones activas en Metasploit")
                    for s in real_sessions:
                        self._emit_log(f"    Session #{s['id']}: {s['type']} → {s['target']} via {s['via']}")
                        try:
                            info = self.msf_manager.run_on_session(s["id"], "sysinfo")
                            if info:
                                s["sysinfo"] = info.strip()[:200]
                                self._emit_log(f"      sysinfo: {s['sysinfo']}")
                        except Exception:
                            pass
                else:
                    self._emit_log("  No hay sesiones activas de Metasploit")
            except Exception as e:
                self._emit_log(f"  ⚠️ Error obteniendo sesiones: {e}")

        if self.llm and self.pipeline.all_findings:
            sessions_json = json.dumps(real_sessions, indent=2) if real_sessions else "Ninguna"
            findings_summary = json.dumps(self.pipeline.all_findings[-15:], indent=2, default=str)
            ports_summary = "\n".join(
                f"{p.port}/{p.protocol} {p.service} {p.product} {p.version}".strip()
                for p in self.pipeline.open_ports()
            )
            chain_prompt = f"""Eres un pentester senior analizando resultados de escaneo. Cruza los hallazgos y responde SOLO JSON:

Hallazgos:
{findings_summary}

Puertos:
{ports_summary}

Sesiones Metasploit activas:
{sessions_json}

{{"chains": [{{"name": "...", "attack_flow": ["paso1", "paso2"], "risk": "HIGH/MEDIUM/LOW", "cves": [], "session_ids": []}}], "summary": "...", "remediation_priority": ["..."], "risk_rating": "HIGH/MEDIUM/LOW"}}"""
            try:
                resp, model = self._llm_analyze(chain_prompt)
                parsed = self._parse_json(resp) or {}
                if parsed:
                    parsed["real_sessions"] = real_sessions
                    phase.metadata["chain_analysis"] = parsed
                    risk = parsed.get("risk_rating", "N/A")
                    chains = parsed.get("chains", [])
                    n_chains = len(chains)
                    self._emit_log(f"  Chain: {n_chains} cadenas, riesgo {risk} (modelo: {model})")
                    if real_sessions:
                        self._emit_log(f"  🎯 {len(real_sessions)} sesiones activas disponibles para post-explotación")
            except Exception as e:
                self._emit_log(f"\u26a0\ufe0f Error en análisis cruzado: {e}")

        n_chains = len(phase.metadata.get("chain_analysis", {}).get("chains", [])) if phase.metadata.get("chain_analysis") else 0
        phase.complete(f"Análisis cruzado: {n_chains} cadenas de ataque, {len(real_sessions)} sesiones reales, {len(self.pipeline.all_findings)} hallazgos totales")

    def _msf_search_cve(self, cve_id: str) -> bool:
        """Verifica si Metasploit tiene un módulo para el CVE (RPC primero, fallback subprocess)."""
        if self.msf_manager:
            try:
                result = self.msf_manager.search_cve(cve_id)
                if result:
                    self._emit_log(f"  ✅ {cve_id} → módulo encontrado vía RPC: {result['module']}")
                    return True
            except Exception:
                pass
        cve_num = cve_id.replace("CVE-", "").strip()
        try:
            result = subprocess.run(
                ["msfconsole", "-q", "-c", f"search cve:{cve_num}; exit"],
                capture_output=True, text=True, timeout=60,
            )
            output = result.stdout + result.stderr
            if "exploit/" in output or "auxiliary/" in output or "payload/" in output:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        try:
            ss = subprocess.run(
                ["searchsploit", "--cve", cve_id, "--json"],
                capture_output=True, text=True, timeout=30,
            )
            if ss.returncode == 0:
                data = json.loads(ss.stdout)
                entries = data.get("RESULTS_EXPLOIT", data.get("RESULTS", []))
                return len(entries) > 0
        except Exception:
            pass
        return False

    def _phase_report(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.REPORT)
        self._emit_log("Fase 6: REPORT — Generando reporte profesional + evidencia")

        # Filtrar solo CVEs con módulo en Metasploit
        analyze_phase = self.pipeline.get_phase(PhaseId.ANALYZE)
        analysis = analyze_phase.metadata.get("llm_analysis", {})
        all_confirmed_cves = analysis.get("confirmed_cves", [])
        exploitable_cves: list[str] = []
        if all_confirmed_cves:
            self._emit_log(f"  Verificando {len(all_confirmed_cves)} CVEs contra Metasploit...")
            for cve in all_confirmed_cves:
                if self._msf_search_cve(cve):
                    exploitable_cves.append(cve)
                    self._emit_log(f"  ✅ {cve} → tiene módulo en Metasploit")
                else:
                    self._emit_log(f"  ❌ {cve} → sin módulo (excluido del reporte)")

        # Filtrar hallazgos: solo los que corresponden a CVEs explotables
        if exploitable_cves:
            filtered = []
            for f in self.pipeline.all_findings:
                title = f.get("title", "")
                desc = f.get("description", "")
                combined = title + " " + desc
                if any(cve in combined for cve in exploitable_cves):
                    filtered.append(f)
            if filtered:
                self._emit_log(f"  {len(filtered)} hallazgos corresponden a CVEs explotables (de {len(self.pipeline.all_findings)} totales)")
                report_findings = filtered
            else:
                report_findings = self.pipeline.all_findings
        else:
            report_findings = []

        by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in report_findings:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        overall_risk = "CRITICAL" if by_severity["critical"] > 0 else (
            "HIGH" if by_severity["high"] > 0 else (
                "MEDIUM" if by_severity["medium"] > 0 else "LOW"
            )
        )

        # Analysis summary del ANALYZE phase
        analyze_phase = self.pipeline.get_phase(PhaseId.ANALYZE)
        analysis_summary = analyze_phase.metadata.get("analysis_summary", "")

        # Hallazgos críticos/altos
        critical_high = [
            f for f in report_findings
            if f.get("severity", "info").lower() in ("critical", "high")
        ]

        report_lines = [
            "# Skoll Security Assessment — Informe de Auditoría",
            f"**Cliente:** {self.target}",
            f"**Fecha:** {datetime.now(timezone.utc).isoformat()}",
            f"**Hallazgos con exploit confirmado:** {len(report_findings)} (de {len(self.pipeline.all_findings)} totales)",
            f"**Riesgo general:** {overall_risk}",
            "",
            "---",
            "## Resumen Ejecutivo",
            "",
            f"Se identificaron **{len(self.pipeline.all_findings)}** hallazgos de seguridad en el target {self.target}. "
            f"De ellos, **{len(report_findings)}** tienen un módulo de explotación confirmado en Metasploit y se detallan en este informe.",
            "",
            "| Severidad | Cantidad |",
            "|-----------|----------|",
            f"| Crítico   | {by_severity['critical']} |",
            f"| Alto      | {by_severity['high']} |",
            f"| Medio     | {by_severity['medium']} |",
            f"| Bajo      | {by_severity['low']} |",
            f"| Informativo | {by_severity['info']} |",
        ]

        # Listar críticos/altos con nombre y descripción
        if critical_high:
            report_lines.extend([
                "",
                "### Hallazgos Críticos y de Alta Severidad",
            ])
            for f in critical_high:
                sev = f.get("severity", "info").upper()
                tool = f.get("tool", "?")
                title = f.get("title", "?")
                desc = f.get("description", "")[:200]
                port = f.get("port", "")
                port_str = f" (puerto {port})" if port else ""
                report_lines.append(f"- **[{sev}]** [{tool}]{port_str} **{title}**: {desc}")

        # Resumen del análisis multi-agente
        if analysis_summary:
            report_lines.extend([
                "",
                "---",
                "## Resumen del Análisis Multi-Agente",
                "",
                analysis_summary,
            ])

        # Model usage / reliability
        model_usage = analyze_phase.metadata.get("llm_analysis", {}).get("model_usage", {})
        if model_usage:
            fallbacks = [name for name, m in model_usage.items() if m.get("fallback")]
            all_ok = len(fallbacks) == 0
            report_lines.extend([
                "",
                "### Fiabilidad de Modelos",
                f"**Estado:** {'✅ Todos los agentes usaron su modelo asignado' if all_ok else f'⚠️ {len(fallbacks)} agente(s) hicieron fallback'}",
                "",
                "| Agente | Modelo Asignado | Modelo Usado | Estado |",
                "|--------|----------------|-------------|--------|",
            ])
            for agent_name in sorted(model_usage.keys()):
                m = model_usage[agent_name]
                assigned = m.get("assigned", "?")
                used = m.get("used", "?")
                status = "✅" if assigned == used else "⚠️ fallback"
                report_lines.append(f"| {agent_name} | {assigned} | {used} | {status} |")

        # Remediation
        chain_analysis = self.pipeline.get_phase(PhaseId.CHAIN).metadata.get("chain_analysis", {})
        if chain_analysis.get("remediation_priority"):
            report_lines.extend([
                "",
                "### Prioridades de Remediación",
            ])
            for i, r in enumerate(chain_analysis["remediation_priority"][:5], 1):
                report_lines.append(f"{i}. {r}")

        report_lines.extend([
            "",
            "---",
            "## Hallazgos Técnicos Detallados",
        ])

        for idx, f in enumerate(report_findings, 1):
            report_lines.extend([
                "",
                f"### Finding #{idx}: {f.get('title', '?')}",
                f"**Severidad:** {f.get('severity', 'info').upper()}",
                f"**Herramienta:** {f.get('tool', '?')}",
                f"**Descripción:** {f.get('description', '')[:500]}",
            ])
            if f.get("port"):
                report_lines.append(f"**Puerto:** {f.get('port')}/{f.get('protocol', 'tcp')}")

        report_lines.extend([
            "",
            "---",
            f"## Puertos y Servicios Descubiertos ({len(self.pipeline.open_ports())})",
        ])
        for p in self.pipeline.open_ports():
            report_lines.append(f"- {p.port}/{p.protocol} {p.service} {p.product} {p.version}".strip())

        report_lines.append("")
        report_lines.append("---")
        report_lines.append("*Generado por Skoll Pipeline — Metodología PTES/OWASP*")

        report = "\n".join(report_lines)
        self._emit("agent_summary", {
            "project": self.target,
            "total_findings": len(report_findings),
            "filtered_total": len(self.pipeline.all_findings),
            "critical_high": by_severity["critical"] + by_severity["high"],
            "iterations": self.pipeline.iteration,
            "overall_risk": overall_risk,
            "exploitable_cves": exploitable_cves,
        })

        # PDF report generation
        try:
            from skoll_agent.report.report_generator import ReportGenerator
            gen = ReportGenerator(self.pipeline, self.target, self.session_id)
            pdf_path = gen.generate_pdf()
            self._emit_log(f"\U0001F4C4 Reporte PDF: {pdf_path}")
            phase.metadata["pdf_path"] = pdf_path
        except ImportError:
            self._emit_log("  ReportGenerator no disponible, reporte en markdown")
        except Exception as e:
            self._emit_log(f"  \u26a0\ufe0f PDF fall\u00f3: {e}")

        # Chain of custody export
        try:
            custody = getattr(self, "_custody", None)
            if custody:
                md = custody.export_markdown()
                reports_dir = os.path.expanduser("~/.skoll/reports")
                os.makedirs(reports_dir, exist_ok=True)
                safe_target = self.target.replace(".", "_").replace(":", "_")
                custody_path = os.path.join(
                    reports_dir, f"custody_{safe_target}_{self.session_id or 'final'}.md"
                )
                with open(custody_path, "w") as f:
                    f.write(md)
                self._emit_log(f"\U0001F4DD Cadena de custodia: {custody_path}")
                phase.metadata["custody_path"] = custody_path
        except Exception as e:
            self._emit_log(f"  \u26a0\ufe0f Custodia fall\u00f3: {e}")

        # Cost tracking save
        try:
            tracker = getattr(self, "_cost_tracker", None)
            if tracker:
                safe = self.target.replace(".", "_").replace(":", "_")
                cost_path = tracker.save(f"{safe}_{self.session_id or 'final'}")
                self._emit_log(f"  Costos guardados: {cost_path}")
                phase.metadata["cost_path"] = cost_path
        except Exception as e:
            self._emit_log(f"  \u26a0\ufe0f Cost tracking fall\u00f3: {e}")

        phase.complete(report)

    def _phase_complete(self) -> None:
        phase = self.pipeline.get_phase(PhaseId.COMPLETE)
        self._emit_log("Fase 7: COMPLETE — Pipeline finalizado")
        if self.msf_manager:
            self._emit_log("  Deteniendo msfrpcd...")
            try:
                self.msf_manager.stop()
                self._emit_log("  ✅ msfrpcd detenido")
            except Exception as e:
                self._emit_log(f"  ⚠️ Error deteniendo msfrpcd: {e}")
        phase.complete("Pipeline completado exitosamente")

    # === HELPERS ===

    def _parse_json(self, text: str) -> dict[str, Any] | None:
        import re
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if json_match:
            raw = json_match.group(1).strip()
        else:
            brace_start = text.find("{")
            brace_end = text.rfind("}")
            if brace_start != -1 and brace_end > brace_start:
                raw = text[brace_start:brace_end + 1]
            else:
                return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    # === FASE 3: RAPTOR ===

    def _parallel_run_tools(
        self, tools: list[tuple[str, str, dict[str, Any]]], phase: PhaseResult,
    ) -> list[list[dict[str, Any]]]:
        """Ejecuta herramientas independientes en paralelo usando ThreadPoolExecutor."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run(tool_name: str, target: str, extra: dict[str, Any]) -> list[dict[str, Any]]:
            return self._run_tool(tool_name, target, phase, extra=extra)

        results: list[list[dict[str, Any]]] = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(_run, name, tgt, ext): (name, tgt)
                for name, tgt, ext in tools
            }
            for future in as_completed(futures):
                tool_name, tgt = futures[future]
                try:
                    results.extend(future.result())
                except Exception as e:
                    self._emit_log(f"  \u26a0\ufe0f {tool_name} en {tgt} fall\u00f3: {e}")
        return results

    def _sanitize_for_llm(self, text: str, max_chars: int = 4000) -> str:
        """Prompt defense: sanitiza output de herramientas antes de pasarlo al LLM."""
        import re
        sanitized = text[:max_chars]
        sanitized = re.sub(r"(?i)(api[_-]?key|secret|token|password|passwd|auth)[=:]\s*\S+", r"\1=***", sanitized)
        sanitized = re.sub(r"gsk_[A-Za-z0-9_-]{40,}", "gsk_***", sanitized)
        sanitized = re.sub(r"[A-Za-z0-9]{40,}", "<hash>", sanitized)
        return sanitized

    def _funnel_findings(self, phase: PhaseResult) -> None:
        """Fase 3: Funnel — clasifica hallazgos como TP/FP/INC usando el modelo principal (70b)."""
        if not self.llm or not self.pipeline.all_findings:
            return
        import json
        self._emit_log("  Funnel: clasificando hallazgos (TP/FP/INC) con modelo principal...")
        findings_batch = self.pipeline.all_findings[-20:]
        funneled = {"tp": [], "fp": [], "inc": []}

        for raw in findings_batch:
            f_str = json.dumps(raw, default=str)[:800]
            tool = raw.get("tool", "?")
            title = raw.get("title", "?")
            desc = raw.get("description", "")[:200]
            # Skip generic/new finding types that are always TP (open ports, service info)
            if tool in ("nmap", "masscan") and raw.get("port"):
                # Open ports are always TP — they exist
                funneled["tp"].append(raw)
                continue
            prompt = f"""Eres un pentester senior validando hallazgos de seguridad. Regla general: los escáneres automatizados generan falsos positivos, pero un pentester experto sabe cuándo un hallazgo es real.

Clasifica este hallazgo como:
- TP (True Positive): Es un hallazgo VÁLIDO y relevante para la auditoría
- FP (False Positive): Falso positivo, no relevante
- INC (Inconclusive): Requiere verificación manual adicional

Tool: {tool}
Title: {title}
Description: {desc}
Details: {f_str}

Responde SOLO con TP, FP, o INC. Sin explicación."""

            try:
                resp, model = self.llm.analyze_with_fallback(prompt) if hasattr(self.llm, "analyze_with_fallback") else ("INC", "none")
                decision = resp.strip().upper()
                if decision.startswith("TP"):
                    funneled["tp"].append(raw)
                elif decision.startswith("FP"):
                    funneled["fp"].append(raw)
                else:
                    funneled["inc"].append(raw)
            except Exception:
                funneled["inc"].append(raw)

        phase.metadata["funnel"] = funneled
        self._emit_log(f"  Funnel: {len(funneled['tp'])} TP, {len(funneled['fp'])} FP, {len(funneled['inc'])} INC")

    def _judge_findings(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Juez independiente con Gemini Flash (Google AI Studio directo).

        Evalúa los hallazgos del multi-agente y determina si son reales o falsos positivos.
        Es un modelo de Google, completamente independiente de Groq/OpenRouter,
        lo que lo hace ideal como juez imparcial.
        """
        if not analysis:
            return analysis

        from skoll_agent.model_pool import _get_google_client
        judge = _get_google_client()
        if not judge:
            return analysis

        confirmed_cves = analysis.get("confirmed_cves", [])
        risk_rating = analysis.get("risk_rating", "MEDIUM")
        attack_vector = analysis.get("attack_vector", "")
        agent_results = analysis.get("agent_results", {})

        # Construir resumen para el juez
        summary_lines = [
            "## Hallazgos de Auditoría de Seguridad",
            f"Riesgo general: {risk_rating}",
            f"Vector de ataque: {attack_vector}",
            f"CVEs confirmados: {', '.join(confirmed_cves) if confirmed_cves else 'Ninguno'}",
            "",
            "### Hallazgos por agente:",
        ]
        for agent_name, result in agent_results.items():
            vulns = result.get("vulns", [])
            rr = result.get("risk_rating", "N/A")
            summary_lines.append(f"\n---\nAgente: {agent_name} (riesgo: {rr})")
            for v in vulns[:3]:
                cve = v.get("cve", "")
                desc = v.get("description", "")[:200]
                conf = v.get("confidence", "N/A")
                summary_lines.append(f"  CVE: {cve} | {desc} | confianza: {conf}")

        summary = "\n".join(summary_lines)

        try:
            self._emit_log("  Juez (Gemini Flash): validando hallazgos...")
            verdict_raw = judge.judge(summary)
            parsed = self._parse_json(verdict_raw)
            if parsed:
                verdict = parsed.get("veredicto", "")
                razon = parsed.get("razon", "")
                confianza = parsed.get("confianza", "media")
                self._emit_log(f"  Juez: {verdict} (confianza: {confianza})")
                self._emit_log(f"  Razón: {razon[:200]}")
                analysis["judge_verdict"] = verdict
                analysis["judge_reason"] = razon
                analysis["judge_confidence"] = confianza
            else:
                self._emit_log(f"  Juez: respuesta no parseable, ignorando")
        except Exception as e:
            self._emit_log(f"  Juez no disponible: {e}")

        return analysis

    def _llm_consensus(self, phase: PhaseResult, prompt: str) -> dict[str, Any]:
        """Fase 3: Multi-model consensus — corre 70b y 32b, cruza resultados."""
        self._emit_log("  Consensus: ejecutando an\u00e1lisis multi-modelo...")
        responses: dict[str, str] = {}

        # Modelo principal (70b)
        if self.llm:
            try:
                if hasattr(self.llm, "analyze_with_fallback"):
                    resp, model = self.llm.analyze_with_fallback(prompt)
                    responses[model] = resp
                elif hasattr(self.llm, "analizar_codigo_stream"):
                    collected = ""
                    for chunk in self.llm.analizar_codigo_stream(prompt):
                        collected += chunk.text if hasattr(chunk, 'text') else str(chunk)
                    responses["main-stream"] = collected
                else:
                    responses["main"] = self.llm.analizar_codigo(prompt)
            except Exception as e:
                self._emit_log(f"  \u26a0\ufe0f 70b fall\u00f3: {e}")

        # Modelo de consenso (32b via Groq) si está disponible
        if self.llm and hasattr(self.llm, "groq_client"):
            try:
                from groq import Groq
                client = self.llm.groq_client
                start = time.time()
                completion = client.chat.completions.create(
                    model="qwen/qwen3-32b",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=2000,
                )
                elapsed = time.time() - start
                resp = completion.choices[0].message.content or ""
                usage = completion.usage or None
                if usage:
                    self._cost_tracker.record(
                        model="qwen/qwen3-32b",
                        input_tokens=usage.prompt_tokens or 0,
                        output_tokens=usage.completion_tokens or 0,
                        endpoint="consensus_32b",
                    )
                if resp:
                    responses["32b-qwen"] = resp
                    self._emit_log("  Consensus: qwen3-32b respondi\u00f3")
            except Exception:
                self._emit_log("  \u26a0\ufe0f 32b no disponible, usando solo 70b")

        # Cruzar resultados
        consensus: dict[str, Any] = {"models_used": list(responses.keys())}
        model_results = {}
        for model_name, resp in responses.items():
            parsed = self._parse_json(resp) or {"raw": resp[:500]}
            model_results[model_name] = parsed

        consensus["model_results"] = model_results

        if len(responses) >= 2:
            main = model_results.get(list(responses.keys())[0], {})
            secondary = model_results.get(list(responses.keys())[1], {})
            consensus["agreement"] = main == secondary
            consensus["attack_vector"] = main.get("attack_vector", secondary.get("attack_vector", ""))
            consensus["risk_rating"] = main.get("risk_rating", secondary.get("risk_rating", "MEDIUM"))
            vulns_main = set(v.get("cve", "") for v in main.get("vulns", []) if v.get("cve"))
            vulns_sec = set(v.get("cve", "") for v in secondary.get("vulns", []) if v.get("cve"))
            consensus["confirmed_cves"] = list(vulns_main & vulns_sec)
            consensus["total_vulns_main"] = len(vulns_main)
            consensus["total_vulns_sec"] = len(vulns_sec)
        elif responses:
            main = model_results.get(list(responses.keys())[0], {})
            consensus["attack_vector"] = main.get("attack_vector", "")
            consensus["risk_rating"] = main.get("risk_rating", "MEDIUM")
            consensus["confirmed_cves"] = [v.get("cve", "") for v in main.get("vulns", []) if v.get("cve")]

        phase.metadata["consensus"] = consensus
        self._emit_log(f"  Consensus: {len(responses)} modelo(s), CVEs confirmados: {len(consensus.get('confirmed_cves', []))}")
        return consensus

    def _feedback_loop(self, phase: PhaseResult, tool_name: str, result_text: str) -> None:
        """Fase 3: Feedback loop — analiza resultado de tool y decide siguiente acción."""
        if not self.llm or not result_text:
            return
        import re as _re
        sanitized = self._sanitize_for_llm(result_text, 3000)

        # Lista de tools que solo aceptan IPs, no URLs
        _IP_TOOLS = {"nmap", "masscan", "hydra", "ftp", "smb", "smbmap", "enum4linux", "redis", "mysql", "postgres"}
        # Tools que ya se ejecutaron en este phase — evitar duplicados
        _already_run = set(phase.raw_outputs.keys())

        prompt = f"""Eres un pentester en un pipeline autónomo. Acaba de ejecutarse {tool_name} y este es el resultado:

{sanitized}

Analiza el resultado y decide si es necesario ejecutar alguna herramienta adicional. Responde JSON:

{{"next_steps": [{{"tool": "...", "reason": "...", "target": "...", "params": {{}}}}], "findings_already_covered": true/false, "critical_hit": true/false}}

Si no se necesita nada más, devuelve next_steps: [].
Si se detecta un hallazgo crítico (credenciales expuestas, RCE posible), marca critical_hit: true.

IMPORTANTE:
- Para herramientas como nmap, hydra, ftp, smb, smbmap, el target debe ser solo IP, no URL.
- NO sugerir herramientas que ya se ejecutaron en esta fase: {', '.join(_already_run) or 'ninguna'}.
- NO sugerir nmap a menos que sea absolutamente necesario (ya se ejecutó en RECON)."""
        try:
            resp, _ = self._llm_analyze(prompt) if hasattr(self, "_llm_analyze") else ("", "none")
            parsed = self._parse_json(resp) or {}
            next_steps = parsed.get("next_steps", [])
            if next_steps:
                self._emit_log(f"  Feedback loop: {len(next_steps)} paso(s) adicional(es)")
                from skoll_agent.engines.registry import get_engine
                for step in next_steps:
                    tool = step.get("tool", "")
                    tgt = self.target
                    params = step.get("params", {})
                    reason = step.get("reason", "")
                    # Saltar si ya se ejecutó
                    if tool in _already_run:
                        self._emit_log(f"    (saltado: {tool} ya ejecutado)")
                        continue
                    # Validar que el engine existe
                    try:
                        get_engine(tool)
                    except Exception:
                        self._emit_log(f"    (saltado: {tool} — engine no disponible)")
                        continue
                    step_target = step.get("target", "")
                    if tool in _IP_TOOLS:
                        ip_match = _re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", step_target)
                        if ip_match:
                            tgt = ip_match.group(1)
                    self._emit_log(f"    -> {tool} en {tgt}: {reason}")
                    self._run_tool(tool, tgt, phase, extra=params)
            if parsed.get("critical_hit"):
                self._emit_log(f"  \U0001F6A8 Feedback: hallazgo cr\u00edtico en {tool_name}")
                phase.metadata["critical_hit"] = True
        except Exception as e:
            self._emit_log(f"  \u26a0\ufe0f Feedback loop error: {e}")

    def _auto_save(self) -> None:
        try:
            self.session_id = self.session_mgr.save(
                self.state, None, session_id=self.session_id or None,
                target=self.target,
                phase=self.pipeline.current_phase.value if self.pipeline else "init",
            )
        except Exception:
            pass
