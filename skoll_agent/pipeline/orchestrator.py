from __future__ import annotations

import json
import os
import subprocess
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from skoll_agent.config.agent_config import CONFIG
from skoll_agent.engines.registry import get_engine
from skoll_agent.memory.session_manager import SessionManager
from skoll_agent.memory.state import AgentState, Finding, Severity, FindingStatus
from skoll_agent.pipeline.state_store import StateStore
from skoll_agent.pipeline.adaptive_router import AdaptiveRouter, PhasePlan
from skoll_agent.utils.dependency_checker import DependencyChecker

console = Console()
EventCallback = Callable[[str, dict[str, Any]], None]


class PipelineOrchestrator:
    """Adaptive 4-phase pipeline: recon → analyze → exploit → report.

    Uses:
      StateStore          – persist/ resume state per target
      AdaptiveRouter      – decide which tools to run based on context
      DependencyChecker   – skip missing tools gracefully
      engines via registry – actual tool execution
    """

    PHASES = ["recon", "analyze", "exploit", "report"]

    def __init__(
        self,
        target: str,
        is_network: bool = False,
        llm_client: Any = None,
        event_callback: EventCallback | None = None,
        session_id: str | None = None,
        resume: bool = False,
    ):
        from urllib.parse import urlparse
        raw = target
        if is_network:
            if "://" not in target:
                target = "//" + target
            parsed = urlparse(target)
            if parsed.hostname:
                target = parsed.hostname
            if not target:
                target = raw
        self.target = target
        self.is_network = is_network
        self.llm = llm_client
        self.event = event_callback
        self.store = StateStore(target, session_id=session_id or "")
        self.router = AdaptiveRouter()
        self.deps = DependencyChecker()
        self.session_id = session_id or ""
        self.resume = resume

        # Backward-compat: reports / cost directories
        reports_dir = Path.home() / ".skoll" / "reports"
        costs_dir = Path.home() / ".skoll" / "costs"
        reports_dir.mkdir(parents=True, exist_ok=True)
        costs_dir.mkdir(parents=True, exist_ok=True)

        # Backward-compat: chain of custody + cost tracker
        from skoll_agent.report.chain_of_custody import ChainOfCustody
        from skoll_agent.report.cost_tracker import CostTracker
        self._custody = ChainOfCustody(target=target, session_id=self.session_id)
        self._cost_tracker = CostTracker()
        self._llm_analysis_done = False

    # ── public API ──────────────────────────────────────────────

    def run(self) -> AgentState:
        self._emit_log(f"Pipeline adaptivo iniciado para {self.target}")
        self._emit_log(self.deps.health_summary())

        # Resume: skip completed phases
        start_phase = self.PHASES[0]
        if self.resume:
            resumed = self.store.resume_from()
            if resumed is None:
                self._emit_log("Pipeline ya completado para este target.")
                return self._build_agent_state()
            if resumed != self.PHASES[0]:
                self._emit_log(f"Reanudando desde fase: {resumed}")
                start_phase = resumed

        started = False
        for phase_name in self.PHASES:
            if not started and phase_name != start_phase:
                continue
            started = True

            self._emit_log(f"\n{'='*50}\nFase: {phase_name.upper()}\n{'='*50}")

            # Load context from state store
            state = self.store.load()
            context = state.get("context", {})
            context["target_ip"] = self.target

            # Check if phase should be skipped
            skip, reason = self.router.should_skip(phase_name, context)
            if skip:
                self._emit_log(f"  Saltando: {reason}")
                self.store.mark_completed(phase_name, f"Skipped: {reason}", 0)
                continue

            # Get the execution plan
            plan = self.router.route(phase_name, context)
            if not plan.tools:
                self._emit_log("  Sin herramientas que ejecutar")
                self.store.mark_completed(phase_name, "No tools to run", 0)
                continue

            # Filter available tools (graceful degradation)
            available, skipped = self._filter_plan(plan)
            if skipped:
                self._emit_log(f"  Herramientas no disponibles: {', '.join(skipped)}")
            if not available:
                self._emit_log("  Ninguna herramienta disponible")
                self.store.mark_completed(
                    phase_name, "No available tools", 0,
                    error=f"Missing: {', '.join(skipped)}" if skipped else "",
                )
                continue

            # Execute phase
            self._emit_log(f"  Ejecutando {len(available)} herramientas...")
            self.store.mark_started(phase_name)
            findings: list[dict] = []
            phase_errors: list[str] = []

            for tool_plan in available:
                result: list[dict] = []
                try:
                    result = self._run_tool(tool_plan.tool_name, self.target, tool_plan.params)
                except Exception as e:
                    msg = f"{tool_plan.tool_name}: {e}"
                    self._emit_log(f"  ⚠️ {msg}")
                    phase_errors.append(msg)
                findings.extend(result)

                # Try fallback if primary produced no findings
                if not result and plan.fallback:
                    fb = plan.fallback.pop(0)
                    if self.deps.check_all().get(fb.tool_name):
                        self._emit_log(f"  Fallback → {fb.tool_name}")
                        try:
                            result = self._run_tool(fb.tool_name, self.target, fb.params)
                            findings.extend(result)
                        except Exception as e:
                            self._emit_log(f"  ⚠️ fallback {fb.tool_name}: {e}")

            # Update context and persist
            self._update_context(context, phase_name, findings)
            self.store.update_context("findings_count", len(context.get("findings", [])))
            if "open_ports" in context:
                self.store.update_context("open_ports", context["open_ports"])
            if "web_services" in context:
                self.store.update_context("web_services", context["web_services"])
            if "credentials" in context:
                self.store.update_context("credentials", context["credentials"])

            # Persist all findings so far for exploit phase to use
            all_findings = self.store.read_findings() + findings
            self.store.update_context("all_findings", all_findings)

            # Persist findings as JSONL
            for f in findings:
                self.store.append_finding(f)

            # Mark phase complete
            summary = f"{len(findings)} hallazgos"
            error = "; ".join(phase_errors[:3]) if phase_errors else ""
            self.store.mark_completed(phase_name, summary, len(findings), error=error)
            self._emit_log(f"  ✓ {phase_name}: {summary}")

            # Chain of custody
            self._custody.log_phase(phase_name.upper(), "completed" if not error else "partial", summary)

        # Final phase: report
        self._run_report_phase()

        # Save session for resume
        self._auto_save()

        self._emit_log("Pipeline completado")
        return self._build_agent_state()

    # ── report phase ────────────────────────────────────────────

    def _run_report_phase(self) -> None:
        self._emit_log("\n" + "=" * 50 + "\nFase: REPORT\n" + "=" * 50)
        context = self.store.load().get("context", {})
        findings = self.store.read_findings()

        if not findings:
            self._emit_log("  Sin hallazgos — reporte vacío")
            self.store.mark_completed("report", "No findings", 0)
            return

        self.store.mark_started("report")
        findings_by_sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            findings_by_sev[sev] = findings_by_sev.get(sev, 0) + 1

        overall_risk = (
            "CRITICAL" if findings_by_sev["critical"] > 0 else
            "HIGH" if findings_by_sev["high"] > 0 else
            "MEDIUM" if findings_by_sev["medium"] > 0 else "LOW"
        )

        report_lines = [
            "# Skoll Security Assessment",
            f"**Target:** {self.target}",
            f"**Date:** {datetime.now(timezone.utc).isoformat()}",
            f"**Total findings:** {len(findings)}",
            f"**Risk:** {overall_risk}",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {findings_by_sev['critical']} |",
            f"| High     | {findings_by_sev['high']} |",
            f"| Medium   | {findings_by_sev['medium']} |",
            f"| Low      | {findings_by_sev['low']} |",
            f"| Info     | {findings_by_sev['info']} |",
        ]

        if self._llm_analysis_done and context.get("llm_analysis"):
            report_lines.extend(["", "## LLM Analysis", "", str(context["llm_analysis"])[:2000]])

        report_lines.extend(["", "## Findings"])
        for i, f in enumerate(findings[-50:], 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "?")
            desc = str(f.get("description", ""))[:200]
            report_lines.append(f"{i}. [{sev}] {title}: {desc}")

        report = "\n".join(report_lines)

        # Emit summary event
        self._emit("agent_summary", {
            "project": self.target,
            "total_findings": len(findings),
            "critical_high": findings_by_sev["critical"] + findings_by_sev["high"],
            "overall_risk": overall_risk,
        })

        # Save report
        safe = self.target.replace(".", "_").replace(":", "_")
        reports_dir = Path.home() / ".skoll" / "reports"
        report_path = reports_dir / f"report_{safe}_{self.session_id or 'final'}.md"
        report_path.write_text(report)
        self._emit_log(f"  Reporte: {report_path}")

        self.store.mark_completed("report", f"{len(findings)} findings, risk {overall_risk}", len(findings))

    # ── tool execution ──────────────────────────────────────────

    def _run_tool(self, tool_name: str, target: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        self._emit("agent_tool_start", {"tool": tool_name, "target": target, "params": params})
        engine_cls = get_engine(tool_name)
        engine = engine_cls()
        result = engine.scan(target, **params)

        self._custody.log_tool_result(tool_name, target, params, result)

        self._emit("agent_tool_result", {
            "tool": tool_name, "target": target,
            "summary": result.summary,
            "raw_output": result.raw_output[:2000],
        })

        if not result.success:
            if result.error:
                self._emit_log(f"  ⚠️ {tool_name}: {result.error}")
            return []

        return result.findings

    def _filter_plan(self, plan: PhasePlan) -> tuple[list, list[str]]:
        """Separate plan tools into available / skipped based on DependencyChecker."""
        deps = self.deps.check_all()
        from skoll_agent.utils.dependency_checker import TOOL_ALIASES as _TA
        from skoll_agent.engines.registry import _engines as _ENG_REG
        available: list = []
        skipped: list[str] = []
        for tp in plan.tools:
            tname = tp.tool_name
            if deps.get(tname) is not None:
                available.append(tp)
            elif tname in deps:
                # In REQUIRED_TOOLS but binary not found
                aliases = _TA.get(tname, [tname])
                if not aliases and tname in _ENG_REG:
                    available.append(tp)  # Python-only engine, no binary needed
                else:
                    skipped.append(tname)
            elif tname in _ENG_REG:
                available.append(tp)  # Engine registered but not in REQUIRED_TOOLS
            else:
                skipped.append(tname)
        return available, skipped

    # ── context update ──────────────────────────────────────────

    def _update_context(self, ctx: dict, phase: str, findings: list[dict]) -> None:
        if phase == "recon":
            ports = []
            for f in findings:
                port = f.get("port")
                if port:
                    ports.append({
                        "port": port,
                        "protocol": f.get("protocol", "tcp"),
                        "service": f.get("service", ""),
                        "product": f.get("product", ""),
                        "version": f.get("version", ""),
                        "state": f.get("state", "open"),
                    })
            ctx["open_ports"] = ports
            ctx["findings"] = ctx.get("findings", []) + findings

        elif phase == "analyze":
            web = []
            for f in findings:
                url = f.get("url")
                if url:
                    web.append({
                        "url": url,
                        "title": f.get("title_text", ""),
                        "tech": f.get("technologies", []),
                        "status": f.get("status_code", 0),
                    })
                if f.get("username") and f.get("password"):
                    ctx.setdefault("credentials", []).append(f)
            ctx["web_services"] = web
            ctx["findings"] = ctx.get("findings", []) + findings

        elif phase == "exploit":
            ctx["findings"] = ctx.get("findings", []) + findings
            for f in findings:
                if f.get("username") and f.get("password"):
                    ctx.setdefault("credentials", []).append(f)

    # ── backward compat: AgentState ─────────────────────────────

    def _build_agent_state(self) -> AgentState:
        state = AgentState(project_path=self.target)
        state.completed = True
        findings = self.store.read_findings()
        for i, f in enumerate(findings):
            title = str(f.get("title", f.get("name", "Unknown")))[:100]
            sev = f.get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
            state.add_finding(Finding(
                id=f"{f.get('tool', '?')}-{i}",
                file_path=f.get("file_path", self.target),
                line_start=0, line_end=0,
                severity=sev_map.get(sev, Severity.MEDIUM),
                title=title,
                description=str(f.get("description", ""))[:500],
                tool=f.get("tool", "?"),
                rule_id=f.get("rule_id", ""),
                status=FindingStatus.OPEN,
            ))
        return state

    # ── helpers ─────────────────────────────────────────────────

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        if self.event:
            self.event(event_type, data)

    def _emit_log(self, msg: str) -> None:
        self._emit("agent_log", {"message": msg})

    def _auto_save(self) -> None:
        try:
            mgr = SessionManager()
            st = self.store.load()
            phase = st.get("status", "running")
            mgr.save(self._build_agent_state(), None, session_id=self.session_id or None,
                     target=self.target, phase=phase)
        except Exception:
            pass

    def _update_nuclei_templates(self) -> None:
        try:
            self._emit_log("  nuclei: updating templates...")
            subprocess.run(
                ["nuclei", "-update-templates", "-silent"],
                capture_output=True, text=True, timeout=120,
            )
        except Exception:
            pass
