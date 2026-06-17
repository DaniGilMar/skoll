from __future__ import annotations

"""Code Analysis Skill: Static code analysis using SAST tools.

This skill wraps scan actions and finding analysis, enabling the agent to
autonomously decide which files to scan and how to interpret results.
"""

import os
from typing import Any, TYPE_CHECKING

from skoll_agent.actions.scan_action import ScanAction
from skoll_agent.actions.report_action import ReportAction
from skoll_agent.actions.exploit_action import ExploitAction
from skoll_agent.config.agent_config import CONFIG
from skoll_agent.memory.state import Finding, Severity
from skoll_agent.skills.base_skill import BaseSkill

if TYPE_CHECKING:
    from skoll_agent.brain.context import ProjectContext
    from skoll_agent.memory.state import AgentState


class CodeAnalysisSkill(BaseSkill):
    name = "code_analysis"
    description = "Static code analysis: scans code with SAST tools and interprets findings"

    def __init__(self):
        self._scanner = ScanAction()
        self._reporter = ReportAction()
        self._exploiter = ExploitAction()

    def execute(self, action: str, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        action_map = {
            "scan_file": self._handle_scan,
            "analyze_findings": self._handle_analyze,
            "simulate_exploit": self._handle_exploit,
            "generate_patch": self._handle_patch,
            "validate_fix": self._handle_validate,
            "report": self._handle_report,
        }

        handler = action_map.get(action)
        if not handler:
            return {"success": False, "summary": f"Unknown action '{action}' for skill code_analysis"}

        return handler(params, state, context)

    def _handle_scan(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        target = params.get("target", "")

        if not target or target == "all":
            targets = [f.relative_path for f in context.files if f.risk_score > 3][:5]
            if not targets:
                targets = [f.relative_path for f in context.files[:3]]
        elif target == "high_risk":
            targets = [f.relative_path for f in context.files if f.risk_score > 5]
            if not targets:
                targets = [f.relative_path for f in context.files[:3]]
        else:
            targets = [target]

        tool = params.get("tool", "bandit")

        all_findings: list[Finding] = []
        scanned: list[str] = []
        errors: list[str] = []

        existing_ids = {f.id for f in state.findings}

        for t in targets:
            abs_target = t if os.path.isabs(t) else os.path.join(context.root_path, t)
            if not os.path.exists(abs_target):
                errors.append(f"Target not found: {t}")
                continue

            result = self._scanner.execute({"target": abs_target, "tool": tool}, state, context)
            if result.success:
                scanned.append(t)
                for f in result.findings:
                    f.file_path = os.path.relpath(f.file_path, context.root_path) if os.path.isabs(f.file_path) else f.file_path
                    if f.id not in existing_ids:
                        existing_ids.add(f.id)
                        all_findings.append(f)
                        state.add_finding(f)
                        state.mark_scanned(f.file_path)
            else:
                errors.append(f"Scan failed for {t}: {result.error}")

        return {
            "success": True,
            "summary": f"Scanned {len(scanned)} files, found {len(all_findings)} vulnerabilities",
            "findings": all_findings,
            "data": {"scanned": scanned, "errors": errors},
        }

    def _handle_analyze(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        open_findings = state.get_open_findings()
        if not open_findings:
            return {"success": True, "summary": "No open findings to analyze"}

        critical = [f for f in open_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        medium = [f for f in open_findings if f.severity == Severity.MEDIUM]
        low = [f for f in open_findings if f.severity in (Severity.LOW, Severity.INFO)]

        analysis = {
            "total_open": len(open_findings),
            "critical_high": len(critical),
            "medium": len(medium),
            "low": len(low),
            "by_file": {},
        }

        for f in open_findings:
            if f.file_path not in analysis["by_file"]:
                analysis["by_file"][f.file_path] = []
            analysis["by_file"][f.file_path].append(f.title)

        return {
            "success": True,
            "summary": f"Analysis: {len(critical)} critical/high, {len(medium)} medium, {len(low)} low",
            "data": analysis,
            "findings": open_findings,
        }

    def _handle_exploit(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        finding_id = params.get("finding_id", "all")
        if finding_id == "all":
            params = dict(params)
            params["findings"] = state.get_critical_findings() or state.get_open_findings()
        result = self._exploiter.execute(params, state, context)
        exploits = result.data.get("exploits", [])
        return {
            "success": result.success,
            "summary": result.summary,
            "data": {"exploits": exploits, "finding_id": finding_id},
            "findings": result.findings,
            "exploits": exploits,
        }

    def _handle_patch(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        return {
            "success": True,
            "summary": "Patch generation requires human_in_loop approval. Use request_human_review first.",
            "data": {"note": "Patching not yet implemented at skill level"},
        }

    def _handle_validate(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        return {
            "success": True,
            "summary": "Validation requires patch to be applied first.",
            "data": {"note": "Validation not yet implemented at skill level"},
        }

    def _handle_report(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        result = self._reporter.execute(params, state, context)
        return {
            "success": result.success,
            "summary": result.summary,
            "data": result.data,
        }
