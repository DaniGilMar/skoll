from __future__ import annotations

from typing import Any, TYPE_CHECKING

from skoll_agent.actions.base_action import ActionResult, BaseAction
from skoll_agent.engines.registry import get_engine, list_engines
from skoll_agent.memory.state import Finding, Severity, FindingStatus

if TYPE_CHECKING:
    from skoll_agent.memory.state import AgentState
    from skoll_agent.brain.context import ProjectContext


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}


class ToolRunnerAction(BaseAction):
    name = "run_tool"

    def execute(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> ActionResult:
        tool_name = params.get("tool", "")
        target = params.get("target", "")
        extra = {k: v for k, v in params.items() if k not in ("tool", "target", "_llm_client", "_progress_callback")}
        progress_cb = params.get("_progress_callback")
        if progress_cb:
            extra["progress_callback"] = progress_cb

        if not tool_name:
            return ActionResult(success=False, summary="No tool specified. Available: " + ", ".join(list_engines().keys()))

        try:
            engine_cls = get_engine(tool_name)
        except KeyError:
            return ActionResult(success=False, summary=f"Tool '{tool_name}' not found. Available: {', '.join(list_engines().keys())}")

        engine = engine_cls()
        result = engine.scan(target, **extra)

        if not result.success:
            return ActionResult(success=False, summary=result.summary, error=result.error)

        existing_ids = {f.id for f in state.findings}
        new_findings = []
        for raw in result.findings:
            f_id = f"{tool_name}-{raw.get('rule_id', '')}-{raw.get('port', '')}-{raw.get('path', '')}"
            f_id = f_id.strip("-")
            if f_id in existing_ids:
                continue
            existing_ids.add(f_id)
            sev = _SEVERITY_MAP.get(raw.get("severity", "medium"), Severity.MEDIUM)
            finding = Finding(
                id=f_id,
                file_path=raw.get("file_path", target),
                line_start=raw.get("line_start", 0),
                line_end=raw.get("line_end", 0),
                severity=sev,
                title=raw.get("title", "Unknown"),
                description=raw.get("description", ""),
                tool=tool_name,
                rule_id=raw.get("rule_id", ""),
                status=FindingStatus.OPEN,
            )
            new_findings.append(finding)
            state.add_finding(finding)
            state.mark_scanned(f"{tool_name}:{target}")

        ports_summary = "; ".join(
            f"{r.get('port','?')}/{r.get('protocol','tcp')}({r.get('service','?')} {r.get('product','')} {r.get('version','')})".strip()
            for r in result.findings
        ) if result.findings else ""

        detailed_summary = f"{tool_name} on {target}: {len(new_findings)} new findings"
        if ports_summary:
            detailed_summary += f" | Open: {ports_summary}"

        return ActionResult(
            success=True,
            summary=detailed_summary,
            data={"tool": tool_name, "target": target, "findings": result.findings},
            findings=new_findings,
        )
