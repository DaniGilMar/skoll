from __future__ import annotations

import os
from typing import Any, TYPE_CHECKING

from skoll_agent.actions.base_action import ActionResult, BaseAction
from skoll_agent.engines.bandit_engine import BanditEngine
from skoll_agent.engines.semgrep_engine import SemgrepEngine
from skoll_agent.memory.state import Finding, Severity, FindingStatus

if TYPE_CHECKING:
    from skoll_agent.brain.context import ProjectContext
    from skoll_agent.memory.state import AgentState

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class ScanAction(BaseAction):
    name = "scan_file"

    def __init__(self):
        self._engines = {
            "bandit": BanditEngine(),
            "semgrep": SemgrepEngine(),
        }

    def execute(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> ActionResult:
        target = params.get("target", "")
        tool = params.get("tool", "all")

        if not target or target == "all":
            target = context.root_path
        else:
            target = os.path.join(context.root_path, target) if not os.path.isabs(target) else target

        if not os.path.exists(target):
            return ActionResult(success=False, summary=f"Target not found: {target}", error="Path does not exist")

        findings: list[Finding] = []
        all_raw: list[str] = []

        engines_to_run = []
        if tool == "all":
            engines_to_run = list(self._engines.values())
        elif tool in self._engines:
            engines_to_run = [self._engines[tool]]

        for engine in engines_to_run:
            result = engine.scan(target)
            if not result.success:
                continue
            all_raw.append(result.raw_output)
            for raw in result.findings:
                sev = _SEVERITY_MAP.get(raw.get("severity", "medium"), Severity.MEDIUM)
                finding_id = f"{engine.name}-{raw.get('file_path', 'unknown')}-{raw.get('line_start', 0)}-{raw.get('rule_id', '')[:8]}"
                finding = Finding(
                    id=finding_id,
                    file_path=raw.get("file_path", ""),
                    line_start=raw.get("line_start", 0),
                    line_end=raw.get("line_end", 0),
                    severity=sev,
                    title=raw.get("title", "Unknown"),
                    description=raw.get("description", ""),
                    tool=engine.name,
                    rule_id=raw.get("rule_id", ""),
                    status=FindingStatus.OPEN,
                )
                findings.append(finding)

        return ActionResult(
            success=True,
            summary=f"Scanned {target} with {tool}: {len(findings)} findings",
            data={"target": target, "tool": tool, "raw_outputs": all_raw},
            findings=findings,
        )
