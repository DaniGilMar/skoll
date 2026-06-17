from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from skoll_agent.actions.base_action import ActionResult, BaseAction
from skoll_agent.reporting.sarif import SARIFBuilder

if TYPE_CHECKING:
    from skoll_agent.brain.context import ProjectContext
    from skoll_agent.memory.state import AgentState


class ReportAction(BaseAction):
    name = "report"

    def execute(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> ActionResult:
        fmt = params.get("format", "sarif")
        output_path = params.get("output_path", "./reports")
        os.makedirs(output_path, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if fmt == "sarif":
            sarif = SARIFBuilder()
            sarif.add_tool("skoll-agent", "0.1.0")
            for finding in state.findings:
                sarif.add_result(finding)
            sarif_doc = sarif.build()
            filepath = os.path.join(output_path, f"skoll_report_{timestamp}.sarif")
            with open(filepath, "w") as f:
                json.dump(sarif_doc, f, indent=2)
        elif fmt == "json":
            report = {
                "generated_at": timestamp,
                "project": context.root_path,
                "summary": {
                    "total_findings": len(state.findings),
                    "critical": len(state.get_critical_findings()),
                    "open": len(state.get_open_findings()),
                    "files_scanned": len(state.scanned_files),
                },
                "findings": [f.__dict__ for f in state.findings],
                "action_log": [a.__dict__ for a in state.action_log],
            }
            filepath = os.path.join(output_path, f"skoll_report_{timestamp}.json")
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2)
        else:
            lines = [f"# Skoll Agent Report - {timestamp}", f"Project: {context.root_path}", ""]
            lines.append("## Summary")
            lines.append(f"- Total findings: {len(state.findings)}")
            lines.append(f"- Critical/High: {len(state.get_critical_findings())}")
            lines.append(f"- Open: {len(state.get_open_findings())}")
            lines.append(f"- Files scanned: {len(state.scanned_files)}")
            lines.append("")
            lines.append("## Findings")
            for f in state.findings:
                lines.append(f"### [{f.severity.value.upper()}] {f.title}")
                lines.append(f"- File: {f.file_path}:{f.line_start}")
                lines.append(f"- Description: {f.description}")
                lines.append(f"- Status: {f.status.value}")
                if f.remediation:
                    lines.append(f"- Remediation: {f.remediation[:200]}")
                lines.append("")
            filepath = os.path.join(output_path, f"skoll_report_{timestamp}.md")
            with open(filepath, "w") as f:
                f.write("\n".join(lines))

        return ActionResult(
            success=True,
            summary=f"Report generated: {filepath}",
            data={"filepath": filepath, "format": fmt, "findings_count": len(state.findings)},
        )
