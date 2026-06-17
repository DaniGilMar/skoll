from __future__ import annotations

from typing import Any, TYPE_CHECKING

from skoll_agent.skills.base_skill import BaseSkill
from skoll_agent.actions.tool_runner_action import ToolRunnerAction
from skoll_agent.engines.registry import list_engines

if TYPE_CHECKING:
    from skoll_agent.memory.state import AgentState
    from skoll_agent.brain.context import ProjectContext


class EngineSkill(BaseSkill):
    name = "tool_runner"
    description = "Ejecuta cualquier herramienta de seguridad del sistema (nmap, gobuster, nikto, sqlmap, nuclei, hydra, etc.)"

    def __init__(self):
        self._runner = ToolRunnerAction()

    def execute(self, action: str, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        if action == "run_tool":
            result = self._runner.execute(params, state, context)
            return {
                "success": result.success,
                "summary": result.summary,
                "data": result.data,
                "findings": result.findings,
            }
        return {"success": False, "summary": f"Unknown action '{action}'"}

    @staticmethod
    def tools_help() -> str:
        engines = list_engines()
        if not engines:
            return "  No hay herramientas adicionales disponibles."
        lines = []
        for name, desc in sorted(engines.items()):
            lines.append(f"  - `{name}`: {desc}")
        return "\n".join(lines)
