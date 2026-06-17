from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from skoll_agent.brain.context import ProjectContext
    from skoll_agent.memory.state import AgentState


@dataclass
class ActionResult:
    success: bool
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Any] = field(default_factory=list)
    error: str = ""


class BaseAction(ABC):
    name: str = "base_action"

    @abstractmethod
    def execute(self, params: dict[str, Any], state: AgentState, context: ProjectContext) -> ActionResult:
        ...
