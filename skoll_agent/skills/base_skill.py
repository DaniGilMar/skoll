from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from skoll_agent.brain.context import ProjectContext
    from skoll_agent.memory.state import AgentState


class BaseSkill(ABC):
    name: str = "base_skill"
    description: str = "Base skill"

    @abstractmethod
    def execute(self, action: str, params: dict[str, Any], state: AgentState, context: ProjectContext) -> dict[str, Any]:
        ...
