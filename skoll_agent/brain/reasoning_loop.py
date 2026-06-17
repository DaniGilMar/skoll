from __future__ import annotations

from typing import Any, Callable

from rich.console import Console

from skoll_agent.memory.state import AgentState
from skoll_agent.memory.session_manager import SessionManager
from skoll_agent.pipeline import PipelineOrchestrator

console = Console()
EventCallback = Callable[[str, dict[str, Any]], None]


class ReasoningLoop:
    def __init__(self, llm_client: Any, project_path: str,
                 event_callback: EventCallback | None = None,
                 session_id: str | None = None,
                 is_network_target: bool = False):
        self.is_network = is_network_target
        self.project_path = project_path
        self.orchestrator = PipelineOrchestrator(
            target=project_path,
            is_network=is_network_target,
            llm_client=llm_client,
            event_callback=event_callback,
            session_id=session_id,
        )
        self.state = AgentState(project_path=project_path)
        self.session_mgr = SessionManager()
        self._session_id = session_id or ""
        self._auto_save_enabled = True

    @property
    def session_id(self) -> str:
        return self._session_id

    @session_id.setter
    def session_id(self, value: str) -> None:
        self._session_id = value
        self.orchestrator.session_id = value

    def run(self) -> AgentState:
        return self.orchestrator.run()

    @classmethod
    def resume(cls, llm_client: Any, session_id: str,
               event_callback: EventCallback | None = None) -> ReasoningLoop:
        mgr = SessionManager()
        loaded = mgr.load(session_id)
        if not loaded:
            raise ValueError(f"Session '{session_id}' not found")
        agent_state, task_queue = loaded
        is_net = not agent_state.project_path.startswith("/") and "." in agent_state.project_path
        loop = cls(llm_client, agent_state.project_path, event_callback,
                   session_id=session_id, is_network_target=is_net)
        loop.state = agent_state
        loop._auto_save_enabled = True
        return loop
