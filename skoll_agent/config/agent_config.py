from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class AgentConfig:
    provider: str = os.getenv("AI_PROVIDER", "gemini")
    model: str = os.getenv("AGENT_MODEL", "")
    max_iterations: int = int(os.getenv("AGENT_MAX_ITERATIONS", "15"))
    max_depth: int = int(os.getenv("AGENT_MAX_DEPTH", "3"))
    human_in_loop: bool = os.getenv("AGENT_HUMAN_IN_LOOP", "true").lower() == "true"
    sandbox_enabled: bool = os.getenv("AGENT_SANDBOX", "true").lower() == "true"
    docker_image: str = os.getenv("AGENT_DOCKER_IMAGE", "skoll-sandbox:latest")
    report_format: Literal["sarif", "markdown", "json"] = os.getenv("AGENT_REPORT_FORMAT", "sarif")  # type: ignore
    auto_patch: bool = os.getenv("AGENT_AUTO_PATCH", "false").lower() == "true"
    output_dir: str = os.getenv("AGENT_OUTPUT_DIR", "./reports")
    project_max_chars: int = int(os.getenv("AGENT_PROJECT_MAX_CHARS", "200000"))

    engines_enabled: list[str] = field(default_factory=lambda: [
        x.strip() for x in os.getenv("AGENT_ENGINES", "bandit,semgrep").split(",") if x.strip()
    ])

    def get_model(self) -> str:
        if self.model:
            return self.model
        from skoll.config import get_default_model
        return get_default_model(self.provider)


CONFIG = AgentConfig()
