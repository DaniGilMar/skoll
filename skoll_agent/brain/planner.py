from __future__ import annotations

import json
import re
from typing import Any

from skoll_agent.brain.context import ProjectContext, context_to_prompt
from skoll_agent.config.agent_config import CONFIG
from skoll_agent.memory.state import AgentState
from skoll_agent.memory.task_queue import Task, TaskPriority

PLANNER_PROMPT = """You are Skoll Agent's strategic planner.

Given the project context and current state, decompose the security audit into
a prioritized task plan. Output a JSON array of tasks.

Project Context:
{project_context}

Current State:
{state_summary}

Output format (JSON array):
```json
[
  {{
    "skill": "code_analysis",
    "action": "scan_file",
    "params": {{"target": "file_or_dir", "tool": "bandit|semgrep|all"}},
    "priority": "critical|high|medium|low",
    "reasoning": "why this task"
  }}
]
```

Prioritize high-risk files first. Generate 3-8 tasks covering:
- Scanning high-risk files
- Analyzing findings
- Reporting
"""


class Planner:
    def __init__(self, llm_client: Any):
        self.llm = llm_client

    def plan(self, context: ProjectContext, state: AgentState) -> list[Task]:
        prompt = PLANNER_PROMPT.format(
            project_context=context_to_prompt(context),
            state_summary=state.summary_text(),
        )

        try:
            if hasattr(self.llm, "analizar_codigo_stream"):
                collected = ""
                stream = self.llm.analizar_codigo_stream(prompt, model=CONFIG.get_model())
                for chunk in stream:
                    collected += chunk.text
                response = collected
            else:
                response = self.llm.analizar_codigo(prompt, model=CONFIG.get_model())

            tasks_data = self._parse_tasks(response)
            tasks: list[Task] = []
            for td in tasks_data:
                priority_map = {"critical": TaskPriority.CRITICAL, "high": TaskPriority.HIGH, "medium": TaskPriority.MEDIUM, "low": TaskPriority.LOW}
                tasks.append(Task(
                    skill=td.get("skill", "code_analysis"),
                    action=td.get("action", "scan_file"),
                    params=td.get("params", {}),
                    reasoning=td.get("reasoning", ""),
                    priority=priority_map.get(td.get("priority", "medium"), TaskPriority.MEDIUM),
                ))
            return tasks

        except Exception as e:
            return self._fallback_plan(context, state)

    def _parse_tasks(self, text: str) -> list[dict[str, Any]]:
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if json_match:
            raw = json_match.group(1).strip()
        else:
            brace_start = text.find("[")
            brace_end = text.rfind("]")
            if brace_start != -1 and brace_end > brace_start:
                raw = text[brace_start : brace_end + 1]
            else:
                return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return []

    def _fallback_plan(self, context: ProjectContext, state: AgentState) -> list[Task]:
        tasks: list[Task] = []
        high_risk = [f for f in context.files if f.risk_score > 5][:5]
        for f in high_risk:
            tasks.append(Task(
                skill="code_analysis",
                action="scan_file",
                params={"target": f.relative_path, "tool": "bandit"},
                priority=TaskPriority.HIGH,
                reasoning=f"High-risk file: {f.relative_path} (risk: {f.risk_score})",
            ))
        if tasks:
            tasks.append(Task(
                skill="code_analysis",
                action="report",
                params={"format": "sarif"},
                priority=TaskPriority.LOW,
                reasoning="Generate SARIF report",
            ))
        return tasks
