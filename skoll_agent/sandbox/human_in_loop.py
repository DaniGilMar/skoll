from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()


class HumanInLoop:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def approve(self, message: str, context: dict[str, Any] | None = None) -> bool:
        if not self.enabled:
            return True

        detail = ""
        if context:
            action = context.get("action", "unknown")
            reasoning = context.get("reasoning", "")
            params = context.get("params", {})
            detail = f"\n[dim]Action: {action}\nReasoning: {reasoning}\nParams: {params}[/dim]"

        panel = Panel(
            f"[bold yellow]⚠ Human Review Required[/bold yellow]\n\n{message}{detail}",
            title="[bold]Skoll Agent — Human-in-the-Loop[/bold]",
            border_style="yellow",
        )
        console.print(panel)

        return Confirm.ask("[bold cyan]¿Aprobar esta acción?[/bold cyan]", default=False)

    def review_findings(self, findings: list[Any]) -> list[str]:
        if not self.enabled:
            return [f.id for f in findings]

        approved: list[str] = []
        for f in findings:
            console.print(Panel(
                f"[bold]{f.severity.value.upper()}[/bold] {f.title}\n"
                f"File: {f.file_path}:{f.line_start}\n"
                f"Description: {f.description[:200]}",
                title="Finding Review",
            ))
            if Confirm.ask("[cyan]¿Aceptar este hallazgo?[/cyan]", default=True):
                approved.append(f.id)
        return approved
