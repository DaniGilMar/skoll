from __future__ import annotations

import threading
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

console = Console()

# Credential response store for web-based HIL
_pending_creds: dict[str, dict[str, Any]] = {}
_pending_creds_lock = threading.Lock()


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
            title="[bold]Yggdrasil Agent — Human-in-the-Loop[/bold]",
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

    def ask_credentials(
        self,
        url: str,
        login_url: str,
        prompt_message: str | None = None,
        event_queue: Any = None,
        session_id: str | None = None,
        timeout: int = 300,
    ) -> dict[str, Any] | None:
        """Ask the user for credentials. Returns {'username': ..., 'password': ...} or None."""
        if not self.enabled:
            return None

        message = prompt_message or f"Se requiere autenticación para {url}"

        # Web path: emit event + wait for response via _pending_creds
        if event_queue is not None and session_id:
            event_queue.put({
                "type": "ask_credentials",
                "data": {"login_url": login_url, "message": message},
            })
            ev = threading.Event()
            with _pending_creds_lock:
                _pending_creds[session_id] = {"event": ev, "response": None}
            waited = ev.wait(timeout=timeout)
            with _pending_creds_lock:
                resp = _pending_creds.pop(session_id, {}).get("response")
            if not waited or not resp:
                return None
            if resp.get("skip"):
                return None
            return {"username": resp.get("username", ""), "password": resp.get("password", "")}

        # CLI path: rich prompt
        panel = Panel(
            f"[bold yellow]🔐 Autenticación requerida[/bold yellow]\n\n{message}",
            title="[bold]Yggdrasil — Credenciales[/bold]",
            border_style="yellow",
        )
        console.print(panel)
        knows = Confirm.ask("[cyan]¿Conoces las credenciales?[/cyan]", default=True)
        if not knows:
            return None
        username = Prompt.ask("[bold cyan]Usuario[/bold cyan]")
        password = Prompt.ask("[bold cyan]Contraseña[/bold cyan]", password=True)
        return {"username": username, "password": password}
