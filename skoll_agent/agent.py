from __future__ import annotations

import os
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from skoll_agent.brain.reasoning_loop import ReasoningLoop
from skoll_agent.config.agent_config import CONFIG
from skoll_agent.config.skill_registry import list_skills
from skoll_agent.sandbox.docker_sandbox import DockerSandbox

console = Console()

def create_llm_client(provider: str | None = None) -> Any:
    from skoll.client import crear_cliente
    p = provider or CONFIG.provider
    try:
        return crear_cliente(provider=p)
    except ValueError as e:
        console.print(f"[red]❌ {e}[/red]")
        console.print("[yellow]Configura tu API Key en variables de entorno o usa el comando 'configure'.[/yellow]")
        sys.exit(1)


def run_agent(project_path: str, provider: str | None = None, model: str | None = None) -> None:
    if not os.path.exists(project_path):
        console.print(f"[red]❌ La ruta '{project_path}' no existe.[/red]")
        sys.exit(1)

    if provider:
        CONFIG.provider = provider
    if model:
        CONFIG.model = model

    llm_client = create_llm_client()

    console.print(Panel.fit(
        "[bold cyan]🛡 Skoll Autonomous Security Agent[/bold cyan]\n"
        f"[dim]Provider: {CONFIG.provider} | Model: {CONFIG.get_model()}[/dim]\n"
        f"[dim]Project: {os.path.abspath(project_path)}[/dim]\n"
        f"[dim]Max iterations: {CONFIG.max_iterations} | Human-in-loop: {CONFIG.human_in_loop}[/dim]\n"
        f"[dim]Skills: {', '.join(list_skills())}[/dim]",
        border_style="cyan",
    ))

    loop = ReasoningLoop(llm_client, project_path)
    final_state = loop.run()

    console.print("\n[bold green]✅ Agente completó el ciclo de razonamiento.[/bold green]")
    console.print(f"[dim]Hallazgos: {len(final_state.findings)} | Acciones: {len(final_state.action_log)}[/dim]")

    return final_state


def run_agent_interactive() -> None:
    console.print(Panel.fit(
        "[bold cyan]🛡 Skoll Agent — Modo Interactivo[/bold cyan]\n"
        "Configura el agente autónomo de seguridad.",
        border_style="cyan",
    ))

    default_path = os.getcwd()
    project_path = Prompt.ask("[bold]Ruta del proyecto a auditar[/bold]", default=default_path)

    provider_choice = Prompt.ask(
        "[bold]Proveedor IA[/bold]",
        choices=["gemini", "groq"],
        default=CONFIG.provider,
    )

    run_agent(project_path, provider=provider_choice)


def run_sandboxed_agent(project_path: str, provider: str | None = None) -> None:
    sandbox = DockerSandbox()
    if not sandbox.ensure_image():
        console.print("[red]No se pudo preparar el sandbox Docker. Ejecutando sin aislamiento.[/red]")
        run_agent(project_path, provider)
        return

    console.print("[green]✓ Sandbox Docker listo. Ejecutando agente en entorno aislado.[/green]")

    result = sandbox.scan_in_sandbox(project_path, tool="bandit")
    if result["success"]:
        console.print(f"[green]Scan completado en sandbox: {len(result['stdout'])} chars[/green]")
    else:
        console.print(f"[red]Error en sandbox: {result['stderr']}[/red]")



