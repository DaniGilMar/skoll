import os
import platform
import threading
import time
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt

# ── Auto-load .env at CLI startup ────────────────────────────────────
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    for _line in _env_path.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

from skoll.client import crear_cliente
from skoll.config import (
    ANALYSIS_TEMPLATE_PROMPT,
    CHAT_WELCOME_MESSAGE,
    DEFAULT_PROVIDER,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_GROQ_MODEL,
    GROQ_MODELS,
    get_default_model,
)
from skoll.scanner import ejecutar_escaneo_sast
from skoll.utils import escanear_directorio, leer_archivo, mostrar_error_api_key, mostrar_error_general
from skoll.verifier import preguntar_y_ejecutar_verificacion

app = typer.Typer(
    help="Skoll: Asistente CLI de ciberseguridad para auditorías de código inspirado en RAPTOR.",
    no_args_is_help=True
)
console = Console()

PROVIDER_HELP = "Proveedor de IA: 'gemini' o 'groq'."
MODEL_HELP = "Modelo a usar (según proveedor)."


def obtener_cliente(provider: str = DEFAULT_PROVIDER):
    try:
        return crear_cliente(provider=provider)
    except ValueError as e:
        mostrar_error_api_key(str(e))
        raise typer.Exit(code=1)
    except Exception as e:
        mostrar_error_general(str(e))
        raise typer.Exit(code=1)


def provider_label(p: str) -> str:
    return "Groq" if p.lower() == "groq" else "Gemini"


@app.command("chat")
def chat_comando(
    provider: str = typer.Option(
        DEFAULT_PROVIDER,
        "--provider", "-p",
        help=PROVIDER_HELP,
    ),
    model: str = typer.Option(
        None,
        "--model", "-m",
        help=MODEL_HELP,
    ),
):
    if model is None:
        model = get_default_model(provider)
    client = obtener_cliente(provider=provider)
    console.print(CHAT_WELCOME_MESSAGE)

    try:
        chat = client.iniciar_chat(model=model)
    except Exception as e:
        mostrar_error_general(f"No se pudo iniciar la sesión de chat: {str(e)}")
        raise typer.Exit(code=1)

    while True:
        try:
            user_input = Prompt.ask(f"\n[bold cyan]Skoll ({provider_label(provider)}) ➔ [/bold cyan]")
            if user_input.strip().lower() in ("salir", "exit", "quit"):
                console.print("[bold yellow][*] Finalizando sesión de chat de seguridad. ¡Mantente seguro![/bold yellow]")
                break

            if not user_input.strip():
                continue

            console.print(f"\n[bold green]{provider_label(provider)} ➔ [/bold green]", end="")

            stream = chat.send_message_stream(user_input)
            for chunk in stream:
                console.print(chunk.text, end="")
            console.print()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow][*] Sesión interrumpida por el usuario. ¡Adiós![/bold yellow]")
            break
        except Exception as e:
            console.print(f"\n[bold red][Error] Ocurrió un fallo en la llamada de IA: {str(e)}[/bold red]")


@app.command("analyze")
def analyze_comando(
    ruta: str = typer.Argument(
        ...,
        help="Ruta al archivo o carpeta de código local a auditar."
    ),
    provider: str = typer.Option(
        DEFAULT_PROVIDER,
        "--provider", "-p",
        help=PROVIDER_HELP,
    ),
    model: str = typer.Option(
        None,
        "--model", "-m",
        help=MODEL_HELP,
    ),
):
    if model is None:
        model = get_default_model(provider)
    if not os.path.exists(ruta):
        mostrar_error_general(f"La ruta '{ruta}' no existe en el sistema.")
        raise typer.Exit(code=1)

    client = obtener_cliente(provider=provider)

    if os.path.isdir(ruta):
        console.print(f"[bold blue][*] Escaneando directorio recursivamente:[/bold blue] '{ruta}'...")
        codigo = escanear_directorio(ruta)
    else:
        console.print(f"[bold blue][*] Leyendo archivo individual:[/bold blue] '{ruta}'...")
        codigo = leer_archivo(ruta)

    if not codigo or codigo.strip() == "":
        mostrar_error_general("No se pudo obtener código fuente legible de la ruta especificada.")
        raise typer.Exit(code=1)

    prompt_analisis = ANALYSIS_TEMPLATE_PROMPT.format(code_content=codigo)

    console.print(f"[bold yellow][*] Enviando contexto a {provider_label(provider)} para auditoría RAPTOR (Etapas A-D)...[/bold yellow]\n")

    try:
        stream = client.analizar_codigo_stream(prompt_analisis, model=model)
        for chunk in stream:
            console.print(chunk.text, end="")
        console.print()

    except Exception as e:
        mostrar_error_general(f"Fallo al procesar el análisis con {provider_label(provider)}: {str(e)}")
        raise typer.Exit(code=1)

    preguntar_y_ejecutar_verificacion(ruta)


@app.command("scan")
def scan_comando(
    ruta: str = typer.Argument(
        ...,
        help="Ruta del proyecto a escanear con herramientas SAST locales."
    ),
    tool: str = typer.Option(
        "all",
        "--tool", "-t",
        help="Herramienta local a correr: 'bandit', 'semgrep', o 'all'."
    ),
    provider: str = typer.Option(
        DEFAULT_PROVIDER,
        "--provider", "-p",
        help=PROVIDER_HELP,
    ),
    model: str = typer.Option(
        None,
        "--model", "-m",
        help=MODEL_HELP,
    ),
):
    if model is None:
        model = get_default_model(provider)
    if not os.path.exists(ruta):
        mostrar_error_general(f"La ruta '{ruta}' no existe en el sistema.")
        raise typer.Exit(code=1)

    console.print(f"[bold blue][*] Lanzando herramientas SAST locales en:[/bold blue] '{ruta}'...")
    with console.status("[bold green]Corriendo escáneres estáticos locales...", spinner="dots"):
        reportes_sast = ejecutar_escaneo_sast(ruta, tool=tool)

    sast_resumen = ""
    for clave, salida in reportes_sast.items():
        sast_resumen += f"=== REPORTE DE {clave.upper()} ===\n{salida}\n\n"

    console.print("[green]✔ Escaneo SAST local finalizado.[/green]")
    console.print(f"[bold yellow][*] Enviando reportes a {provider_label(provider)} para interpretación y triage RAPTOR...[/bold yellow]\n")

    client = obtener_cliente(provider=provider)
    prompt_sast = (
        "Interpreta la salida de las siguientes herramientas SAST locales sobre el código del proyecto.\n"
        "Identifica los fallos reales de los falsos positivos y genera un reporte en ESPAÑOL "
        "estructurado según la metodología RAPTOR (Etapas A-D):\n\n"
        f"{sast_resumen}"
    )

    try:
        stream = client.analizar_codigo_stream(prompt_sast, model=model)
        for chunk in stream:
            console.print(chunk.text, end="")
        console.print()

    except Exception as e:
        mostrar_error_general(f"Fallo al procesar el reporte SAST con {provider_label(provider)}: {str(e)}")
        raise typer.Exit(code=1)

    preguntar_y_ejecutar_verificacion(ruta)


@app.command("web")
def web_comando(
    port: int = typer.Option(
        8000,
        "--port", "-p",
        help="Puerto en el que se ejecutará el servidor web local."
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="No abrir el navegador automáticamente al iniciar."
    ),
    provider: str = typer.Option(
        DEFAULT_PROVIDER,
        "--provider", "-P",
        help=PROVIDER_HELP,
    ),
    model: str = typer.Option(
        None,
        "--model", "-m",
        help=MODEL_HELP,
    ),
):
    if model is None:
        model = get_default_model(provider)
    try:
        import uvicorn

        from skoll.web_server import app as web_app
    except ImportError:
        console.print(
            "[bold red]❌ Dependencias web no instaladas.[/bold red]\n"
            "Instálalas con: [bold cyan]pip install fastapi uvicorn[standard][/bold cyan]"
        )
        raise typer.Exit(code=1)

    # Pasar provider y model a web_server vía variables de entorno
    os.environ["AI_PROVIDER"] = provider
    os.environ["AI_MODEL"] = model

    sistema = platform.system()
    nombre_so = {"Darwin": "macOS", "Linux": "Linux", "Windows": "Windows"}.get(sistema, sistema)

    def tiene_gui() -> bool:
        if sistema == "Darwin":
            return True
        if sistema == "Linux":
            return bool(
                os.environ.get("DISPLAY")
                or os.environ.get("WAYLAND_DISPLAY")
                or os.environ.get("MIR_SOCKET")
            )
        return True

    url = f"http://localhost:{port}"

    console.print()
    console.print("[bold green]🛡️  Skoll — Interfaz Web[/bold green]")
    console.print(f"   [dim]Sistema detectado:[/dim]  [bold]{nombre_so}[/bold]")
    console.print(f"   [dim]Proveedor:[/dim]           [bold cyan]{provider_label(provider)}[/bold cyan]")
    console.print(f"   [dim]Modelo:[/dim]              [bold cyan]{model}[/bold cyan]")
    console.print(f"   [dim]Servidor en:[/dim]        [bold blue]{url}[/bold blue]")

    abrir_navegador = not no_browser

    if abrir_navegador and tiene_gui():
        console.print("   [dim]Navegador:[/dim]          [green]Abriéndose automáticamente...[/green]")
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()
    elif abrir_navegador and not tiene_gui():
        console.print(f"   [dim]Navegador:[/dim]          [yellow]Sin entorno gráfico — abre manualmente:[/yellow] {url}")
    else:
        console.print("   [dim]Navegador:[/dim]          [dim]Desactivado (--no-browser)[/dim]")

    console.print()
    console.print("[dim]   Pulsa Ctrl+C para detener el servidor.[/dim]\n")

    uvicorn.run(
        web_app,
        host="0.0.0.0",
        port=port,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    app()
