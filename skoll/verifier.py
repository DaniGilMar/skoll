import ast
import os
import shutil
import subprocess

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()

class BaseVerificationPlugin:
    name: str = "BasePlugin"
    description: str = "Descripción del plugin"

    def verificar(self, target_path: str, context: dict) -> dict:
        raise NotImplementedError("Los plugins deben implementar el método verificar().")


class BanditVerifierPlugin(BaseVerificationPlugin):
    """Ejecuta Bandit real sobre el objetivo y devuelve los resultados."""
    name = "Bandit SAST"
    description = "Ejecuta Bandit localmente para detectar vulnerabilidades Python."

    def verificar(self, target_path: str, context: dict) -> dict:
        console.print("\n[bold yellow][*] Ejecutando Bandit para verificación dinámica...[/bold yellow]")
        if not shutil.which("bandit"):
            return {
                "success": False,
                "log": "Bandit no está instalado. Instálalo con 'pip install bandit'.",
                "details": "No se pudo ejecutar la verificación."
            }
        try:
            result = subprocess.run(
                ["bandit", "-r", target_path, "-f", "txt", "-q"],
                capture_output=True, text=True, timeout=60
            )
            log = result.stdout.strip() or "Bandit no encontró vulnerabilidades."
            return {
                "success": True,
                "log": log,
                "details": "Verificación completada. Revisa los hallazgos de Bandit."
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "log": "Bandit agotó el tiempo de espera.", "details": ""}
        except Exception as e:
            return {"success": False, "log": f"Error: {str(e)}", "details": ""}


class SemgrepVerifierPlugin(BaseVerificationPlugin):
    """Ejecuta Semgrep real sobre el objetivo."""
    name = "Semgrep SAST"
    description = "Ejecuta Semgrep con reglas automáticas de seguridad."

    def verificar(self, target_path: str, context: dict) -> dict:
        console.print("\n[bold yellow][*] Ejecutando Semgrep para verificación dinámica...[/bold yellow]")
        if not shutil.which("semgrep"):
            return {
                "success": False,
                "log": "Semgrep no está instalado. Instálalo con 'pip install semgrep'.",
                "details": "No se pudo ejecutar la verificación."
            }
        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config", "auto", target_path, "--quiet"],
                capture_output=True, text=True, timeout=120
            )
            log = result.stdout.strip() or "Semgrep no encontró vulnerabilidades."
            return {
                "success": True,
                "log": log,
                "details": "Verificación completada. Revisa los hallazgos de Semgrep."
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "log": "Semgrep agotó el tiempo de espera.", "details": ""}
        except Exception as e:
            return {"success": False, "log": f"Error: {str(e)}", "details": ""}


class AstAnalyzerPlugin(BaseVerificationPlugin):
    """Analiza código Python con AST en busca de patrones peligrosos."""
    name = "Analizador AST"
    description = "Analiza código Python con AST en busca de eval(), exec(), os.system(), etc."

    def verificar(self, target_path: str, context: dict) -> dict:
        console.print("\n[bold yellow][*] Analizando AST del código fuente...[/bold yellow]")
        peligrosos = []
        archivos_analizados = 0

        for root, _dirs, files in os.walk(target_path):
            for f in files:
                if not f.endswith(".py"):
                    continue
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, errors="ignore") as fh:
                        tree = ast.parse(fh.read(), filename=filepath)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name):
                                if node.func.id in ("eval", "exec", "compile"):
                                    peligrosos.append(f"{filepath}:{node.lineno} - uso de {node.func.id}()")
                            elif isinstance(node.func, ast.Attribute):
                                if (isinstance(node.func.value, ast.Name) and
                                    node.func.value.id == "os" and
                                    node.func.attr in ("system", "popen", "execve")):
                                    peligrosos.append(f"{filepath}:{node.lineno} - os.{node.func.attr}()")
                                elif (isinstance(node.func.value, ast.Attribute) and
                                      node.func.value.attr == "popen" and
                                      node.func.attr == "communicate"):
                                    peligrosos.append(f"{filepath}:{node.lineno} - subprocess peligroso")
                        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                            if node.func.attr == "execute" and isinstance(node.func.value, ast.Attribute):
                                peligrosos.append(f"{filepath}:{node.lineno} - posible SQL injection")
                    archivos_analizados += 1
                except (SyntaxError, Exception):
                    continue

        if peligrosos:
            log = "Se encontraron patrones peligrosos:\n" + "\n".join(peligrosos)
            details = f"Archivos analizados: {archivos_analizados}. Revisa y mitiga cada hallazgo."
            return {"success": True, "log": log, "details": details}
        else:
            log = f"No se encontraron patrones peligrosos en {archivos_analizados} archivos Python."
            return {"success": True, "log": log, "details": "AST analysis completado sin hallazgos."}


class DockerSandboxPlugin(BaseVerificationPlugin):
    """Intenta construir y lanzar un contenedor Docker desde el proyecto."""
    name = "Sandbox Docker"
    description = "Construye y ejecuta un contenedor Docker para validar configuraciones."

    def verificar(self, target_path: str, context: dict) -> dict:
        console.print("\n[bold yellow][*] Verificando Docker en el proyecto...[/bold yellow]")
        if not shutil.which("docker"):
            return {
                "success": False,
                "log": "Docker no está instalado o no disponible en el PATH.",
                "details": "Instala Docker Desktop para usar este verificador."
            }
        dockerfile = os.path.join(target_path, "Dockerfile")
        if not os.path.exists(dockerfile):
            return {
                "success": False,
                "log": "No se encontró Dockerfile en la ruta especificada.",
                "details": "Crea un Dockerfile en la raíz del proyecto para usar este verificador."
            }
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                t = progress.add_task("[cyan]Construyendo imagen Docker...", total=None)
                build = subprocess.run(
                    ["docker", "build", "-q", target_path],
                    capture_output=True, text=True, timeout=120
                )
                progress.update(t, completed=True)

            if build.returncode != 0:
                return {
                    "success": False,
                    "log": f"Error al construir la imagen:\n{build.stderr.strip()}",
                    "details": "Corrige el Dockerfile e inténtalo de nuevo."
                }
            image_id = build.stdout.strip()
            return {
                "success": True,
                "log": f"Imagen construida exitosamente: {image_id[:20] if image_id else 'OK'}",
                "details": "El Dockerfile es válido y la imagen se construyó correctamente."
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "log": "Docker build agotó el tiempo de espera.", "details": ""}
        except Exception as e:
            return {"success": False, "log": f"Error: {str(e)}", "details": ""}


PLUGINS_REGISTRY: dict[str, type[BaseVerificationPlugin]] = {
    "bandit": BanditVerifierPlugin,
    "semgrep": SemgrepVerifierPlugin,
    "ast": AstAnalyzerPlugin,
    "docker": DockerSandboxPlugin,
}


def registrar_plugin(clave: str, plugin_class: type[BaseVerificationPlugin]):
    PLUGINS_REGISTRY[clave] = plugin_class


def preguntar_y_ejecutar_verificacion(target_path: str):
    console.print("\n" + "─" * 60)
    confirmar = Confirm.ask(
        "[bold cyan]¿Desea iniciar la fase de verificación dinámica para validar estos hallazgos?[/bold cyan]",
        default=False
    )
    if not confirmar:
        console.print("[yellow][*] Auditoría finalizada de forma segura. No se ejecutaron verificaciones dinámicas.[/yellow]")
        return

    console.print("\n[bold green]=== Módulos de Verificación Dinámica Disponibles ===[/bold green]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Índice", style="dim", width=6)
    table.add_column("Clave", style="cyan")
    table.add_column("Nombre del Módulo")
    table.add_column("Descripción")

    claves = list(PLUGINS_REGISTRY.keys())
    for idx, clave in enumerate(claves, start=1):
        plugin = PLUGINS_REGISTRY[clave]
        table.add_row(str(idx), clave, plugin.name, plugin.description)
    console.print(table)

    seleccion = Prompt.ask(
        "Seleccione la clave del módulo que desea ejecutar (o presione Enter para salir)",
        choices=claves + [""],
        default=""
    )
    if not seleccion:
        console.print("[yellow][*] Verificación dinámica cancelada por el usuario.[/yellow]")
        return

    plugin_class = PLUGINS_REGISTRY[seleccion]
    plugin_instance = plugin_class()
    try:
        resultado = plugin_instance.verificar(target_path, {})
        console.print("\n[bold green]✔ Verificación Ejecutada[/bold green]")
        console.print(Panel(resultado["log"], title="Logs del Verificador", border_style="green"))
        if resultado["details"]:
            console.print(Panel(resultado["details"], title="Detalles", border_style="blue"))
    except Exception as e:
        console.print(f"[bold red][Error] Fallo al ejecutar el plugin: {str(e)}[/bold red]")
