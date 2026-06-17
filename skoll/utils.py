import os

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

console = Console()

# Extensiones de texto comunes que contienen código fuente de interés
INTERESTING_EXTENSIONS = {
    ".py", ".sh", ".bash", ".js", ".ts", ".go", ".rs", ".c", ".cpp", ".h",
    ".json", ".yaml", ".yml", ".tf", ".tfvars", ".rb", ".php", ".ini",
    ".conf", ".java", ".gradle", ".properties", ".toml", ".md", ".dockerfile"
}

# Carpetas y archivos a ignorar durante un escaneo recursivo (evitar excesos de tokens y binarios)
EXCLUDE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist",
    "target", ".idea", ".vscode", "tmp", "coverage", ".gemini", "brain"
}

def leer_archivo(filepath: str) -> str:
    """Intenta leer el contenido de un archivo de texto de forma segura."""
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return f"[No se pudo leer el archivo: {str(e)}]"

def es_extension_valida(filename: str) -> bool:
    """Verifica si la extensión del archivo es candidata para auditoría."""
    ext = os.path.splitext(filename)[1].lower()
    # Si no tiene extensión pero se llama 'Dockerfile', lo permitimos
    if not ext and filename.lower() == "dockerfile":
        return True
    return ext in INTERESTING_EXTENSIONS

def es_directorio_excluido(dirpath: str) -> bool:
    """Verifica si la ruta contiene alguna de las carpetas excluidas."""
    parts = dirpath.split(os.sep)
    return any(ex in parts for ex in EXCLUDE_DIRS)

def escanear_directorio(dirpath: str, max_chars: int = 150000) -> str:
    """
    Escanea recursivamente un directorio, filtra archivos binarios o excluidos,
    y compila un contexto en texto legible para enviar a la IA.
    """
    contexto = []
    total_chars = 0

    for root, dirs, files in os.walk(dirpath):
        # Filtrado in-place de directorios excluidos para evitar descender en ellos
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            if not es_extension_valida(file):
                continue

            filepath = os.path.join(root, file)
            # Doble chequeo de ruta para carpetas excluidas
            if es_directorio_excluido(filepath):
                continue

            rel_path = os.path.relpath(filepath, dirpath)
            content = leer_archivo(filepath)

            # Limitar tamaño acumulado
            if total_chars + len(content) > max_chars:
                contexto.append(
                    f"--- ARCHIVO: {rel_path} (TRUNCADO POR LÍMITE DE TAMAÑO) ---\n"
                    "[El archivo no fue cargado completamente para evitar superar el contexto CLI]\n"
                )
                break

            contexto.append(
                f"--- ARCHIVO: {rel_path} ---\n"
                f"{content}\n"
                f"-------------------------\n"
            )
            total_chars += len(content)

    if not contexto:
        return "No se encontraron archivos de código fuente válidos para analizar en este directorio."

    return "\n".join(contexto)

def mostrar_error_api_key(error_msg: str):
    """Muestra un panel estilizado para advertir sobre la falta de API Key."""
    error_panel = Panel(
        f"[bold red]Acceso Denegado / Variable Faltante[/bold red]\n\n"
        f"{error_msg}\n\n"
        "[dim]Obtén tu API Key gratis en: https://aistudio.google.com/[/dim]",
        title="[bold yellow]⚠️ Error de Configuración de Gemini[/bold yellow]",
        border_style="red",
        expand=False
    )
    console.print(error_panel)

def mostrar_markdown(content: str):
    """Renderiza el contenido Markdown con formato enriquecido en la terminal."""
    md = Markdown(content)
    console.print(md)

def mostrar_error_general(msg: str):
    """Muestra un error general formateado."""
    console.print(f"[bold red]❌ Error:[/bold red] [yellow]{msg}[/yellow]")
