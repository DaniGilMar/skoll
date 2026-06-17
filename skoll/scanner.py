import shutil
import subprocess
import sys


def is_tool_installed(name: str) -> bool:
    return shutil.which(name) is not None

def ejecutar_bandit(target_path: str) -> str:
    bandit_cmd = [sys.executable, "-m", "bandit"]
    try:
        process = subprocess.run(
            bandit_cmd + ["-r", target_path, "-f", "txt", "-q"],
            capture_output=True, text=True
        )
        output = process.stdout.strip()
        if not output:
            output = "No se encontraron vulnerabilidades obvias usando Bandit."
        return output
    except FileNotFoundError:
        return "[Error: Bandit no está instalado. Instálalo con 'pip install bandit']."
    except Exception as e:
        return f"[Error al ejecutar Bandit: {str(e)}]"

def ejecutar_semgrep(target_path: str) -> str:
    if not is_tool_installed("semgrep"):
        return "[Error: Semgrep no está instalado. Instálalo con 'pip install semgrep']."
    try:
        process = subprocess.run(
            ["semgrep", "scan", "--config", "auto", target_path, "--quiet"],
            capture_output=True, text=True
        )
        output = process.stdout.strip()
        if not output:
            output = "No se encontraron vulnerabilidades obvias usando Semgrep."
        return output
    except Exception as e:
        return f"[Error al ejecutar Semgrep: {str(e)}]"

def ejecutar_escaneo_sast(target_path: str, tool: str = "all") -> dict:
    resultados = {}
    tool = tool.lower()

    if tool in ("bandit", "all"):
        resultados["bandit"] = ejecutar_bandit(target_path)

    if tool in ("semgrep", "all"):
        resultados["semgrep"] = ejecutar_semgrep(target_path)

    return resultados
