from __future__ import annotations

import select
import subprocess
import threading
import time
from typing import Any

from core.logging import get_logger

logger = get_logger()


def run_command(
    cmd: list[str],
    description: str = "",
    timeout: int = 300,
    capture_output: bool = True,
    stream: bool = True,
    line_callback: callable | None = None,
) -> dict[str, Any]:
    """Ejecuta un comando con timeout, streaming y captura de output.

    Args:
        cmd: Comando y argumentos como lista
        description: Descripción legible para logging
        timeout: Timeout en segundos (default 300)
        capture_output: Si True, captura stdout/stderr
        stream: Si True, muestra output en tiempo real

    Returns:
        dict con: returncode, stdout, stderr, timed_out
    """
    phase = "run"
    if description:
        logger.info(phase, f"Ejecutando: {description}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        logger.error(phase, f"Comando no encontrado: {cmd[0]}")
        return {"returncode": -1, "stdout": "", "stderr": f"Command not found: {cmd[0]}", "timed_out": False}
    except PermissionError:
        logger.error(phase, f"Permiso denegado: {cmd[0]}")
        return {"returncode": -1, "stdout": "", "stderr": f"Permission denied: {cmd[0]}", "timed_out": False}

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    timed_out = False

    def _reader(pipe, storage, prefix: str = ""):
        for line in iter(pipe.readline, ""):
            if line:
                storage.append(line)
                if line_callback:
                    line_callback(line.rstrip())
                if stream and description:
                    display = line.rstrip()[:200]
                    logger.debug(phase, f"{prefix}{display}")

    threads = []
    if capture_output and proc.stdout:
        t = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, ""), daemon=True)
        t.start()
        threads.append(t)
    if capture_output and proc.stderr:
        t = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, "[STDERR] "), daemon=True)
        t.start()
        threads.append(t)

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
        logger.warn(phase, f"Timeout {timeout}s: {description or cmd[0]}")

    for t in threads:
        t.join(timeout=5)

    stdout = "".join(stdout_lines)
    stderr = "".join(stderr_lines)

    if proc.returncode != 0 and not timed_out:
        logger.warn(phase, f"Exit code {proc.returncode}: {description or cmd[0]}")

    return {
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    }
