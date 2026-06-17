from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

SANDBOX_DOCKERFILE = """FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir bandit semgrep
WORKDIR /workspace
COPY . /workspace
"""


class DockerSandbox:
    def __init__(self, image_name: str = "skoll-sandbox:latest"):
        self.image_name = image_name
        self._container_id: str | None = None

    def ensure_image(self) -> bool:
        if shutil.which("docker") is None:
            console.print("[red]Docker no está instalado. Sandbox deshabilitado.[/red]")
            return False

        existing = subprocess.run(
            ["docker", "images", "-q", self.image_name],
            capture_output=True, text=True,
        )
        if existing.stdout.strip():
            return True

        console.print("[yellow]Construyendo imagen sandbox Docker...[/yellow]")
        with tempfile.TemporaryDirectory() as tmpdir:
            df_path = os.path.join(tmpdir, "Dockerfile")
            with open(df_path, "w") as f:
                f.write(SANDBOX_DOCKERFILE)
            result = subprocess.run(
                ["docker", "build", "-t", self.image_name, tmpdir],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                console.print(f"[red]Error construyendo sandbox: {result.stderr}[/red]")
                return False
        console.print("[green]✓ Sandbox image built[/green]")
        return True

    def run_in_sandbox(self, project_path: str, command: list[str]) -> dict[str, Any]:
        if not self.ensure_image():
            return {"success": False, "stdout": "", "stderr": "Docker not available"}

        abs_path = os.path.abspath(project_path)
        mount = f"{abs_path}:/workspace"

        try:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", mount,
                    self.image_name,
                ] + command,
                capture_output=True, text=True, timeout=300,
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "stdout": "", "stderr": "Timeout (300s)"}
        except Exception as e:
            return {"success": False, "stdout": "", "stderr": str(e)}

    def scan_in_sandbox(self, project_path: str, tool: str = "bandit") -> dict[str, Any]:
        tool_cmd = {
            "bandit": ["bandit", "-r", "/workspace", "-f", "json", "-q"],
            "semgrep": ["semgrep", "scan", "--config", "auto", "/workspace", "--json", "--quiet"],
        }
        cmd = tool_cmd.get(tool, tool_cmd["bandit"])
        return self.run_in_sandbox(project_path, cmd)

    def cleanup(self) -> None:
        if self._container_id:
            subprocess.run(["docker", "rm", "-f", self._container_id], capture_output=True)
            self._container_id = None
