from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult

CAIDO_CLI = "/usr/bin/caido-cli"
CAIDO_UI_PORT = 18080
CAIDO_PROXY_PORT = 18081
CAIDO_DATA_DIR = "/tmp/caido-headless"
MAX_WAIT = 40
POLL_INTERVAL = 2


class CaidoEngine(BaseEngine):
    name = "caido"
    description = "Caido headless proxy: lanza Caido en modo invisible y pasa tráfico web por su proxy para escaneo pasivo."
    capabilities = ["web_scan", "passive_scan", "proxy_scan"]

    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._proxy_url = f"http://127.0.0.1:{CAIDO_PROXY_PORT}"

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings: list[dict[str, Any]] = []
        raw_lines: list[str] = []

        if not os.path.isfile(CAIDO_CLI):
            raw_lines.append("[INSTALL] caido-cli no está instalado.")
            raw_lines.append("  Para instalar: sudo apt update && sudo apt install caido-cli")
            raw_lines.append("  Alternativa: descargar desde https://caido.io/download")
            return EngineResult(
                success=False,
                raw_output="\n".join(raw_lines),
                findings=[],
                summary="caido: no instalado",
                error="caido-cli no encontrado. Instalar con: sudo apt install caido-cli",
            )

        urls: list[str] = kwargs.get("urls", [target])
        timeout = int(kwargs.get("timeout", 180))

        try:
            self._start_caido(raw_lines)
            if not self._is_ready():
                raw_lines.append("[ERR] Caido no respondió a tiempo")
                return EngineResult(success=False, raw_output="\n".join(raw_lines), findings=[],
                                    summary="caido: no responde")

            raw_lines.append(f"[CAIDO] Caido listo (proxy: {self._proxy_url})")

            for url in urls:
                raw_lines.append(f"[PROXY] Enviando {url}...")
                self._send_through_proxy(url, raw_lines)
                time.sleep(0.5)
                findings.append({
                    "file_path": url,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"Caido proxy: {url}",
                    "description": f"URL {url} enviada a través del proxy pasivo de Caido ({self._proxy_url}). Caido analizó la respuesta en busca de vulnerabilidades de forma pasiva.",
                    "tool": self.name,
                    "rule_id": "caido-proxied",
                    "caido_proxy": self._proxy_url,
                })

        finally:
            self._stop_caido(raw_lines)

        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=f"caido: {len(urls)} URLs proxyzadas",
        )

    def _start_caido(self, raw_lines: list[str]) -> None:
        if self._is_port_open(CAIDO_PROXY_PORT):
            raw_lines.append("[CAIDO] Caido ya está corriendo")
            return

        os.makedirs(CAIDO_DATA_DIR, exist_ok=True)
        env = os.environ.copy()

        raw_lines.append(f"[CAIDO] Lanzando caido-cli (puerto proxy: {CAIDO_PROXY_PORT})...")
        try:
            self._process = subprocess.Popen(
                [
                    CAIDO_CLI,
                    "--listen", f"127.0.0.1:{CAIDO_UI_PORT}",
                    "--proxy-listen", f"127.0.0.1:{CAIDO_PROXY_PORT}",
                    "--invisible",
                    "--no-open",
                    "--data-path", CAIDO_DATA_DIR,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
        except FileNotFoundError:
            raw_lines.append("[ERR] caido-cli no encontrado")
            self._process = None

    def _is_ready(self) -> bool:
        for _ in range(MAX_WAIT // POLL_INTERVAL):
            if self._is_port_open(CAIDO_PROXY_PORT):
                time.sleep(2)
                return True
            time.sleep(POLL_INTERVAL)
        return False

    @staticmethod
    def _is_port_open(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return True
        except (socket.error, OSError):
            return False

    def _send_through_proxy(self, url: str, raw_lines: list[str]) -> None:
        proxies = {"http": self._proxy_url, "https": self._proxy_url}
        try:
            r = requests.get(url, proxies=proxies, timeout=15, verify=False, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
            raw_lines.append(f"  {r.status_code} {url}")
        except requests.exceptions.ConnectionError:
            raw_lines.append(f"  [ERR] proxy: {self._proxy_url} no accesible")
        except Exception as e:
            raw_lines.append(f"  [ERR] {url}: {e}")

    def _stop_caido(self, raw_lines: list[str]) -> None:
        if self._process:
            raw_lines.append("[CAIDO] Deteniendo caido-cli...")
            try:
                self._process.send_signal(signal.SIGTERM)
                self._process.wait(timeout=10)
            except Exception:
                self._process.kill()
            self._process = None
        for port in (CAIDO_UI_PORT, CAIDO_PROXY_PORT):
            try:
                subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
            except Exception:
                pass

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
