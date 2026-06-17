from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class BloodHoundEngine(BaseEngine):
    name = "bloodhound"
    description = "BloodHound AD collector. Recolecta datos del dominio Active Directory para analisis de rutas de ataque (ACE, ACL, Group Membership, Sessions)."
    capabilities = ["ad_audit", "bloodhound", "enumeration", "active_directory", "recon"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        domain = kwargs.get("domain", target)
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        dc_ip = kwargs.get("dc_ip", target)
        timeout = int(kwargs.get("timeout", 180))
        collection_method = kwargs.get("collection_method", "All")
        zip_output = kwargs.get("zip_output", "")
        namespace = kwargs.get("namespace", "")

        if not username or not password:
            raw_lines.append("[WARN] BloodHound requiere credenciales de dominio")
            findings.append({
                "file_path": target,
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "BloodHound necesita credenciales",
                "description": "Se requieren credenciales de dominio validas para ejecutar BloodHound collector",
                "tool": self.name,
                "rule_id": "bh-needs-creds",
            })
            return EngineResult(
                success=False,
                raw_output="bloodhound: necesita credenciales",
                findings=findings,
                summary="bloodhound: faltan credenciales",
            )

        raw_lines.append(f"[INFO] BloodHound recolectando datos de {domain} (DC: {dc_ip})")

        # Usar bloodhound-python
        out_dir = "/tmp/bloodhound_data"
        os.makedirs(out_dir, exist_ok=True)

        args = [
            "bloodhound-python",
            "-d", domain,
            "-u", username,
            "-p", password,
            "-dc", dc_ip,
            "-c", collection_method,
            "--zip",
            "--outputdir", out_dir,
            "--dns-timeout", "5",
        ]
        if namespace:
            args.extend(["--nameserver", namespace])
        if kwargs.get("disable_pooling", False):
            args.append("--disable-pooling")
        if kwargs.get("use_ldaps", False):
            args.append("--use-ldaps")

        raw_lines.append(f"[INFO] Ejecutando: {' '.join(args)}")

        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            stdout = result.stdout
            stderr = result.stderr
            combined = stdout + stderr

            raw_lines.append(f"[INFO] bloodhound-python exit code: {result.returncode}")

            # Parse results
            if "Error" in stderr and "connection" in stderr.lower():
                raw_lines.append(f"[ERR] Error de conexion: {stderr[:300]}")
                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": "BloodHound: error de conexion al DC",
                    "description": f"No se pudo conectar al DC {dc_ip} para recoleccion BloodHound: {stderr[:200]}",
                    "tool": self.name,
                    "rule_id": "bh-connection-error",
                })
                return EngineResult(
                    success=False,
                    raw_output="\n".join(raw_lines),
                    findings=findings,
                    summary="bloodhound: error de conexion",
                )

            # Check for output files
            output_files = []
            for f in os.listdir(out_dir):
                if f.endswith(".json") or f.endswith(".zip"):
                    output_files.append(f)
                    raw_lines.append(f"[INFO] Output: {os.path.join(out_dir, f)}")

            # Parse JSON files for findings
            for fname in output_files:
                if not fname.endswith(".json"):
                    continue
                fpath = os.path.join(out_dir, fname)
                try:
                    with open(fpath) as f:
                        data = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    continue

                # Find high-value targets
                if "data" in data:
                    items = data["data"] if isinstance(data["data"], list) else [data["data"]]
                    for item in items:
                        props = item.get("Properties", {})
                        stype = item.get("type", "")

                        if stype == "user" and props.get("enabled", True):
                            # Check for high-value user attributes
                            if props.get("admincount") or props.get("isadmin"):
                                findings.append({
                                    "file_path": dc_ip,
                                    "line_start": 0, "line_end": 0,
                                    "severity": "high",
                                    "title": f"Usuario administrativo: {props.get('samaccountname', '?')}",
                                    "description": f"Usuario con privilegios administrativos encontrado via BloodHound: {props.get('samaccountname', '?')}@{domain}",
                                    "tool": self.name,
                                    "rule_id": f"bh-admin-{props.get('samaccountname', '?').lower()}",
                                    "username": props.get("samaccountname", ""),
                                    "domain": domain,
                                })

                        if stype == "group" and props.get("admincount"):
                            findings.append({
                                "file_path": dc_ip,
                                "line_start": 0, "line_end": 0,
                                "severity": "high",
                                "title": f"Grupo privilegiado: {props.get('name', '?')}",
                                "description": f"Grupo con adminCount=1 encontrado en {domain}: {props.get('name', '?')}",
                                "tool": self.name,
                                "rule_id": f"bh-priv-group-{props.get('name', '?').lower().replace(' ', '-')}",
                            })

                        if stype == "computer" and props.get("enabled"):
                            if props.get("operatingsystem"):
                                os_ver = props.get("operatingsystem", "")
                                if any(w in os_ver for w in ["2008", "2012", "Windows 7", "Windows 8"]):
                                    findings.append({
                                        "file_path": dc_ip,
                                        "line_start": 0, "line_end": 0,
                                        "severity": "medium",
                                        "title": f"SO desactualizado: {os_ver}",
                                        "description": f"Equipo {props.get('samaccountname', '?')} corriendo {os_ver} — posiblemente sin parches de seguridad",
                                        "tool": self.name,
                                        "rule_id": f"bh-old-os-{props.get('samaccountname', '?').lower()}",
                                        "computer": props.get("samaccountname", ""),
                                        "os": os_ver,
                                    })

            # Summary finding
            if output_files:
                total_json = len([f for f in output_files if f.endswith(".json")])
                total_zip = len([f for f in output_files if f.endswith(".zip")])
                findings_count = len(findings)
                raw_lines.append(f"[INFO] BloodHound: {total_json} JSON, {total_zip} ZIP generados")
                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"BloodHound: recoleccion completada en {domain}",
                    "description": f"Recolectados datos del dominio {domain}. {findings_count} hallazgos durante la recoleccion. JSON/CSV disponibles en {out_dir}",
                    "tool": self.name,
                    "rule_id": "bh-collection-complete",
                    "domain": domain,
                    "output_dir": out_dir,
                    "files": output_files,
                })

        except FileNotFoundError:
            raw_lines.append("[WARN] bloodhound-python not installed")
            findings.append({
                "file_path": target,
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "BloodHound no instalado",
                "description": "bloodhound-python no esta instalado. Instalar con: pip install bloodhound",
                "tool": self.name,
                "rule_id": "bh-not-installed",
            })
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] BloodHound collection timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] BloodHound: {e}")

        summary = f"bloodhound: {len(findings)} hallazgos en {domain}"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
