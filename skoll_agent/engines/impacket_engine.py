from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


IMPACKET_EXAMPLES = "/usr/share/doc/python3-impacket/examples"


class ImpacketEngine(BaseEngine):
    name = "impacket"
    description = "Impacket toolkit: secretsdump, wmiexec, psexec, smbexec, atexec, dcomexec. Movimiento lateral y dumpeo de credenciales."
    capabilities = ["ad_audit", "lateral_movement", "credential_dump", "active_directory", "exploitation"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        domain = kwargs.get("domain", "")
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        dc_ip = kwargs.get("dc_ip", target)
        timeout = int(kwargs.get("timeout", 120))
        ntlm_hash = kwargs.get("ntlm_hash", "")

        if not username:
            raw_lines.append("[WARN] Impacket requiere username")
            return EngineResult(
                success=False, raw_output="impacket: requiere username",
                summary="impacket: faltan credenciales",
                findings=[{
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "Impacket requiere credenciales",
                    "description": "Se necesita username/password o NTLM hash para usar impacket",
                    "tool": self.name,
                    "rule_id": "impacket-needs-creds",
                }],
            )

        auth = f"{domain}/{username}:{password}" if password else f"{domain}/{username}"
        has_lm = f"--hashes :{ntlm_hash}" if ntlm_hash else ""

        # 1. secretsdump — dump SAM/LSA/NTDS
        if kwargs.get("secretsdump", True):
            self._secretsdump(dc_ip, domain, username, password, ntlm_hash, findings, raw_lines, timeout)

        # 2. wmiexec — WMI command execution
        if kwargs.get("wmiexec", False):
            self._wmiexec(dc_ip, domain, username, password, ntlm_hash, findings, raw_lines, timeout)

        # 3. Lookup SID
        if kwargs.get("lookupsid", True):
            self._lookupsid(dc_ip, domain, username, password, ntlm_hash, findings, raw_lines, timeout)

        summary = f"impacket: {len(findings)} hallazgos en {target}"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _secretsdump(self, dc_ip: str, domain: str, username: str,
                     password: str, ntlm_hash: str,
                     findings: list[dict[str, Any]],
                     raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] secretsdump contra {dc_ip}...")

        try:
            if ntlm_hash:
                args = [
                    "python3", f"{IMPACKET_EXAMPLES}/secretsdump.py",
                    f"{domain}/{username}@{dc_ip}" if "@" not in f"{domain}/{username}" else f"{domain}/{username}",
                    "--hashes", f":{ntlm_hash}",
                ]
            else:
                args = [
                    "python3", f"{IMPACKET_EXAMPLES}/secretsdump.py",
                    f"{domain}/{username}:{password}@{dc_ip}",
                ]

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr

            if "Error" in output and "DCERPCSessionError" in output:
                raw_lines.append(f"[INFO] secretsdump: acceso denegado (falta de privilegios)")
                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": "secretsdump: acceso denegado",
                    "description": f"No se pudo ejecutar secretsdump contra {dc_ip}. Puede requerir privilegios de administrador en el DC.",
                    "tool": self.name,
                    "rule_id": "impacket-secretsdump-denied",
                })
            elif "Dumping" in output or "SAM" in output or "hashes" in output.lower():
                # Extract hashes
                hash_pattern = re.findall(r"(.+?):(\d+):[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", output)
                if hash_pattern:
                    raw_lines.append(f"[CRITICAL] secretsdump: {len(hash_pattern)} hashes extraidos!")

                    # Group by user for findings (first 10)
                    for user, rid, *_ in hash_pattern[:10]:
                        findings.append({
                            "file_path": dc_ip,
                            "line_start": 0, "line_end": 0,
                            "severity": "critical",
                            "title": f"Credenciales dumpeadas: {user} (RID {rid})",
                            "description": f"Hash NTLM del usuario {user} extraido via secretsdump de {dc_ip}",
                            "tool": self.name,
                            "rule_id": f"impacket-dump-{user.lower()}",
                            "username": user,
                            "rid": rid,
                        })

                    findings.append({
                        "file_path": dc_ip,
                        "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": f"secretsdump: {len(hash_pattern)} cuentas comprometidas",
                        "description": f"Se extrajeron {len(hash_pattern)} hashes NTLM del DC {dc_ip} via secretsdump",
                        "tool": self.name,
                        "rule_id": "impacket-dump-summary",
                        "hash_count": len(hash_pattern),
                    })
                else:
                    raw_lines.append(f"[INFO] secretsdump ejecutado pero no se encontraron hashes nuevos")
                    raw_lines.append(f"  Output sample: {output[:500]}")
            else:
                raw_lines.append(f"[INFO] secretsdump: sin resultados utiles")
                if output.strip():
                    raw_lines.append(f"  Output: {output[:500]}")

        except FileNotFoundError:
            raw_lines.append("[WARN] secretsdump.py not found")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] secretsdump timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] secretsdump: {e}")

    def _wmiexec(self, dc_ip: str, domain: str, username: str,
                 password: str, ntlm_hash: str,
                 findings: list[dict[str, Any]],
                 raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] wmiexec — ejecutando comando en {dc_ip}...")

        command = "whoami"
        try:
            if ntlm_hash:
                args = [
                    "python3", f"{IMPACKET_EXAMPLES}/wmiexec.py",
                    f"{domain}/{username}@{dc_ip}",
                    "--hashes", f":{ntlm_hash}",
                    command,
                ]
            else:
                args = [
                    "python3", f"{IMPACKET_EXAMPLES}/wmiexec.py",
                    f"{domain}/{username}:{password}@{dc_ip}",
                    command,
                ]

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr

            if "ERROR_" in output:
                raw_lines.append(f"[ERR] wmiexec: {output[:200]}")
            elif command in output:
                user_info = output.strip()
                raw_lines.append(f"[INFO] wmiexec: Comando ejecutado — {user_info}")
                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Ejecucion remota via WMI en {dc_ip}",
                    "description": f"Se ejecuto comando via wmiexec en {dc_ip}. Resultado: {user_info}",
                    "tool": self.name,
                    "rule_id": "impacket-wmi-exec",
                })
            else:
                raw_lines.append(f"[INFO] wmiexec output: {output[:300]}")

        except FileNotFoundError:
            raw_lines.append("[WARN] wmiexec.py not found")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] wmiexec timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] wmiexec: {e}")

    def _lookupsid(self, dc_ip: str, domain: str, username: str,
                   password: str, ntlm_hash: str,
                   findings: list[dict[str, Any]],
                   raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] lookupsid — enumerando SID en {dc_ip}...")

        try:
            args = [
                "python3", f"{IMPACKET_EXAMPLES}/lookupsid.py",
                f"{domain}/{username}:{password}@{dc_ip}",
            ] if not ntlm_hash else [
                "python3", f"{IMPACKET_EXAMPLES}/lookupsid.py",
                f"{domain}/{username}@{dc_ip}",
                "--hashes", f":{ntlm_hash}",
            ]

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr

            if "error" in output.lower() and "Access denied" in output:
                raw_lines.append("[INFO] lookupsid: acceso denegado")
            elif "Sid" in output or "S-1-" in output:
                sids = re.findall(r"\(S-1-\d+-\d+-\d+-\d+-\d+-\d+\)", output)
                users_found = len(re.findall(r"\\\w+", output))
                raw_lines.append(f"[INFO] lookupsid: {len(sids)} SIDs, ~{users_found} usuarios encontrados")
                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"SID enumeration: ~{users_found} usuarios via lookupsid",
                    "description": f"Enumerados ~{users_found} usuarios del dominio via lookupsid contra {dc_ip}",
                    "tool": self.name,
                    "rule_id": "impacket-lookupsid",
                    "user_count": users_found,
                })
            else:
                raw_lines.append(f"[INFO] lookupsid output: {output[:300]}")

        except FileNotFoundError:
            raw_lines.append("[WARN] lookupsid.py not found")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] lookupsid timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] lookupsid: {e}")

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
