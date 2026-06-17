from __future__ import annotations

import subprocess
import re
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class NmapEngine(BaseEngine):
    name = "nmap"
    description = "Port scanner and service detector. Descubre puertos abiertos, servicios, versiones y SO."
    capabilities = ["port_scan", "service_detection", "os_detection", "network_recon"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        ports = kwargs.get("ports", "")
        progress_cb = kwargs.get("progress_callback")
        args = [
            "nmap", "-sV", "-sC", "--min-rate", "5000", "-T5",
            "--script=vuln", "-oX", "-", "--stats-every", "2s",
        ]
        if ports:
            args.extend(["-p", ports])
        else:
            args.extend(["-p-"])
        args.append(target)

        line_cb = None
        if progress_cb:
            _prog_re = re.compile(r"about (\d+)\.\d+s remaining")
            def line_cb(line: str) -> None:
                m = _prog_re.search(line)
                if m:
                    remaining = float(m.group(1))
                    pct = max(0, min(95, int(100 - remaining / 5)))
                    progress_cb(pct)

        try:
            raw, stderr, timed_out = self.run_subprocess(args, timeout=kwargs.get("timeout", 600), line_callback=line_cb)
            if not raw.strip():
                msg = "nmap: partial output (timeout)" if timed_out else "nmap: no output"
                return EngineResult(success=timed_out, raw_output="", summary=msg, error=stderr[:500])
            findings = self.parse_output(raw)
            if progress_cb:
                progress_cb(100)
            summary = f"nmap: {len(findings)} ports open on {target}"
            if timed_out:
                summary += " (partial, timeout)"
            return EngineResult(
                success=True, raw_output=raw, findings=findings,
                summary=summary,
            )
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="nmap: not installed", error="Install nmap")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"nmap: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_output)
            for host in root.findall(".//host"):
                ip = host.find(".//address").get("addr", "") if host.find(".//address") is not None else ""
                for port in host.findall(".//port"):
                    port_id = port.get("portid", "")
                    protocol = port.get("protocol", "")
                    state_el = port.find("state")
                    port_state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                    service = port.find("service")
                    service_name = service.get("name", "unknown") if service is not None else "unknown"
                    service_product = service.get("product", "") if service is not None else ""
                    service_version = service.get("version", "") if service is not None else ""
                    findings.append({
                        "file_path": ip,
                        "line_start": 0, "line_end": 0,
                        "severity": "info" if port_state == "open" else "low",
                        "title": f"{'Open' if port_state == 'open' else 'Filtered'} port: {port_id}/{protocol} - {service_name}",
                        "description": f"Port {port_id}/{protocol} is {port_state}. Service: {service_name} {service_product} {service_version}".strip(),
                        "tool": self.name,
                        "rule_id": f"port-{port_id}",
                        "port": int(port_id),
                        "protocol": protocol,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                        "state": port_state,
                        "ip": ip,
                    })
                    if port_state != "open":
                        continue

                    # Parse vuln script results
                    for script in port.findall("script"):
                        script_id = script.get("id", "")
                        script_out = script.get("output", "")
                        if not script_out:
                            continue
                        # Check for CVEs in vulners output
                        for line in script_out.split("\n"):
                            line = line.strip()
                            if not line:
                                continue
                            cve_match = re.search(r"(CVE-\d{4}-\d+)", line, re.IGNORECASE)
                            if cve_match:
                                findings.append({
                                    "file_path": ip,
                                    "line_start": 0, "line_end": 0,
                                    "severity": "high",
                                    "title": f"CVE: {cve_match.group(1)} ({script_id})",
                                    "description": line[:300],
                                    "tool": self.name,
                                    "rule_id": f"nmap-vuln-{cve_match.group(1).lower()}",
                                    "port": int(port_id),
                                    "protocol": protocol,
                                    "cve_id": cve_match.group(1),
                                    "ip": ip,
                                })

            # Host-level scripts (not per-port)
            for script in host.findall("script"):
                script_id = script.get("id", "")
                script_out = script.get("output", "")
                if script_out and "vuln" in script_id.lower():
                    findings.append({
                        "file_path": ip,
                        "line_start": 0, "line_end": 0,
                        "severity": "medium",
                        "title": f"Script: {script_id}",
                        "description": script_out[:500],
                        "tool": self.name,
                        "rule_id": f"nmap-script-{script_id}",
                        "ip": ip,
                    })

        except ET.ParseError:
            pass
        return findings
