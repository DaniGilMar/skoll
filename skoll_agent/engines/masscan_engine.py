from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class MasscanEngine(BaseEngine):
    name = "masscan"
    description = "Escaneo de puertos masivo ultra-rápido. Pre-scan antes de nmap para detectar puertos abiertos en segundos."
    capabilities = ["port_scan", "fast_discovery", "pre_nmap"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        ports = kwargs.get("ports", "1-65535")
        rate = int(kwargs.get("rate", 50000))
        timeout_s = int(kwargs.get("timeout", 120))

        fd, out_file = tempfile.mkstemp(suffix=".json", prefix="masscan_")
        os.close(fd)
        args = [
            "sudo", "masscan", target, "-p", ports,
            "--rate", str(rate), "-oJ", out_file,
            "--open-only", "--wait", "0",
        ]

        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout_s,
            )
            raw = result.stdout + result.stderr
            findings = []
            open_ports = []

            try:
                with open(out_file) as f:
                    for line in f:
                        line = line.strip().rstrip(",")
                        if not line or line in ("[", "]"):
                            continue
                        entry = json.loads(line)
                        port = entry.get("ports", [{}])[0]
                        pnum = port.get("port", 0)
                        proto = port.get("proto", "tcp")
                        ip = entry.get("ip", target)
                        pdata = {"port": pnum, "protocol": proto, "ip": ip}
                        open_ports.append(pdata)
                        findings.append({
                            "line_start": 0, "line_end": 0,
                            "severity": "info",
                            "title": f"Open port: {pnum}/{proto}",
                            "description": f"Open port {pnum}/{proto} on {ip}",
                            "tool": self.name,
                            "rule_id": f"masscan-{pnum}",
                            "port": pnum, "protocol": proto, "ip": ip,
                        })
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            summary = f"masscan: {len(open_ports)} open ports (rate={rate})"
            return EngineResult(
                success=len(open_ports) > 0, raw_output=raw,
                findings=findings, summary=summary, error="",
            )
        except subprocess.TimeoutExpired:
            partial = []
            try:
                with open(out_file) as f:
                    for line in f:
                        line = line.strip().rstrip(",")
                        if not line or line in ("[", "]"):
                            continue
                        entry = json.loads(line)
                        port = entry.get("ports", [{}])[0]
                        partial.append(port.get("port", 0))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            return EngineResult(
                success=len(partial) > 0, raw_output="",
                summary=f"masscan: timeout, {len(partial)} ports found so far",
                error="Timeout",
            )
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="masscan: not installed", error="Install masscan")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"masscan: {e}", error=str(e))
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
