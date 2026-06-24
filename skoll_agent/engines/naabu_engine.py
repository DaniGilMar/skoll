from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class NaabuEngine(BaseEngine):
    name = "naabu"
    description = "Escaneo de puertos ultrarrápido (ProjectDiscovery). Priorizar sobre nmap."
    capabilities = ["port_scan", "recon", "fast_scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        binary = shutil.which("naabu")
        if not binary:
            return EngineResult(
                success=False, raw_output="", summary="naabu: not installed",
                error="naabu not found. Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            )

        clean = target.split("://")[-1].rstrip("/")
        args = ["-host", clean, "-json", "-silent"]
        if kwargs.get("ports"):
            args.extend(["-p", str(kwargs["ports"])])
        if kwargs.get("top_ports"):
            args.extend(["--top-ports", str(kwargs["top_ports"])])
        if kwargs.get("rate"):
            args.extend(["-rate", str(kwargs["rate"])])
        if kwargs.get("exclude_cdn"):
            args.append("-exclude-cdn")

        try:
            result = subprocess.run(
                [binary, *args], capture_output=True, text=True,
                timeout=kwargs.get("timeout", 120),
            )
            stdout = result.stdout.strip()
            if result.returncode != 0 and not stdout:
                return EngineResult(
                    success=False, raw_output=result.stderr,
                    summary="naabu: no ports found",
                    error=result.stderr[:500],
                )
            findings = self.parse_output(stdout)
            return EngineResult(
                success=bool(findings), raw_output=stdout, findings=findings,
                summary=f"naabu: {len(findings)} puertos en {target}",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                success=False, raw_output="", summary="naabu: timeout",
                error="Timeout (120s)",
            )
        except FileNotFoundError:
            return EngineResult(
                success=False, raw_output="", summary="naabu: not installed",
                error="Install naabu",
            )
        except Exception as e:
            return EngineResult(
                success=False, raw_output="", summary=f"naabu: {e}",
                error=str(e),
            )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        seen: set[tuple] = set()
        findings = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                port = obj.get("port")
                protocol = obj.get("protocol", "tcp")
                ip = obj.get("ip") or obj.get("address", "")
                key = (ip, port, protocol)
                if key in seen:
                    continue
                seen.add(key)
                if port:
                    findings.append({
                        "file_path": ip,
                        "line_start": 0, "line_end": 0,
                        "severity": "medium",
                        "title": f"Puerto {port}/{protocol}",
                        "description": f"Puerto abierto: {port}/{protocol} en {ip}",
                        "tool": self.name,
                        "rule_id": f"port-{port}",
                        "port": port,
                        "protocol": protocol,
                        "service": obj.get("service", ""),
                        "state": "open",
                    })
            except json.JSONDecodeError:
                pass
        return findings
