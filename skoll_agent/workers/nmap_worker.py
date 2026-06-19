from __future__ import annotations

import re
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class NmapWorker(BaseWorker):
    name = "nmap"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        clean = target.split("://")[-1].rstrip("/")
        args = ["-sV", "-T4", "--open"]
        if kwargs.get("ports"):
            args.extend(["-p", str(kwargs["ports"])])
        else:
            args.append("-p-")
        if kwargs.get("scripts"):
            args.extend(["--script", str(kwargs["scripts"])])
        if kwargs.get("os_detect"):
            args.append("-O")
        args.extend(["-oG", "-", clean])
        return self.execute("nmap", args, target, timeout=kwargs.get("timeout", 600))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("|_"):
                continue
            # Parse grepable nmap output: Host: 127.0.0.1 (localhost) Ports: 80/open/tcp//http//Apache httpd//
            m = re.search(r"Host:\s+(\S+)", line)
            host = m.group(1) if m else "unknown"
            ports_section = re.search(r"Ports:\s+(.+)", line)
            if not ports_section:
                continue
            for part in ports_section.group(1).split(","):
                part = part.strip()
                fields = part.split("/")
                if len(fields) >= 5:
                    port = fields[0].strip()
                    state = fields[1].strip()
                    proto = fields[2].strip()
                    service = fields[3].strip()
                    product = fields[4].strip()
                    if state == "open":
                        title = f"{host}:{port}"
                        desc = f"Puerto {port}/{proto} — {service}"
                        if product:
                            desc += f" ({product})"
                        findings.append({
                            "type": "port",
                            "name": title,
                            "severity": "medium",
                            "description": desc,
                            "data": {
                                "host": host,
                                "port": int(port),
                                "protocol": proto,
                                "service": service,
                                "product": product,
                            },
                        })
        return findings
