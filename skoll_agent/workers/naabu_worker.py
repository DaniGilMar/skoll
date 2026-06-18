from __future__ import annotations

import json
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class NaabuWorker(BaseWorker):
    name = "naabu"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        args = ["-host", target, "-json", "-silent"]
        if kwargs.get("ports"):
            args.extend(["-p", str(kwargs["ports"])])
        if kwargs.get("top_ports"):
            args.extend(["--top-ports", str(kwargs["top_ports"])])
        if kwargs.get("rate"):
            args.extend(["-rate", str(kwargs["rate"])])
        if kwargs.get("exclude_cdn"):
            args.append("-exclude-cdn")
        return self.execute("naabu", args, target, parse_json_lines=False)

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                port = obj.get("port")
                if port:
                    findings.append({
                        "type": "port",
                        "name": f"{obj.get('address', '')}:{port}",
                        "severity": "medium",
                        "description": f"Puerto abierto: {port}/{obj.get('protocol', 'tcp')}",
                        "data": obj,
                    })
            except json.JSONDecodeError:
                pass
        return findings
