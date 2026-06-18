from __future__ import annotations

import json
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class SubfinderWorker(BaseWorker):
    name = "subfinder"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        args = ["-d", target, "-json", "-silent"]
        if kwargs.get("recursive"):
            args.extend(["-recursive"])
        if kwargs.get("all"):
            args.append("-all")
        return self.execute("subfinder", args, target, parse_json_lines=False)

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = obj.get("host", "")
                if host:
                    findings.append({
                        "type": "subdomain",
                        "name": host,
                        "severity": "info",
                        "description": f"Subdominio descubierto: {host}",
                        "data": obj,
                    })
            except json.JSONDecodeError:
                pass
        return findings
