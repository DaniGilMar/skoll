from __future__ import annotations

import re
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class GobusterWorker(BaseWorker):
    name = "gobuster"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        self._target = target
        clean = target.split("://")[-1].rstrip("/")
        args = ["dir", "-u", target, "-q"]
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        args.extend(["-w", wordlist])
        if kwargs.get("extensions"):
            args.extend(["-x", str(kwargs["extensions"])])
        if kwargs.get("status_codes"):
            args.extend(["-s", str(kwargs["status_codes"])])
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        else:
            args.extend(["-t", "20"])
        return self.execute("gobuster", args, target, timeout=kwargs.get("timeout", 300))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        base = getattr(self, "_target", "").rstrip("/")
        # Gobuster dir output: "path (Status: 200)" without leading / (modern gobuster)
        pattern = re.compile(r"^/?(\S+)\s+\(Status:\s+(\d+)\)")
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            m = pattern.search(line)
            if m:
                path = "/" + m.group(1).lstrip("/")
                status = int(m.group(2))
                findings.append({
                    "type": "endpoint",
                    "name": f"{base}{path}",
                    "severity": "info",
                    "description": f"Endpoint descubierto: {path} (Status: {status})",
                    "data": {"path": path, "status_code": status, "size": None},
                })
        return findings
