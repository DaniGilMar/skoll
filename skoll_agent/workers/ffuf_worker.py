from __future__ import annotations

import json
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class FfufWorker(BaseWorker):
    name = "ffuf"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        args = ["-u", f"{target}/FUZZ", "-w", wordlist, "-json", "-ac", "-t", "50"]
        if kwargs.get("extensions"):
            args.extend(["-e", kwargs["extensions"]])
        if kwargs.get("recursive"):
            args.append("-recursion")
        if kwargs.get("recursion_depth"):
            args.extend(["-recursion-depth", str(kwargs["recursion_depth"])])
        if kwargs.get("mc"):
            args.extend(["-mc", kwargs["mc"]])
        if kwargs.get("fs"):
            args.extend(["-fs", kwargs["fs"]])
        if kwargs.get("rate"):
            args.extend(["-rate", str(kwargs["rate"])])
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        return self.execute("ffuf", args, target, parse_json_lines=False)

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                status = obj.get("status", 0)
                if url:
                    sev = "medium" if status in (200, 201, 204) else "low" if status in (301, 302, 307, 403) else "info"
                    findings.append({
                        "type": "endpoint",
                        "name": url,
                        "severity": sev,
                        "description": f"Endpoint: {url} (Status: {status}, Size: {obj.get('length', 0)})",
                        "data": obj,
                    })
            except json.JSONDecodeError:
                pass
        return findings
