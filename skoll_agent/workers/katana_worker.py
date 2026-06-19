from __future__ import annotations

import json
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class KatanaWorker(BaseWorker):
    name = "katana"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        args = ["-u", target, "-json", "-silent"]
        # JS crawling + depth + filter: needed for real crawling (e.g. DVWA redirects)
        if kwargs.get("no_defaults"):
            if kwargs.get("depth"):
                args.extend(["-d", str(kwargs["depth"])])
        else:
            args.append("-jc")
            args.extend(["-d", str(kwargs.get("depth", 3))])
            if not kwargs.get("field"):
                args.extend(["-f", "qurl"])
        if kwargs.get("known_files"):
            args.append("-known-files")
        if kwargs.get("no_crawl"):
            args.append("-no-crawl")
        if kwargs.get("field"):
            args.extend(["-f", kwargs["field"]])
        if kwargs.get("headless"):
            args.append("-headless")
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        return self.execute("katana", args, target, parse_json_lines=False)

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url", obj.get("request", ""))
                if url:
                    findings.append({
                        "type": "endpoint",
                        "name": url,
                        "severity": "info",
                        "description": f"Endpoint descubierto: {url}",
                        "data": obj,
                    })
            except json.JSONDecodeError:
                pass
        return findings
