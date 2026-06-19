from __future__ import annotations

import json
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class HttpxWorker(BaseWorker):
    name = "httpx"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        args = ["-u", target, "-j", "-silent", "-sc", "-title", "-td"]
        if kwargs.get("follow_redirects"):
            args.append("-follow-redirects")
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        return self.execute("httpx", args, target, parse_json_lines=False)

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                if url:
                    techs = obj.get("tech", [])
                    title = obj.get("title", "")
                    status = obj.get("status_code", 0)
                    desc_parts = []
                    if title:
                        desc_parts.append(f"Title: {title}")
                    if techs:
                        desc_parts.append(f"Tech: {', '.join(techs)}")
                    if status:
                        desc_parts.append(f"Status: {status}")
                    findings.append({
                        "type": "web",
                        "name": url,
                        "severity": "info",
                        "description": " | ".join(desc_parts) if desc_parts else f"Web endpoint: {url}",
                        "data": obj,
                    })
            except json.JSONDecodeError:
                pass
        return findings
