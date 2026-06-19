from __future__ import annotations

from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class NucleiWorker(BaseWorker):
    name = "nuclei"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        args = ["-u", target, "-j", "-silent", "-rl", "150"]
        if kwargs.get("templates"):
            args.extend(["-t", kwargs["templates"]])
        sev = kwargs.get("severity", "medium,high,critical")
        if sev:
            args.extend(["-severity", sev])
        if kwargs.get("tags"):
            args.extend(["-tags", kwargs["tags"]])
        tout = kwargs.get("timeout", 120)
        return self.execute("nuclei", args, target, timeout=tout, parse_json_lines=False)

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        objs = self._parse_json_lines(raw_output)
        for obj in objs:
            info = obj.get("info", {})
            sev = self.severity_from(info.get("severity", "medium"))
            name = info.get("name", "Unknown")
            template = obj.get("template-id", "")
            matched = obj.get("matched-at", "")
            findings.append({
                "type": "vulnerability",
                "name": name,
                "severity": sev,
                "description": f"[{template}] {matched}",
                "template": template,
                "matched": matched,
                "data": obj,
            })
        return findings
