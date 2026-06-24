from __future__ import annotations

import subprocess
import json
import re
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class NucleiEngine(BaseEngine):
    name = "nuclei"
    description = "Template-based vulnerability scanner. Escanea usando miles de templates YAML contra cualquier target."
    capabilities = ["vuln_scan", "template_scan", "cve_scan", "web_scan"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        args = ["nuclei", "-u", target, "-j", "-silent", "-rl", "150"]
        sev = kwargs.get("severity", "medium,high,critical")
        if sev:
            args.extend(["-severity", sev])
        if kwargs.get("templates"):
            args.extend(["-t", kwargs["templates"]])
        if kwargs.get("tags"):
            args.extend(["-tags", kwargs["tags"]])
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        if kwargs.get("cve"):
            from datetime import datetime
            year = kwargs["cve"].split("-")[1] if "-" in kwargs["cve"] else ""
            if year:
                args.extend(["-t", f"cves/{year}"])

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=kwargs.get("timeout", 120))
            raw = result.stdout.strip()
            if not raw:
                return EngineResult(success=True, raw_output="", summary="nuclei: no vulnerabilities found")
            findings = self.parse_output(raw)
            return EngineResult(
                success=True, raw_output=raw, findings=findings,
                summary=f"nuclei: {len(findings)} vulnerabilities on {target}",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary="nuclei: timeout", error="Timeout (120s)")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="nuclei: not installed", error="Install nuclei")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"nuclei: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                sev = data.get("info", {}).get("severity", "medium")
                name = data.get("info", {}).get("name", "Unknown")
                template = data.get("template-id", "")
                matched = data.get("matched-at", "")
                extrated = data.get("extracted-results", "")
                desc = f"[{template}] {matched}"
                if extrated:
                    desc += f" | Extracted: {extrated}"
                findings.append({
                    "file_path": matched or data.get("host", ""),
                    "line_start": 0, "line_end": 0,
                    "severity": sev,
                    "title": name,
                    "description": desc,
                    "tool": self.name,
                    "rule_id": template,
                    "template": template,
                    "matched": matched,
                })
            except json.JSONDecodeError:
                m = re.match(r"\[(\w+)\]\s*\[(\w+)\]\s*(.*?)(?:\s+\[.*\])?\s*$", line)
                if m:
                    findings.append({
                        "file_path": "",
                        "line_start": 0, "line_end": 0,
                        "severity": m.group(1).lower(),
                        "title": m.group(3)[:100],
                        "description": line[:300],
                        "tool": self.name,
                        "rule_id": m.group(2),
                    })
        return findings
