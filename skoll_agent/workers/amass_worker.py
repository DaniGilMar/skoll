from __future__ import annotations

import json
from typing import Any

from skoll_agent.workers.base_worker import BaseWorker, WorkerResult


class AmassWorker(BaseWorker):
    name = "amass"

    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        mode = kwargs.get("mode", "enum")
        args = [mode, "-d", target, "-json", "/dev/stdout", "-nocolor"]
        if kwargs.get("passive"):
            args.append("-passive")
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        return self.execute("amass", args, target, parse_json_lines=False)

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                entry_type = obj.get("type", "")
                name = obj.get("name", "")
                if entry_type == "FQDN" and name:
                    findings.append({
                        "type": "fqdn",
                        "name": name,
                        "severity": "info",
                        "description": f"FQDN descubierto: {name}",
                        "data": obj,
                    })
                elif entry_type == "NSRecord" and name:
                    findings.append({
                        "type": "ns",
                        "name": name,
                        "severity": "info",
                        "description": f"NS record: {name}",
                        "data": obj,
                    })
                elif entry_type == "ASN" and obj.get("asn"):
                    findings.append({
                        "type": "asn",
                        "name": str(obj.get("asn", "")),
                        "severity": "info",
                        "description": f"ASN: {obj.get('asn')} - {obj.get('description', '')}",
                        "data": obj,
                    })
                elif entry_type == "Addr" and name:
                    findings.append({
                        "type": "address",
                        "name": name,
                        "severity": "info",
                        "description": f"Dirección IP: {name}",
                        "data": obj,
                    })
            except json.JSONDecodeError:
                pass
        return findings
