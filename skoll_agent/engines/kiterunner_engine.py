from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class KiterunnerEngine(BaseEngine):
    name = "kiterunner"
    description = "API endpoint discovery with Kiterunner. Descubre rutas API, endpoints REST/GraphQL y recursos ocultos."
    capabilities = ["api_discovery", "web_discovery", "api_audit"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []
        from skoll_agent.config.wordlists import resolve_wordlist
        wordlist = resolve_wordlist("kiterunner_routes", kwargs.get("wordlist"))
        threads = int(kwargs.get("threads", 10))
        rate_limit = int(kwargs.get("rate_limit", 50))
        timeout_s = int(kwargs.get("timeout", 60))

        url = target.rstrip("/")

        args = [
            "kr", "scan", url,
            "-w", wordlist,
            "-t", str(threads),
            "-r", str(rate_limit),
            "-o", "json",
            "--fail-codes", "404,400",
        ]

        try:
            proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )

            stdout_lines: list[str] = []
            try:
                for line in proc.stdout:
                    stdout_lines.append(line)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    status = data.get("status", 0)
                    path = data.get("path", "")
                    method = data.get("method", "GET")
                    length = data.get("length", 0)
                    words = data.get("words", 0)

                    if not path:
                        continue

                    sev = "medium"
                    if status in (200, 201, 204, 304):
                        sev = "high" if any(kw in path.lower() for kw in ["admin", "api", "graphql", "token", "auth", "login", "key", "secret"]) else "medium"
                    elif status in (301, 302, 303, 307, 308):
                        sev = "low"
                    elif status in (401, 403):
                        sev = "medium"
                    else:
                        sev = "info"

                    findings.append({
                        "file_path": path,
                        "line_start": 0, "line_end": 0,
                        "severity": sev,
                        "title": f"API endpoint: {method} {path} ({status})",
                        "description": f"Discovered endpoint {method} {path} — HTTP {status}, length {length}",
                        "tool": self.name,
                        "rule_id": f"kr-{method.lower()}-{path.strip('/').replace('/', '-')[:40]}",
                        "path": path,
                        "method": method,
                        "status": status,
                        "length": length,
                        "words": words,
                    })
            except subprocess.TimeoutExpired:
                proc.kill()
            finally:
                proc.wait()

            raw_output = "".join(stdout_lines)
            summary = f"kiterunner: {len(findings)} endpoints on {target}" if findings else "kiterunner: no endpoints found"

            return EngineResult(
                success=True,
                raw_output=raw_output,
                findings=findings,
                summary=summary,
            )

        except FileNotFoundError:
            return EngineResult(
                success=False, raw_output="",
                summary="kiterunner: not installed. Install with: sudo apt install kiterunner or from https://github.com/assetnote/kiterunner",
                error="kiterunner not installed",
            )
        except Exception as e:
            return EngineResult(
                success=False, raw_output="",
                summary=f"kiterunner: {e}",
                error=str(e),
            )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                status = data.get("status", 0)
                path = data.get("path", "")
                method = data.get("method", "GET")
                if not path:
                    continue
                findings.append({
                    "file_path": path,
                    "line_start": 0, "line_end": 0,
                    "severity": "medium" if status < 400 else "info",
                    "title": f"API: {method} {path}",
                    "description": f"Discovered: {method} {path} [HTTP {status}]",
                    "tool": self.name,
                    "rule_id": f"kr-{path.strip('/').replace('/', '-')[:40]}",
                })
            except json.JSONDecodeError:
                continue
        return findings
