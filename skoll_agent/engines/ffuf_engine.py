from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class FfufEngine(BaseEngine):
    name = "ffuf"
    description = "Web fuzzer rápido. Alternativa a gobuster con mejor manejo de timeouts y auto-calibración."
    capabilities = ["dir_bruteforce", "web_discovery", "fuzzing"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        from skoll_agent.config.wordlists import resolve_wordlist
        wordlist = resolve_wordlist("web_directories_common", kwargs.get("wordlist"))
        threads = int(kwargs.get("threads", 30))
        extensions = kwargs.get("extensions", ".php,.txt,.html")
        rate_limit = int(kwargs.get("rate_limit", 200))
        timeout_s = int(kwargs.get("http_timeout", 5))

        url = target.rstrip("/") + "/FUZZ"
        fd, out_file = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
        os.close(fd)
        try:
            args = [
                "ffuf", "-u", url, "-w", wordlist,
                "-t", str(threads), "-rate", str(rate_limit),
                "-timeout", str(timeout_s), "-ac",
                "-e", extensions, "-of", "json", "-o", out_file,
                "-c", "-s",
            ]

            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=kwargs.get("timeout", 300),
            )
            findings = []
            raw = result.stdout + result.stderr

            try:
                with open(out_file) as f:
                    data = json.load(f)
                results = data.get("results", [])
                for r in results:
                    status = r.get("status", 0)
                    if status in (404, 400) or not status:
                        continue
                    path = r.get("input", {}).get("FUZZ", "")
                    size = r.get("length", 0)
                    sev = "medium" if status in (200, 201, 204) else "low" if status in (301, 302, 403, 401) else "info"
                    findings.append({
                        "file_path": f"/{path}",
                        "line_start": 0, "line_end": 0,
                        "severity": sev,
                        "title": f"Path: /{path} (HTTP {status})",
                        "description": f"Path /{path} — status {status}, size {size}",
                        "tool": self.name,
                        "rule_id": f"ffuf-{path}",
                        "path": f"/{path}",
                        "status": status,
                        "size": size,
                    })
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            summary = f"ffuf: {len(findings)} paths on {target}"
            return EngineResult(
                success=True, raw_output=raw, findings=findings,
                summary=summary, error="",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                success=False, raw_output="",
                summary=f"ffuf: timeout on {target}",
                error="Timeout (300s)",
            )
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="ffuf: not installed", error="Install ffuf")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"ffuf: {e}", error=str(e))
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
