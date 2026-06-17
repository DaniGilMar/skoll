from __future__ import annotations

import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class GobusterEngine(BaseEngine):
    name = "gobuster"
    description = "Directory/file brute-forcer para descubrir rutas en servidores web."
    capabilities = ["dir_bruteforce", "dns_bruteforce", "web_discovery"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        from skoll_agent.config.wordlists import resolve_wordlist
        wordlist = resolve_wordlist("web_directories_medium", kwargs.get("wordlist"))
        mode = kwargs.get("mode", "dir")
        progress_cb = kwargs.get("progress_callback")
        extensions = kwargs.get("extensions", ".php,txt,html")
        threads = int(kwargs.get("threads", 30))
        timeout_s = kwargs.get("http_timeout", 30)
        args = ["gobuster", mode, "-u", target, "-w", wordlist,
                "-t", str(threads), "-x", extensions, "-o", "gusbuster.txt",
                "--timeout", f"{timeout_s}s", "--retry"]

        _prog_re = re.compile(r"Progress:\s*(\d+)\s*/\s*(\d+)")
        line_cb = None
        if progress_cb:
            def line_cb(line: str) -> None:
                m = _prog_re.search(line)
                if m:
                    done, total = int(m.group(1)), int(m.group(2))
                    if total > 0:
                        progress_cb(min(99, int(done * 100 / total)))

        try:
            raw, stderr, timed_out = self.run_subprocess(args, timeout=kwargs.get("timeout", 300), line_callback=line_cb)
            full = raw + stderr
            findings = self.parse_output(full) if full.strip() else []
            if progress_cb:
                progress_cb(100)
            summary = f"gobuster: {len(findings)} paths found on {target}"
            if timed_out:
                summary += " (partial, timeout)"
            return EngineResult(
                success=True, raw_output=full, findings=findings,
                summary=summary,
            )
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="gobuster: not installed", error="Install gobuster")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"gobuster: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.split("\n"):
            line = line.strip()
            if not line or line.startswith("Error"):
                continue
            m = re.match(r"/(\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                path, status = m.group(1), int(m.group(2))
                sev = "medium" if status in (200, 201, 204) else "low" if status in (301, 302, 403) else "info"
                findings.append({
                    "file_path": f"{path}",
                    "line_start": 0, "line_end": 0,
                    "severity": sev,
                    "title": f"Path found: /{path} (HTTP {status})",
                    "description": f"Discovered path /{path} with status {status}",
                    "tool": self.name,
                    "rule_id": f"gobuster-{path}",
                    "path": f"/{path}",
                    "status": status,
                })
        return findings
