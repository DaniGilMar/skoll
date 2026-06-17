from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class EngineResult:
    success: bool
    raw_output: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    error: str = ""


ProgressCallback = Callable[[int], None]  # percentage 0-100


class BaseEngine(ABC):
    name: str = "base"
    description: str = "Base engine"
    capabilities: list[str] = []

    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        ...

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        ...

    def normalize_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "file_path": raw.get("file_path", ""),
            "line_start": raw.get("line_start", 0),
            "line_end": raw.get("line_end", 0),
            "severity": raw.get("severity", "medium"),
            "title": raw.get("title", "Unknown"),
            "description": raw.get("description", ""),
            "tool": self.name,
            "rule_id": raw.get("rule_id", ""),
        }

    def run_subprocess(
        self, args: list[str], timeout: int = 300,
        line_callback: Callable[[str], None] | None = None,
        merge_stderr: bool = False,
    ) -> tuple[str, str, bool]:
        """Run subprocess, return (stdout, stderr_or_merged, timed_out).
        If merge_stderr=True, stderr is redirected to stdout (tools like nikto).
        Even on timeout, returns partial output collected so far."""
        import select
        import time as _time
        stderr_target = subprocess.STDOUT if merge_stderr else subprocess.PIPE
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=stderr_target,
            text=True, bufsize=1,
        )
        all_lines: list[str] = []
        timed_out = False
        deadline = _time.monotonic() + timeout

        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                timed_out = True
                proc.kill()
                break
            select_timeout = 0.1
            r, _, _ = select.select([proc.stdout], [], [], select_timeout)
            if r:
                line = proc.stdout.readline()
                if not line:
                    break
                all_lines.append(line)
                if line_callback:
                    line_callback(line.rstrip("\n\r"))

        proc.stdout.close()
        stderr_out = ""
        if not merge_stderr:
            stderr_out = proc.stderr.read()
            proc.stderr.close()
        proc.wait()
        return "".join(all_lines), stderr_out, timed_out

    def extract_progress(self, line: str) -> int | None:
        """Override in subclasses to parse progress percentage from output lines."""
        return None
