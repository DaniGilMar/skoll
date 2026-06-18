from __future__ import annotations

import json
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class WorkerResult:
    tool_name: str
    target: str
    success: bool
    raw_output: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration: float = 0.0
    error: str = ""
    normalized: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "target": self.target,
            "success": self.success,
            "findings": self.findings,
            "duration": self.duration,
            "error": self.error,
        }


TOOL_REQUIREMENTS: dict[str, str] = {
    "subfinder": "Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "Install: go install -v github.com/owasp-amass/amass/v4/...@master",
    "naabu": "Install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "httpx": "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "Install: go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "ffuf": "Install: apt install ffuf | go install github.com/ffuf/ffuf/v2@latest",
    "nuclei": "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}


def check_tool(binary: str) -> str | None:
    path = shutil.which(binary)
    if path:
        return path
    hint = TOOL_REQUIREMENTS.get(binary, f"Install {binary} manually")
    return None


class BaseWorker(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, target: str, **kwargs: Any) -> WorkerResult:
        ...

    def execute(
        self, binary: str, args: list[str], target: str,
        timeout: int = 300, parse_json_lines: bool = False,
    ) -> WorkerResult:
        binary_path = check_tool(binary)
        if not binary_path:
            hint = TOOL_REQUIREMENTS.get(binary, f"Install {binary}")
            return WorkerResult(
                tool_name=self.name, target=target, success=False,
                error=f"{binary} not found. {hint}",
            )

        start = time.time()
        try:
            result = subprocess.run(
                [binary_path, *args],
                capture_output=True, text=True, timeout=timeout,
            )
            stdout = result.stdout
            stderr = result.stderr
            duration = time.time() - start

            if result.returncode != 0 and not stdout.strip():
                return WorkerResult(
                    tool_name=self.name, target=target, success=False,
                    raw_output=stderr, duration=duration,
                    error=stderr[:500],
                )

            if parse_json_lines:
                findings = self._parse_json_lines(stdout)
            else:
                findings = self.parse_output(stdout)

            return WorkerResult(
                tool_name=self.name, target=target, success=True,
                raw_output=stdout, findings=findings, duration=duration,
            )

        except subprocess.TimeoutExpired:
            return WorkerResult(
                tool_name=self.name, target=target, success=False,
                error=f"Timeout after {timeout}s",
            )
        except FileNotFoundError:
            hint = TOOL_REQUIREMENTS.get(binary, f"Install {binary}")
            return WorkerResult(
                tool_name=self.name, target=target, success=False,
                error=f"{binary} not found. {hint}",
            )
        except Exception as e:
            return WorkerResult(
                tool_name=self.name, target=target, success=False,
                error=str(e),
            )

    def _parse_json_lines(self, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                findings.append(obj)
            except json.JSONDecodeError:
                pass
        return findings

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    def severity_from(self, value: str | None) -> str:
        if not value:
            return "info"
        v = value.lower()
        if v in ("critical", "high", "medium", "low", "info"):
            return v
        if v in ("critical", "crit", "c"):
            return "critical"
        if v in ("high", "h"):
            return "high"
        if v in ("medium", "med", "m"):
            return "medium"
        if v in ("low", "l"):
            return "low"
        return "info"
