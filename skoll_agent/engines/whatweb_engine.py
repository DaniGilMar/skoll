from __future__ import annotations

import re
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mK]')


class WhatWebEngine(BaseEngine):
    name = "whatweb"
    description = "Web technology detector. Identifica CMS, frameworks, librerías JS, servidores y versiones."
    capabilities = ["web_tech_detect", "fingerprint", "cms_detection"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        args = ["whatweb", target, "--log-verbose=-"]
        if kwargs.get("aggression"):
            args.append(f"--aggression={kwargs['aggression']}")

        tout = kwargs.get("timeout", 120)
        raw, _stderr, timed_out = self.run_subprocess(args, timeout=tout)
        raw = _ANSI_RE.sub('', raw).strip()

        if not raw:
            if timed_out:
                return EngineResult(success=False, raw_output="", summary="whatweb: timeout", error=f"Timeout ({tout}s)")
            return EngineResult(success=True, raw_output="", summary="whatweb: no technologies detected")

        findings = self.parse_output(raw)
        summary_line = self._extract_summary(raw)
        summary = f"whatweb: {len(findings)} technologies on {target}"
        if timed_out:
            summary += " (timeout, partial)"
        return EngineResult(
            success=True, raw_output=summary_line, findings=findings,
            summary=summary,
        )

    def _extract_summary(self, clean_output: str) -> str:
        """Extract the one-line summary from whatweb output (last non-header line)."""
        lines = clean_output.strip().split("\n")
        # The summary is usually the last line with [200 OK] or similar
        for line in reversed(lines):
            if "[" in line and ("OK" in line or "Redirect" in line or "Error" in line):
                return line.strip()
        # Fallback: first non-empty line
        for line in lines:
            if line.strip():
                return line.strip()
        return clean_output[:500]

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        clean = _ANSI_RE.sub('', raw_output)
        findings = []

        # Extract title
        title_match = re.search(r"Title\s*:\s*(.+)", clean)
        title = title_match.group(1).strip() if title_match else ""

        # Extract status
        status_match = re.search(r"Status\s*:\s*(\d+)", clean)
        status = status_match.group(1) if status_match else ""

        # Extract technologies from the summary line (last line with [...])
        summary_line = self._extract_summary(clean)
        # Parse tech from summary: Apache[2.4.29], HTML5, HTTPServer[...]
        tech_matches = re.findall(r'(\w[\w+.-]*)(?:\[([^\]]*)\])?', summary_line)
        technologies = []
        tech_versions = {}
        for tech_name, tech_ver in tech_matches:
            tech_lower = tech_name.lower()
            if tech_lower not in ("http", "https", "country", "ip", "title", "status", "redirectlocation"):
                technologies.append(tech_name)
                if tech_ver:
                    tech_versions[tech_name] = tech_ver

        if title:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "medium",
                "title": f"Title: {title}",
                "description": f"Web title: {title}",
                "tool": self.name, "rule_id": "whatweb-title",
                "title_found": title,
            })

        for tech in technologies[:8]:
            ver = tech_versions.get(tech, "")
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "medium" if ver else "info",
                "title": f"Tech: {tech}" + (f" {ver}" if ver else ""),
                "description": f"Technology: {tech}" + (f" (version: {ver})" if ver else ""),
                "tool": self.name, "rule_id": f"whatweb-tech-{tech.lower()}",
                "technology": tech,
                "version": ver,
            })

        if status:
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "info", "title": f"Status: {status}",
                "description": f"HTTP status: {status}",
                "tool": self.name, "rule_id": "whatweb-status",
            })

        return findings

    def normalize_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "file_path": raw.get("file_path", ""),
            "line_start": raw.get("line_start", 0),
            "line_end": raw.get("line_end", 0),
            "severity": raw.get("severity", "info"),
            "title": raw.get("title", "Unknown"),
            "description": raw.get("description", ""),
            "tool": self.name,
            "rule_id": raw.get("rule_id", ""),
        }
