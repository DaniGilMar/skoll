from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mK]')


class CVEEngine(BaseEngine):
    name = "cve"
    description = "CVE lookup engine — busca vulnerabilidades conocidas por servicio+versión mediante searchsploit"
    capabilities = ["cve_lookup", "vuln_research"]

    SERVICE_ALIASES: dict[str, list[str]] = {
        "http": ["apache httpd", "apache", "httpd", "nginx"],
        "https": ["apache httpd", "apache", "httpd", "nginx"],
        "ftp": ["vsftpd", "proftpd", "pure-ftpd"],
        "ssh": ["openssh"],
        "smb": ["samba"],
        "microsoft-ds": ["samba"],
        "mysql": ["mysql"],
        "postgresql": ["postgresql"],
        "mariadb": ["mysql"],
    }

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        services: list[dict[str, str]] = kwargs.get("services", [])
        if not services:
            return EngineResult(success=True, raw_output="No services provided", summary="cve: no services to check")

        all_results: list[dict[str, Any]] = []
        seen_titles: set[str] = set()

        for svc in services:
            name = svc.get("service", "").lower()
            product = svc.get("product", "")
            version = svc.get("version", "")
            search_terms = self._build_search_terms(name, product, version)

            for term in search_terms:
                if not term.strip():
                    continue
                try:
                    entries = self._search_exploitdb(term)
                    for entry in entries:
                        title = entry.get("Title", "")
                        if title in seen_titles:
                            continue
                        seen_titles.add(title)
                        all_results.append({
                            "service": name,
                            "product": product,
                            "version": version,
                            "search_term": term,
                            **entry,
                        })
                except Exception:
                    continue

        findings = self._findings_from_results(all_results)
        raw = json.dumps(all_results, indent=2, default=str) if all_results else "No CVEs found"
        return EngineResult(
            success=True,
            raw_output=raw,
            findings=findings,
            summary=f"cve: {len(findings)} CVEs/exploits from {len(services)} services"
        )

    def _build_search_terms(self, service: str, product: str, version: str) -> list[str]:
        terms = []
        if product and version:
            terms.append(f"{product} {version}")
        if product:
            terms.append(product)
        # Aliases
        aliases = self.SERVICE_ALIASES.get(service, [])
        for alias in aliases:
            if version:
                terms.append(f"{alias} {version}")
            terms.append(alias)
        return terms

    def _search_exploitdb(self, term: str) -> list[dict[str, Any]]:
        try:
            result = subprocess.run(
                ["searchsploit", "-t", term, "-j"],
                capture_output=True, text=True, timeout=30,
            )
            raw = _ANSI_RE.sub('', result.stdout)
            data = json.loads(raw)
            return data.get("RESULTS_EXPLOIT", [])
        except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _findings_from_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen_cves: set[str] = set()

        for r in results:
            edb_id = r.get("EDB-ID", "")
            cve_codes = r.get("Codes", "")
            cves = [c.strip() for c in cve_codes.split(",") if c.strip().startswith("CVE-")] if cve_codes else []

            for cve in cves:
                if cve in seen_cves:
                    continue
                seen_cves.add(cve)
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"CVE: {cve} — {r.get('Title', '?')}",
                    "description": (
                        f"CVE: {cve}\n"
                        f"EDB-ID: {edb_id}\n"
                        f"Service: {r.get('service', r.get('search_term', '?'))}\n"
                        f"Type: {r.get('Type', '?')}\n"
                        f"Platform: {r.get('Platform', '?')}\n"
                        f"Title: {r.get('Title', '?')}\n"
                        f"Path: {r.get('Path', '?')}"
                    ),
                    "tool": self.name,
                    "rule_id": f"cve-{cve.lower()}",
                    "cve_id": cve,
                    "edb_id": edb_id,
                    "exploit_title": r.get("Title", ""),
                    "exploit_path": r.get("Path", ""),
                    "exploit_type": r.get("Type", ""),
                    "exploit_platform": r.get("Platform", ""),
                    "verified": r.get("Verified", "0") == "1",
                })

            if not cves and edb_id and edb_id not in seen_cves:
                seen_cves.add(edb_id)
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"EDB: {edb_id} — {r.get('Title', '?')}",
                    "description": (
                        f"EDB-ID: {edb_id}\n"
                        f"Service: {r.get('service', r.get('search_term', '?'))}\n"
                        f"Type: {r.get('Type', '?')}\n"
                        f"Platform: {r.get('Platform', '?')}\n"
                        f"Title: {r.get('Title', '?')}\n"
                        f"Path: {r.get('Path', '?')}"
                    ),
                    "tool": self.name,
                    "rule_id": f"edb-{edb_id}",
                    "cve_id": "",
                    "edb_id": edb_id,
                    "exploit_title": r.get("Title", ""),
                    "exploit_path": r.get("Path", ""),
                })

        return findings

    def normalize_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "file_path": raw.get("file_path", ""),
            "line_start": raw.get("line_start", 0),
            "line_end": raw.get("line_end", 0),
            "severity": raw.get("severity", "medium"),
            "title": raw.get("title", "CVE lookup"),
            "description": raw.get("description", ""),
            "tool": self.name,
            "rule_id": raw.get("rule_id", ""),
            "cve_id": raw.get("cve_id", ""),
            "edb_id": raw.get("edb_id", ""),
            "exploit_path": raw.get("exploit_path", ""),
        }

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
