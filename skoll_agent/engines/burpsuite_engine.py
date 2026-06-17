from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class BurpSuiteEngine(BaseEngine):
    name = "burpsuite"
    description = "Burp Suite headless auditor. Controla Burp Suite via REST API (Proxy/Scanner), inicia escaneos y extrae hallazgos."
    capabilities = ["api_audit", "web_vuln_scan", "proxy_scan", "web_security"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        rest_api_url = kwargs.get("rest_api", "http://127.0.0.1:1337")
        api_key = kwargs.get("api_key", "")
        scan_type = kwargs.get("scan_type", "passive")
        timeout = int(kwargs.get("timeout", 300))

        burp_url = kwargs.get("burp_proxy", "http://127.0.0.1:8080")

        # Strategy 1: Use Burp REST API if available
        api_available = self._check_rest_api(rest_api_url, api_key)
        if api_available:
            raw_lines.append(f"[INFO] Burp REST API available at {rest_api_url}")
            return self._scan_via_api(rest_api_url, api_key, target, scan_type, timeout, findings, raw_lines)

        # Strategy 2: Use Burp Proxy as a forwarding proxy
        raw_lines.append(f"[INFO] Burp REST API not available. Attempting proxy-based scan via {burp_url}")
        return self._scan_via_proxy(burp_url, target, timeout, findings, raw_lines)

    def _check_rest_api(self, rest_api_url: str, api_key: str) -> bool:
        try:
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            r = requests.get(f"{rest_api_url}/v0.1/status", headers=headers, timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def _scan_via_api(
        self, rest_api_url: str, api_key: str,
        target: str, scan_type: str, timeout: int,
        existing_findings: list[dict[str, Any]],
        raw_lines: list[str],
    ) -> EngineResult:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # 1. Add URL to scope
        try:
            payload = {"url": target}
            r = requests.put(
                f"{rest_api_url}/v0.1/scope",
                json=payload, headers=headers, timeout=10,
            )
            raw_lines.append(f"[SCOPE] PUT /scope -> {r.status_code}")
        except Exception as e:
            raw_lines.append(f"[ERR] Scope: {e}")

        # 2. Start scan
        try:
            scan_payload = {
                "urls": [target],
                "scope": {"type": "SimpleScope", "value": target},
                "scan_type": scan_type,
            }
            r = requests.post(
                f"{rest_api_url}/v0.1/scan",
                json=scan_payload, headers=headers, timeout=10,
            )
            raw_lines.append(f"[SCAN] POST /scan -> {r.status_code}")

            if r.status_code == 201:
                scan_data = r.json()
                scan_id = scan_data.get("scan_id", "")
                raw_lines.append(f"[SCAN] Started scan ID: {scan_id}")

                # Poll for results
                start = time.time()
                while time.time() - start < timeout:
                    time.sleep(5)
                    try:
                        r2 = requests.get(
                            f"{rest_api_url}/v0.1/scan/{scan_id}",
                            headers=headers, timeout=10,
                        )
                        if r2.status_code == 200:
                            status_data = r2.json()
                            if status_data.get("scan_status") == "succeeded":
                                raw_lines.append("[SCAN] Scan completed")
                                # Get issues
                                issues_r = requests.get(
                                    f"{rest_api_url}/v0.1/scan/{scan_id}/issues",
                                    headers=headers, timeout=10,
                                )
                                if issues_r.status_code == 200:
                                    issues = issues_r.json()
                                    for issue in issues:
                                        sev_map = {
                                            "high": "high", "medium": "medium",
                                            "low": "low", "info": "info",
                                            "certain": "high", "firm": "medium",
                                            "tentative": "low",
                                        }
                                        sev = sev_map.get(
                                            issue.get("severity", "").lower(), "medium"
                                        )
                                        existing_findings.append({
                                            "file_path": target,
                                            "line_start": 0, "line_end": 0,
                                            "severity": sev,
                                            "title": issue.get("name", "Burp Issue"),
                                            "description": issue.get("description", ""),
                                            "tool": self.name,
                                            "rule_id": f"burp-{issue.get('type', 'unknown')}",
                                            "burp_type": issue.get("type", ""),
                                            "burp_severity": issue.get("severity", ""),
                                            "remediation": issue.get("remediation", ""),
                                        })
                                break
                            elif status_data.get("scan_status") == "failed":
                                raw_lines.append("[SCAN] Scan failed")
                                break
                    except Exception:
                        continue
        except Exception as e:
            raw_lines.append(f"[ERR] Scan: {e}")

        summary = f"burpsuite: {len(existing_findings)} issues (REST API)"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=existing_findings,
            summary=summary,
        )

    def _scan_via_proxy(
        self, burp_url: str, target: str, timeout: int,
        existing_findings: list[dict[str, Any]],
        raw_lines: list[str],
    ) -> EngineResult:
        """Use Burp as a proxy to crawl the target."""
        proxies = {
            "http": burp_url,
            "https": burp_url,
        }

        pages_to_visit = [target]
        visited = set()

        start = time.time()
        while pages_to_visit and (time.time() - start) < timeout:
            url = pages_to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                r = requests.get(url, proxies=proxies, timeout=15, verify=False)
                raw_lines.append(f"[PROXY] {r.status_code} {url}")
                existing_findings.append({
                    "file_path": url,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"Sent through Burp proxy: {url}",
                    "description": f"URL {url} sent through Burp proxy {burp_url} for analysis.",
                    "tool": self.name,
                    "rule_id": "burp-proxied",
                    "burp_proxy": burp_url,
                })
            except requests.exceptions.ConnectionError:
                raw_lines.append(f"[ERR] Proxy connection failed: {burp_url}")
                continue
            except Exception as e:
                raw_lines.append(f"[ERR] {url}: {e}")
                continue

        summary = f"burpsuite: {len(existing_findings)} pages proxied through Burp" if visited else "burpsuite: no pages proxied"
        return EngineResult(
            success=bool(visited),
            raw_output="\n".join(raw_lines),
            findings=existing_findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
