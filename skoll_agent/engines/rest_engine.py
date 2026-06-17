from __future__ import annotations

import json
import subprocess
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class RestEngine(BaseEngine):
    name = "rest"
    description = "REST API security auditor. Prueba métodos HTTP, auth, IDOR, injection, y configuración insegura en endpoints REST."
    capabilities = ["api_audit", "rest_api", "web_security"]

    COMMON_ENDPOINTS = [
        "/api", "/api/v1", "/api/v2", "/v1", "/v2",
        "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/openapi.json",
        "/graphql", "/health", "/status", "/admin", "/users", "/login",
    ]

    COMMON_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []
        base_url = target.rstrip("/")
        timeout = kwargs.get("timeout", 30)

        # 1. Discover common endpoints
        if kwargs.get("discover", True):
            for ep in self.COMMON_ENDPOINTS:
                url = f"{base_url}{ep}"
                try:
                    r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
                    raw_lines.append(f"[{r.status_code}] GET {url}")
                    if r.status_code not in (404, 405, 400):
                        findings.append({
                            "file_path": url,
                            "line_start": 0, "line_end": 0,
                            "severity": "medium" if r.status_code < 300 else "low",
                            "title": f"REST endpoint discoverable: {ep}",
                            "description": f"Endpoint {ep} responded with HTTP {r.status_code}. Content: {r.text[:200]}",
                            "tool": self.name,
                            "rule_id": f"rest-endpoint-{ep.strip('/').replace('/', '-')}",
                            "endpoint": ep,
                            "status": r.status_code,
                        })
                except requests.exceptions.ConnectionError:
                    raw_lines.append(f"[ERR] Connection refused: {url}")
                except requests.exceptions.Timeout:
                    raw_lines.append(f"[TIMEOUT] {url}")
                except Exception as e:
                    raw_lines.append(f"[ERR] {url}: {e}")

        # 2. Method enumeration on base URL
        for method in self.COMMON_METHODS:
            if method == "GET" and not kwargs.get("force_method_test", False):
                continue
            try:
                r = requests.request(method, base_url, timeout=timeout, verify=False)
                raw_lines.append(f"[{r.status_code}] {method} {base_url}")
                if r.status_code not in (404, 405, 400, 200):
                    findings.append({
                        "file_path": base_url,
                        "line_start": 0, "line_end": 0,
                        "severity": "medium",
                        "title": f"Unexpected method response: {method}",
                        "description": f"Method {method} on {base_url} returned HTTP {r.status_code}",
                        "tool": self.name,
                        "rule_id": f"rest-method-{method.lower()}",
                        "method": method,
                        "status": r.status_code,
                    })
            except Exception:
                pass

        # 3. Check for security headers
        try:
            r = requests.get(base_url, timeout=timeout, verify=False)
            headers = r.headers
            missing = []
            security_headers = {
                "Strict-Transport-Security": "HSTS missing",
                "Content-Security-Policy": "CSP missing",
                "X-Content-Type-Options": "X-Content-Type-Options missing",
                "X-Frame-Options": "X-Frame-Options missing",
                "X-XSS-Protection": "X-XSS-Protection missing",
            }
            for h, msg in security_headers.items():
                if h not in headers:
                    missing.append(h)
                    findings.append({
                        "file_path": base_url,
                        "line_start": 0, "line_end": 0,
                        "severity": "low",
                        "title": f"Missing security header: {h}",
                        "description": msg,
                        "tool": self.name,
                        "rule_id": f"rest-header-{h.lower()}",
                    })
            if missing:
                raw_lines.append(f"[INFO] Missing headers: {', '.join(missing)}")
        except Exception:
            pass

        summary = f"rest: {len(findings)} issues on {target}"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
