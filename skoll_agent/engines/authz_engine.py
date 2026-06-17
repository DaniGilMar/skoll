from __future__ import annotations

import json
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class AuthzEngine(BaseEngine):
    name = "authz"
    description = "Authorization and authentication auditor. Prueba IDOR, privilege escalation, bypass de auth, y endpoints protegidos."
    capabilities = ["api_audit", "authz", "authn", "web_security"]

    COMMON_AUTH_BYPASS = [
        {"header": "X-Forwarded-For", "value": "127.0.0.1"},
        {"header": "X-Original-URL", "value": "/admin"},
        {"header": "X-Rewrite-URL", "value": "/admin"},
        {"header": "X-Forwarded-Host", "value": "localhost"},
        {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
        {"header": "X-ProxyUser-Ip", "value": "127.0.0.1"},
    ]

    COMMON_ADMIN_PATHS = [
        "/admin", "/administrator", "/admin.php", "/admin/",
        "/wp-admin", "/dashboard", "/panel", "/cpanel",
        "/api/admin", "/v1/admin", "/manage", "/management",
    ]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []
        base_url = target.rstrip("/")
        timeout = kwargs.get("timeout", 15)
        session_token = kwargs.get("token", "")
        test_user = kwargs.get("test_user", "user")
        admin_user = kwargs.get("admin_user", "admin")

        # 1. Check auth bypass headers on protected paths
        paths_to_test = kwargs.get("paths", self.COMMON_ADMIN_PATHS)

        for path in paths_to_test:
            url = f"{base_url}{path}"
            # Try without auth first
            try:
                r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
                raw_lines.append(f"[{r.status_code}] GET {url} (no auth)")

                if r.status_code in (200, 201, 204):
                    findings.append({
                        "file_path": url,
                        "line_start": 0, "line_end": 0,
                        "severity": "high",
                        "title": f"Protected path accessible without auth: {path}",
                        "description": f"Path '{path}' returned HTTP {r.status_code} without authentication.",
                        "tool": self.name,
                        "rule_id": f"authz-no-auth-{path.strip('/').replace('/', '-')}",
                        "path": path,
                        "status": r.status_code,
                    })
                elif r.status_code in (401, 403):
                    # Try auth bypass headers
                    for bypass in self.COMMON_AUTH_BYPASS:
                        try:
                            r2 = requests.get(
                                url,
                                headers={bypass["header"]: bypass["value"]},
                                timeout=timeout,
                                verify=False,
                                allow_redirects=False,
                            )
                            raw_lines.append(f"[{r2.status_code}] GET {url} (bypass: {bypass['header']}: {bypass['value']})")
                            if r2.status_code in (200, 201, 204):
                                findings.append({
                                    "file_path": url,
                                    "line_start": 0, "line_end": 0,
                                    "severity": "critical",
                                    "title": f"Auth bypass via header: {bypass['header']}",
                                    "description": f"Path '{path}' blocked normally (HTTP {r.status_code}) but accessible with header {bypass['header']}: {bypass['value']} (HTTP {r2.status_code})",
                                    "tool": self.name,
                                    "rule_id": f"authz-bypass-{bypass['header'].lower().replace('-', '')}",
                                    "path": path,
                                    "bypass_header": bypass["header"],
                                    "bypass_value": bypass["value"],
                                    "original_status": r.status_code,
                                    "bypass_status": r2.status_code,
                                })
                                break
                        except Exception:
                            continue
            except Exception:
                continue

        # 2. IDOR test by path traversal (sequential IDs)
        idor_pattern = kwargs.get("idor_pattern", "/api/users/")
        for i in range(1, 5):
            idor_url = f"{base_url}{idor_pattern}{i}"
            try:
                r = requests.get(idor_url, timeout=timeout, verify=False)
                raw_lines.append(f"[{r.status_code}] GET {idor_url}")
                if r.status_code == 200:
                    findings.append({
                        "file_path": idor_url,
                        "line_start": 0, "line_end": 0,
                        "severity": "high",
                        "title": f"Potential IDOR: sequential ID accessible",
                        "description": f"Endpoint {idor_url} returns HTTP 200. Sequential IDs may expose data belonging to other users.",
                        "tool": self.name,
                        "rule_id": "authz-idor-sequential",
                        "idor_url": idor_url,
                        "idor_id": i,
                    })
            except Exception:
                continue

        # 3. Test method override / privilege escalation
        methods_to_test = ["POST", "PUT", "PATCH", "DELETE"]
        for path in paths_to_test[:3]:
            url = f"{base_url}{path}"
            for method in methods_to_test:
                try:
                    headers = {}
                    if session_token:
                        headers["Authorization"] = f"Bearer {session_token}"
                    r = requests.request(method, url, headers=headers, timeout=timeout, verify=False)
                    raw_lines.append(f"[{r.status_code}] {method} {url}")
                    if r.status_code not in (404, 405, 401, 403):
                        findings.append({
                            "file_path": url,
                            "line_start": 0, "line_end": 0,
                            "severity": "medium",
                            "title": f"Unexpected method allowed: {method} on {path}",
                            "description": f"Method {method} on {path} returned HTTP {r.status_code}. May allow privilege escalation.",
                            "tool": self.name,
                            "rule_id": f"authz-unexpected-{method.lower()}",
                            "path": path,
                            "method": method,
                            "status": r.status_code,
                        })
                except Exception:
                    continue

        # 4. Check security headers related to auth
        try:
            r = requests.get(base_url, timeout=timeout, verify=False)
            headers = r.headers
            # Check CORS
            acao = headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                findings.append({
                    "file_path": base_url,
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": "CORS misconfiguration: wildcard origin",
                    "description": "Access-Control-Allow-Origin: * allows any domain to access resources.",
                    "tool": self.name,
                    "rule_id": "authz-cors-wildcard",
                })
            # Check for missing auth schemes in WWW-Authenticate
            if "WWW-Authenticate" not in headers and r.status_code in (401, 403):
                findings.append({
                    "file_path": base_url,
                    "line_start": 0, "line_end": 0,
                    "severity": "low",
                    "title": "Missing WWW-Authenticate header",
                    "description": "401/403 response without WWW-Authenticate header. May confuse clients.",
                    "tool": self.name,
                    "rule_id": "authz-missing-www-auth",
                })
        except Exception:
            pass

        summary = f"authz: {len(findings)} issues on {target}"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines) if raw_lines else "authz: scan complete",
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
