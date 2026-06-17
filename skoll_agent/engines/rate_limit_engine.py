from __future__ import annotations

import json
import time
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class RateLimitEngine(BaseEngine):
    name = "rate_limit"
    description = "Rate limiting auditor. Prueba si un endpoint aplica rate limiting enviando ráfagas de peticiones."
    capabilities = ["api_audit", "rate_limit", "dos_test"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []
        requests_count = kwargs.get("requests", 50)
        burst_size = kwargs.get("burst", 10)
        delay = kwargs.get("delay", 0.01)
        method = kwargs.get("method", "GET")
        timeout = kwargs.get("timeout", 60)
        headers = kwargs.get("headers", {})

        url = target.rstrip("/")

        raw_lines.append(f"[INFO] Rate limit test: {requests_count} requests to {url}")
        raw_lines.append(f"[INFO] Burst: {burst_size}, Delay: {delay}s, Method: {method}")

        status_codes: dict[int, int] = {}
        total_time = 0.0
        rate_limited = False
        responses: list[dict[str, Any]] = []

        start = time.time()
        for i in range(requests_count):
            try:
                req_start = time.time()
                r = requests.request(
                    method, url,
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                )
                elapsed = time.time() - req_start
                total_time += elapsed
                status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1
                responses.append({
                    "iteration": i + 1,
                    "status": r.status_code,
                    "elapsed": round(elapsed, 3),
                    "headers": dict(r.headers),
                })

                # Detect rate limiting responses
                if r.status_code in (429, 503) or "retry-after" in {h.lower(): v for h, v in r.headers.items()}:
                    rate_limited = True

                if (i + 1) % burst_size == 0:
                    time.sleep(delay + 0.5)  # Small cooldown between bursts
            except requests.exceptions.ConnectionError:
                status_codes[0] = status_codes.get(0, 0) + 1
                responses.append({"iteration": i + 1, "status": 0, "elapsed": 0, "error": "Connection refused"})
            except requests.exceptions.Timeout:
                status_codes[0] = status_codes.get(0, 0) + 1
                responses.append({"iteration": i + 1, "status": 0, "elapsed": 0, "error": "Timeout"})
            except Exception as e:
                status_codes[0] = status_codes.get(0, 0) + 1
                responses.append({"iteration": i + 1, "status": 0, "elapsed": 0, "error": str(e)})

            if (i + 1) % burst_size == 0:
                time.sleep(delay)
                raw_lines.append(f"[BURST] {i + 1}/{requests_count} sent. Codes: {dict(sorted(status_codes.items()))}")

        total_elapsed = time.time() - start
        raw_lines.append(f"[DONE] {requests_count} requests in {total_elapsed:.2f}s")
        raw_lines.append(f"[INFO] Status code distribution: {dict(sorted(status_codes.items()))}")

        # Analysis
        success_count = status_codes.get(200, 0) + status_codes.get(201, 0) + status_codes.get(204, 0)
        error_count = status_codes.get(500, 0) + status_codes.get(502, 0) + status_codes.get(503, 0)

        if rate_limited:
            rt_headers = [r for r in responses if r.get("status") in (429, 503)]
            retry_after = ""
            for r in rt_headers[:1]:
                rh = {h.lower(): v for h, v in r.get("headers", {}).items()}
                retry_after = rh.get("retry-after", "unknown")

            findings.append({
                "file_path": url,
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "Rate limiting detected",
                "description": f"Rate limiting is active. Triggered after ~{len(rt_headers)} requests. Retry-After: {retry_after}",
                "tool": self.name,
                "rule_id": "ratelimit-active",
                "rate_limited_count": len(rt_headers),
                "retry_after": retry_after,
                "total_requests": requests_count,
            })
        else:
            findings.append({
                "file_path": url,
                "line_start": 0, "line_end": 0,
                "severity": "medium",
                "title": "No rate limiting detected",
                "description": f"Sent {requests_count} requests in {total_elapsed:.2f}s. All {success_count} succeeded. No rate limiting applied.",
                "tool": self.name,
                "rule_id": "ratelimit-missing",
                "total_requests": requests_count,
                "success_count": success_count,
                "total_time": round(total_elapsed, 2),
                "avg_response": round(total_time / requests_count, 3) if requests_count else 0,
            })

        # Error rate check
        if error_count > requests_count * 0.3:
            findings.append({
                "file_path": url,
                "line_start": 0, "line_end": 0,
                "severity": "high",
                "title": "High error rate under load",
                "description": f"{error_count}/{requests_count} requests returned 5xx errors. May indicate instability under load.",
                "tool": self.name,
                "rule_id": "ratelimit-high-errors",
                "error_count": error_count,
                "total_requests": requests_count,
            })

        summary = f"rate_limit: {len(findings)} findings ({'rate limited' if rate_limited else 'no limit'})"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
