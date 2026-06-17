from __future__ import annotations

import json
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class PostmanEngine(BaseEngine):
    name = "postman"
    description = "Postman/Newman API test runner. Ejecuta colecciones Postman via Newman y analiza resultados de tests."
    capabilities = ["api_audit", "postman", "newman", "integration_test"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        collection = kwargs.get("collection", target)
        environment = kwargs.get("environment", "")
        reporters = kwargs.get("reporters", "cli,json")
        timeout = int(kwargs.get("timeout", 120))

        args = [
            "newman", "run", collection,
            "--reporters", reporters,
            "--reporter-json-export", "/tmp/newman_report.json",
            "--delay-request", "100",
            "--timeout-request", "10000",
        ]
        if environment:
            args.extend(["-e", environment])
        if kwargs.get("insecure", True):
            args.append("--insecure")
        if kwargs.get("folder"):
            args.extend(["--folder", kwargs["folder"]])

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            stdout = result.stdout
            stderr = result.stderr
            combined = stdout + stderr
            raw_lines.append(stdout[:2000] if stdout else "newman: no stdout")
            if stderr:
                raw_lines.append(f"[STDERR] {stderr[:1000]}")

            # Try to parse the JSON report
            try:
                with open("/tmp/newman_report.json") as f:
                    report = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                report = None

            if report:
                run = report.get("run", {})
                executions = run.get("executions", [])
                stats = run.get("stats", {})
                total_reqs = stats.get("requests", {}).get("total", 0)
                failed_reqs = stats.get("requests", {}).get("failed", 0)
                total_asserts = stats.get("assertions", {}).get("total", 0)
                failed_asserts = stats.get("assertions", {}).get("failed", 0)

                raw_lines.append(f"[INFO] Newman: {total_reqs} requests, {failed_reqs} failed")
                raw_lines.append(f"[INFO] Newman: {total_asserts} assertions, {failed_asserts} failed")

                if failed_asserts > 0:
                    findings.append({
                        "file_path": collection,
                        "line_start": 0, "line_end": 0,
                        "severity": "medium",
                        "title": f"Newman test failures: {failed_asserts} assertions failed",
                        "description": f"Postman collection {collection} had {failed_asserts}/{total_asserts} failed assertions across {total_reqs} requests.",
                        "tool": self.name,
                        "rule_id": "postman-assertions-failed",
                        "collection": collection,
                        "total_asserts": total_asserts,
                        "failed_asserts": failed_asserts,
                        "total_requests": total_reqs,
                        "failed_requests": failed_reqs,
                    })

                # Check individual execution failures
                for exec_ in executions[:20]:
                    req = exec_.get("request", {})
                    req_method = req.get("method", "GET")
                    req_url = req.get("url", {})
                    url_str = ""
                    if isinstance(req_url, dict):
                        url_str = "".join(req_url.get("path", []))
                    else:
                        url_str = str(req_url)

                    assertion_failures = exec_.get("assertions", []) or []
                    for af in assertion_failures:
                        if af.get("error"):
                            err = af["error"]
                            findings.append({
                                "file_path": url_str,
                                "line_start": 0, "line_end": 0,
                                "severity": "medium",
                                "title": f"Newman assertion failure: {err.get('name', 'Unknown')}",
                                "description": f"{req_method} {url_str}: {err.get('message', '')}",
                                "tool": self.name,
                                "rule_id": "postman-assertion-error",
                                "assertion": err.get("name", ""),
                                "method": req_method,
                                "url": url_str,
                            })
            else:
                # No JSON report, parse text output
                for line in combined.split("\n"):
                    if "fail" in line.lower() and ("assert" in line.lower() or "error" in line.lower()):
                        findings.append({
                            "file_path": collection,
                            "line_start": 0, "line_end": 0,
                            "severity": "medium",
                            "title": "Newman test failure",
                            "description": line[:200],
                            "tool": self.name,
                            "rule_id": "postman-text-failure",
                        })

            success = result.returncode == 0
            summary = f"postman: {len(findings)} issues, collection {collection} {'passed' if success else 'failed'}"
            return EngineResult(
                success=success,
                raw_output="\n".join(raw_lines),
                findings=findings,
                summary=summary,
            )

        except FileNotFoundError:
            return EngineResult(
                success=False, raw_output="",
                summary="newman: not installed. Install with: npm install -g newman",
                error="newman not installed",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                success=False, raw_output="",
                summary=f"newman: timeout ({timeout}s)",
                error=f"Timeout ({timeout}s)",
            )
        except Exception as e:
            return EngineResult(
                success=False, raw_output="",
                summary=f"newman: {e}",
                error=str(e),
            )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
