from __future__ import annotations

import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class RedisEngine(BaseEngine):
    name = "redis"
    description = "Redis no-auth check. Detecta instancias Redis sin autenticación."
    capabilities = ["redis_check", "no_auth", "database_enum"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout_s = int(kwargs.get("timeout", 15))
        port = kwargs.get("port", 6379)
        args = [
            "redis-cli", "-h", target, "-p", str(port), "INFO", "server",
        ]
        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout_s,
            )
            raw = result.stdout + result.stderr
            findings = []

            if "redis_version" in raw or "uptime_in_seconds" in raw:
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "critical",
                    "title": "Redis no-auth access",
                    "description": f"Redis on {target}:{port} is accessible without authentication",
                    "tool": self.name,
                    "rule_id": "redis-noauth",
                    "recommendation": "Set requirepass in redis.conf and use AUTH",
                })

            summary = f"redis: {'accessible' if findings else 'no access'} on {target}:{port}"
            return EngineResult(
                success=len(findings) > 0, raw_output=raw,
                findings=findings, summary=summary, error="",
            )
        except subprocess.TimeoutExpired:
            return EngineResult(success=False, raw_output="", summary=f"redis: timeout {target}", error="Timeout")
        except FileNotFoundError:
            return EngineResult(success=False, raw_output="", summary="redis-cli: not installed", error="Install redis-tools")
        except Exception as e:
            return EngineResult(success=False, raw_output="", summary=f"redis: {e}", error=str(e))

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []


class MySqlEngine(BaseEngine):
    name = "mysql"
    description = "MySQL default creds check. Prueba root:root, root:'' y otras combinaciones comunes."
    capabilities = ["mysql_check", "default_creds", "database_enum"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout_s = int(kwargs.get("timeout", 15))
        port = int(kwargs.get("port", 3306))
        creds = kwargs.get("credentials", [
            ("root", ""),
            ("root", "root"),
            ("root", "password"),
            ("admin", ""),
        ])
        findings = []
        raw_lines = []

        for user, passwd in creds:
            args = [
                "mysql", "-h", target, "-P", str(port),
                "-u", user, f"-p{passwd}", "-e", "SELECT 1;",
                "--connect-timeout=5", "-N", "--batch",
            ]
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=timeout_s)
                output = r.stdout + r.stderr
                raw_lines.append(f"[{user}:{passwd}] {output.strip()}")
                if "ERROR" not in output.upper() and r.returncode == 0:
                    findings.append({
                        "file_path": "", "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": f"MySQL default creds: {user}:{passwd}",
                        "description": f"MySQL on {target}:{port} accepts {user}:{passwd}",
                        "tool": self.name,
                        "rule_id": f"mysql-default-{user}",
                        "user": user, "password": passwd,
                        "recommendation": "Change default MySQL credentials immediately",
                    })
            except subprocess.TimeoutExpired:
                raw_lines.append(f"[{user}:{passwd}] timeout")
                continue
            except FileNotFoundError:
                return EngineResult(success=False, raw_output="", summary="mysql: not installed", error="Install mysql-client")
            except Exception as e:
                raw_lines.append(f"[{user}:{passwd}] {e}")

        raw = "\n".join(raw_lines)
        summary = f"mysql: {len(findings)} default creds on {target}:{port}"
        return EngineResult(
            success=len(findings) > 0, raw_output=raw,
            findings=findings, summary=summary, error="",
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []


class PostgresEngine(BaseEngine):
    name = "postgres"
    description = "PostgreSQL default creds check. Prueba postgres:postgres y otras combinaciones."
    capabilities = ["postgres_check", "default_creds", "database_enum"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        timeout_s = int(kwargs.get("timeout", 15))
        port = int(kwargs.get("port", 5432))
        creds = kwargs.get("credentials", [
            ("postgres", "postgres"),
            ("postgres", ""),
            ("postgres", "password"),
            ("admin", "admin"),
        ])
        findings = []
        raw_lines = []

        for user, passwd in creds:
            env = {"PGPASSWORD": passwd}
            args = [
                "psql", "-h", target, "-p", str(port),
                "-U", user, "-c", "SELECT 1;",
                "--no-password",
            ]
            try:
                r = subprocess.run(
                    args, env=env,
                    capture_output=True, text=True, timeout=timeout_s,
                )
                output = r.stdout + r.stderr
                raw_lines.append(f"[{user}:{passwd}] {output.strip()}")
                if "FATAL" not in output.upper() and r.returncode == 0:
                    findings.append({
                        "file_path": "", "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": f"PostgreSQL default creds: {user}:{passwd}",
                        "description": f"PostgreSQL on {target}:{port} accepts {user}:{passwd}",
                        "tool": self.name,
                        "rule_id": f"postgres-default-{user}",
                        "user": user, "password": passwd,
                        "recommendation": "Change default PostgreSQL credentials immediately",
                    })
            except subprocess.TimeoutExpired:
                raw_lines.append(f"[{user}:{passwd}] timeout")
                continue
            except FileNotFoundError:
                return EngineResult(success=False, raw_output="", summary="psql: not installed", error="Install postgresql-client")
            except Exception as e:
                raw_lines.append(f"[{user}:{passwd}] {e}")

        raw = "\n".join(raw_lines)
        summary = f"postgres: {len(findings)} default creds on {target}:{port}"
        return EngineResult(
            success=len(findings) > 0, raw_output=raw,
            findings=findings, summary=summary, error="",
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
