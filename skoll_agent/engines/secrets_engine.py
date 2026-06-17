from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


SECRET_PATTERNS: dict[str, list[str]] = {
    "aws_key": [
        r"AKIA[0-9A-Z]{16}",
        r"(?i)aws[_\-\.]?(?:access\s*)?key[_\-\.]?id?\s*[=:]\s*['\"]?AKIA[0-9A-Z]{16}",
    ],
    "aws_secret": [
        r"(?i)aws[_\-\.]?(?:secret\s*)?access\s*key\s*[=:]\s*['\"][0-9a-zA-Z\/+]{40}['\"]",
    ],
    "azure_connection": [
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
    ],
    "gcp_service_account": [
        r"-----BEGIN PRIVATE KEY-----",
        r"\"type\": \"service_account\"",
        r"\"project_id\": \"[^\"]+\"",
    ],
    "github_token": [
        r"(?i)github[_\-\.]?token\s*[=:]\s*['\"][0-9a-zA-Z_]{35,40}['\"]",
        r"ghp_[0-9a-zA-Z]{36}",
        r"gho_[0-9a-zA-Z]{36}",
    ],
    "slack_token": [
        r"xox[pborsa]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}",
    ],
    "google_api_key": [
        r"AIza[0-9A-Za-z\-_]{35}",
    ],
    "jwt_token": [
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    ],
    "private_key": [
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        r"-----BEGIN CERTIFICATE-----",
    ],
    "password_env": [
        r"(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*['\"][^'\"]{3,}['\"]",
    ],
    "connection_string": [
        r"(?i)(?:mysql|postgres(?:ql)?|mongodb|redis)://[^\s]{3,}",
    ],
}

SECRET_SEVERITY: dict[str, str] = {
    "aws_key": "critical",
    "aws_secret": "critical",
    "azure_connection": "critical",
    "gcp_service_account": "critical",
    "github_token": "high",
    "slack_token": "high",
    "google_api_key": "high",
    "jwt_token": "high",
    "private_key": "critical",
    "password_env": "high",
    "connection_string": "high",
}


class SecretsEngine(BaseEngine):
    name = "secrets"
    description = "Secrets leakage scanner. Detecta claves AWS, Azure, GCP, GitHub tokens, JWT, passwords y secretos hardcodeados en codigo, git history, env y URLs publicas."
    capabilities = ["cloud_security", "secrets", "code_audit", "leak_detection", "supply_chain"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        mode = kwargs.get("mode", "url")
        depth = int(kwargs.get("depth", 3))
        timeout = int(kwargs.get("timeout", 60))

        raw_lines.append(f"[INFO] Secrets scan mode={mode} target={target[:80]}")

        if mode == "url":
            self._scan_url(target, findings, raw_lines, timeout)
        elif mode == "dir":
            self._scan_directory(target, findings, raw_lines, depth)
        elif mode == "git":
            self._scan_git(target, findings, raw_lines, timeout)
        elif mode == "env":
            self._scan_env(target, findings, raw_lines)
        elif mode == "all":
            self._scan_directory(target, findings, raw_lines, depth)
            self._scan_env("", findings, raw_lines)
            if os.path.exists(os.path.join(target, ".git")):
                self._scan_git(target, findings, raw_lines, timeout)
        else:
            raw_lines.append(f"[WARN] Modo no soportado: {mode}")

        summary = f"secrets: {len(findings)} secretos encontrados"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _scan_url(self, url: str, findings: list[dict[str, Any]],
                  raw_lines: list[str], timeout: int) -> None:
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            body = r.text

            for secret_type, patterns in SECRET_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, body)
                    for match in matches[:5]:
                        sev = SECRET_SEVERITY.get(secret_type, "high")
                        masked = match[:8] + "..." + match[-4:] if len(match) > 16 else match
                        findings.append({
                            "file_path": url, "line_start": 0, "line_end": 0,
                            "severity": sev,
                            "title": f"Secreto expuesto: {secret_type} en {url}",
                            "description": f"Se encontró un patrón de {secret_type} en la URL {url}: {masked}",
                            "tool": self.name, "rule_id": f"secret-{secret_type}-url",
                            "secret_type": secret_type, "url": url, "match": masked[:50],
                        })
                        raw_lines.append(f"[{sev.upper()}] {secret_type}: {masked} en {url}")

        except requests.exceptions.ConnectionError:
            raw_lines.append(f"[ERR] Connection error: {url}")
        except requests.exceptions.Timeout:
            raw_lines.append(f"[TIMEOUT] {url}")
        except Exception as e:
            raw_lines.append(f"[ERR] {url}: {e}")

    def _scan_directory(self, path: str, findings: list[dict[str, Any]],
                        raw_lines: list[str], depth: int) -> None:
        if not os.path.isdir(path):
            if os.path.isfile(path):
                self._scan_file(path, findings, raw_lines)
            return

        raw_lines.append(f"[INFO] Scanning directory: {path} (depth={depth})")

        for root, dirs, files in os.walk(path):
            rel_depth = root.replace(path, "").count(os.sep)
            if rel_depth > depth:
                dirs.clear()
                continue

            # Skip common dirs
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv",
                                                      "__pycache__", ".cache", ".npm", ".next")]

            for fname in files:
                fpath = os.path.join(root, fname)
                if self._should_skip_file(fname):
                    continue
                self._scan_file(fpath, findings, raw_lines)

    def _should_skip_file(self, fname: str) -> bool:
        skip_extensions = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
                           ".mp3", ".mp4", ".avi", ".mov", ".mkv",
                           ".woff", ".woff2", ".ttf", ".eot",
                           ".zip", ".gz", ".tar", ".7z", ".rar",
                           ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                           ".min.js", ".min.css", ".map",
                           ".lock", ".sum")
        return fname.endswith(skip_extensions) or fname in (".gitkeep", ".gitignore", "package-lock.json")

    def _scan_file(self, fpath: str, findings: list[dict[str, Any]],
                   raw_lines: list[str]) -> None:
        try:
            size = os.path.getsize(fpath)
            if size > 500 * 1024:
                return

            with open(fpath, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for secret_type, patterns in SECRET_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    for match in matches[:2]:
                        sev = SECRET_SEVERITY.get(secret_type, "high")
                        masked = match[:8] + "..." + match[-4:] if len(match) > 16 else match
                        findings.append({
                            "file_path": fpath, "line_start": 0, "line_end": 0,
                            "severity": sev,
                            "title": f"Secreto hardcodeado: {secret_type}",
                            "description": f"Patrón de {secret_type} encontrado en {fpath}: {masked}",
                            "tool": self.name, "rule_id": f"secret-{secret_type}-{fpath.split('/')[-1][:20]}",
                            "secret_type": secret_type, "file": fpath, "match": masked[:50],
                        })
                        raw_lines.append(f"[{sev.upper()}] {secret_type}: {masked} en {fpath}")

        except (FileNotFoundError, PermissionError):
            pass
        except Exception as e:
            raw_lines.append(f"[ERR] {fpath}: {e}")

    def _scan_git(self, path: str, findings: list[dict[str, Any]],
                  raw_lines: list[str], timeout: int) -> None:
        try:
            r = subprocess.run(
                ["git", "log", "-p", "--all", "--diff-filter=AM", "--since=5.years"],
                capture_output=True, text=True, timeout=timeout,
                cwd=path,
            )
            git_log = r.stdout + r.stderr

            if not git_log.strip():
                raw_lines.append("[INFO] Git log vacio")
                return

            for secret_type, patterns in SECRET_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, git_log)
                    for match in matches[:2]:
                        sev = SECRET_SEVERITY.get(secret_type, "high")
                        masked = match[:8] + "..." + match[-4:] if len(match) > 16 else match
                        findings.append({
                            "file_path": path, "line_start": 0, "line_end": 0,
                            "severity": sev,
                            "title": f"Secreto en git history: {secret_type}",
                            "description": f"Patrón de {secret_type} encontrado en el historial de git: {masked}",
                            "tool": self.name, "rule_id": f"secret-git-{secret_type}",
                            "secret_type": secret_type, "git_path": path, "match": masked[:50],
                        })
                        raw_lines.append(f"[{sev.upper()}] {secret_type}: {masked} en git history de {path}")

        except FileNotFoundError:
            raw_lines.append("[WARN] Git no disponible")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] Git log timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] Git: {e}")

    def _scan_env(self, env_path: str, findings: list[dict[str, Any]],
                  raw_lines: list[str]) -> None:
        paths = []
        if env_path and os.path.isfile(env_path):
            paths = [env_path]
        elif env_path and os.path.isdir(env_path):
            paths = [os.path.join(env_path, f) for f in os.listdir(env_path)
                     if f.startswith(".env") or f.endswith(".env") or
                     f in (".env.example", ".env.local", ".env.production", ".env.development")]
        else:
            # Look in common locations
            for base in [os.getcwd(), "/etc", os.path.expanduser("~")]:
                for f in [".env", ".env.example", ".env.local"]:
                    p = os.path.join(base, f)
                    if os.path.isfile(p):
                        paths.append(p)

        for env_file in set(paths):
            try:
                with open(env_file, encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for secret_type, patterns in SECRET_PATTERNS.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        for match in matches[:2]:
                            sev = SECRET_SEVERITY.get(secret_type, "high")
                            masked = match[:10] + "..." + match[-4:] if len(match) > 14 else match
                            findings.append({
                                "file_path": env_file, "line_start": 0, "line_end": 0,
                                "severity": sev,
                                "title": f"Secreto en archivo env: {secret_type}",
                                "description": f"Patrón de {secret_type} encontrado en {env_file}: {masked}",
                                "tool": self.name, "rule_id": f"secret-env-{secret_type}",
                                "secret_type": secret_type, "file": env_file, "match": masked[:50],
                            })
                            raw_lines.append(f"[{sev.upper()}] {secret_type}: {masked} en {env_file}")
            except Exception:
                pass

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
