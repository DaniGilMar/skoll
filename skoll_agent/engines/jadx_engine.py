from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


JADX_ANALYSIS_PATTERNS = [
    (r"(?i)api[_-]?key\s*=\s*['\"][^'\"]+", "Hardcoded API key"),
    (r"(?i)secret\s*=\s*['\"][^'\"]+", "Hardcoded secret"),
    (r"(?i)password\s*=\s*['\"][^'\"]{4,}", "Hardcoded password"),
    (r"(?i)token\s*=\s*['\"][^'\"]{10,}", "Hardcoded token"),
    (r"(?i)jwt|bearer\s+[a-zA-Z0-9\-_.]{20,}", "JWT/Bearer token"),
    (r"https?://[a-z0-9.\-]+\.(com|io|org|net|app)/api/", "API endpoint"),
    (r"(?:mysql|postgresql|mongodb|redis)://\S+", "Database connection string"),
    (r"firebase\.(?:io|com)/[a-z0-9\-]+", "Firebase project"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"-----BEGIN (?:RSA |EC |)?PRIVATE KEY-----", "Private key embedded"),
    (r"encrypt|decrypt|cipher|Cipher", "Cryptographic operation"),
    (r"Base64\.encode|Base64\.decode|base64_encode|base64_decode", "Base64 encoding"),
    (r"URLEncoder|URLDecoder|url_encode|url_decode", "URL encoding"),
]


class JadxEngine(BaseEngine):
    name = "jadx"
    description = "JADX APK decompiler. Descompila APK/DEX/AAR a codigo Java, analiza strings, resources y codigo fuente en busca de vulnerabilidades y secretos."
    capabilities = ["mobile_security", "android", "reverse_engineering", "static_analysis", "decompilation"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        apk_path = kwargs.get("apk", target)
        output_dir = kwargs.get("output", "/tmp/jadx_output")
        timeout = int(kwargs.get("timeout", 300))
        decompile_mode = kwargs.get("mode", "full")

        if not os.path.exists(apk_path):
            raw_lines.append(f"[WARN] APK no encontrado: {apk_path}")
            return EngineResult(
                success=False, raw_output="",
                summary=f"jadx: APK no encontrado: {apk_path}",
                findings=[{
                    "file_path": apk_path, "line_start": 0, "line_end": 0,
                    "severity": "info", "title": "APK no encontrado",
                    "description": f"El archivo {apk_path} no existe.",
                    "tool": self.name, "rule_id": "jadx-no-apk",
                }],
            )

        if not self._check_jadx(raw_lines):
            findings.append({
                "file_path": "", "line_start": 0, "line_end": 0,
                "severity": "info", "title": "JADX no instalado",
                "description": "JADX no se encuentra en PATH. Instalar desde https://github.com/skylot/jadx",
                "tool": self.name, "rule_id": "jadx-not-installed",
            })
            return EngineResult(
                success=False, raw_output="",
                summary="jadx: not installed",
                findings=findings,
            )

        raw_lines.append(f"[INFO] JADX decompilando {apk_path}...")

        # Decompile with jadx
        args = ["jadx", "--deobf", "--show-bad-code",
                "-d", output_dir,
                apk_path]

        if decompile_mode == "strings":
            args = ["jadx", "--deobf", "--show-bad-code",
                    "--output-format", "json",
                    "-d", output_dir,
                    apk_path]

        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            raw_lines.append(f"[INFO] jadx exit code: {result.returncode}")
            if result.stderr:
                raw_lines.append(f"[STDERR] {result.stderr[:300]}")

            if result.returncode == 0:
                raw_lines.append(f"[INFO] JADX decompilation OK -> {output_dir}")
                findings.append({
                    "file_path": apk_path, "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "APK decompilado exitosamente",
                    "description": f"JADX decompilo {apk_path} a {output_dir}",
                    "tool": self.name, "rule_id": "jadx-decompiled",
                    "output_dir": output_dir,
                })

                # Analyze decompiled source
                self._analyze_source(output_dir, apk_path, findings, raw_lines)

            else:
                raw_lines.append(f"[WARN] jadx failed: {result.stderr[:300]}")
                findings.append({
                    "file_path": apk_path, "line_start": 0, "line_end": 0,
                    "severity": "low",
                    "title": "JADX decompilation fallo",
                    "description": f"JADX no pudo decompilar {apk_path}: {result.stderr[:200]}",
                    "tool": self.name, "rule_id": "jadx-failed",
                })

        except subprocess.TimeoutExpired:
            raw_lines.append(f"[TIMEOUT] jadx decompilation timed out ({timeout}s)")
            findings.append({
                "file_path": apk_path, "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "JADX decompilation timeout",
                "description": f"JADX timed out after {timeout}s on {apk_path}. APK may be large.",
                "tool": self.name, "rule_id": "jadx-timeout",
            })
        except Exception as e:
            raw_lines.append(f"[ERR] jadx: {e}")

        summary = f"jadx: {len(findings)} hallazgos en {apk_path.split('/')[-1]}"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _analyze_source(self, output_dir: str, apk_path: str,
                        findings: list[dict[str, Any]],
                        raw_lines: list[str]) -> None:
        java_files = []
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                if f.endswith(".java") or f.endswith(".json"):
                    fpath = os.path.join(root, f)
                    size = os.path.getsize(fpath)
                    if size < 500 * 1024:
                        java_files.append(fpath)

        raw_lines.append(f"[INFO] Archivos Java/JSON: {len(java_files)}")

        # Scan each file for patterns
        for fpath in java_files:
            rel_path = os.path.relpath(fpath, output_dir)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern, desc in JADX_ANALYSIS_PATTERNS:
                    matches = re.findall(pattern, content)
                    for m in matches[:1]:
                        masked = m[:10] + "..." + m[-4:] if len(m) > 14 else m
                        finding_key = f"{desc[:15]}:{rel_path[:30]}"
                        findings.append({
                            "file_path": rel_path, "line_start": 0, "line_end": 0,
                            "severity": "high",
                            "title": f"JADX: {desc}",
                            "description": f"Patron '{desc}' encontrado en {rel_path}: {masked}",
                            "tool": self.name, "rule_id": f"jadx-{desc[:10].lower().replace(' ','')}-{f.split('/')[-1][:20]}",
                            "pattern": desc, "file": rel_path, "match": masked,
                        })
                        if len(findings) > 100:
                            return
            except (FileNotFoundError, PermissionError, UnicodeDecodeError):
                pass

        # Summary
        string_counts: dict[str, int] = {}
        for f in findings:
            key = f.get("pattern", "other")
            string_counts[key] = string_counts.get(key, 0) + 1

        raw_lines.append(f"[INFO] JADX analysis summary:")
        for pattern, count in sorted(string_counts.items(), key=lambda x: -x[1])[:10]:
            raw_lines.append(f"  {pattern}: {count}")

    def _check_jadx(self, raw_lines: list[str]) -> bool:
        try:
            r = subprocess.run(["jadx", "--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                raw_lines.append(f"[INFO] JADX version: {r.stdout.strip() or r.stderr.strip()}")
                return True
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
