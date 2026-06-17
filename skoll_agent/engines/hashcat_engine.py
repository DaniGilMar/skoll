from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


HASH_MODE_MAP: dict[str, int] = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700,
    "ntlm": 1000,
    "netntlm": 5500,
    "netntlmv2": 5600,
    "krb5tgs": 13100,
    "krb5asrep": 18200,
    "bcrypt": 3200,
    "sha1dasan": 110,
    "mysql": 300,
    "mysqlsha1": 200,
    "oracle12c": 2100,
    "postgres": 12,
    "descrypt": 1500,
    "md5crypt": 500,
    "sha256crypt": 7400,
    "sha512crypt": 1800,
    "lm": 3000,
}


class HashcatEngine(BaseEngine):
    name = "hashcat"
    description = "Hashcat GPU-accelerated hash cracker. Rompe hashes NTLM, Kerberos, MD5, SHA, bcrypt, etc. via diccionario, reglas o fuerza bruta."
    capabilities = ["password_cracking", "hash_cracking", "offline_attack", "credential_recovery"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        hash_input = kwargs.get("hash", target)
        hash_type = kwargs.get("hash_type", "ntlm")
        from skoll_agent.config.wordlists import resolve_wordlist
        wordlist = resolve_wordlist("passwords_common", kwargs.get("wordlist"))
        rules = kwargs.get("rules", "/usr/share/hashcat/rules/best64.rule")
        timeout = int(kwargs.get("timeout", 300))
        hash_mode = kwargs.get("hash_mode", HASH_MODE_MAP.get(hash_type, 1000))
        attack_mode = kwargs.get("attack_mode", "dictionary")
        username = kwargs.get("username", "")
        output_file = kwargs.get("output", "/tmp/hashcat_cracked.txt")

        raw_lines.append(f"[INFO] Hashcat cracking {hash_type} (mode {hash_mode}), attack={attack_mode}")

        # Write hash to temp file
        hash_content = hash_input
        if username and ":" not in hash_input:
            hash_content = f"{username}:{hash_input}"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            hash_file = f.name
            f.write(hash_content.strip() + "\n")

        cracked_count = 0

        try:
            args = [
                "hashcat", "-m", str(hash_mode),
                "-a", "3" if attack_mode == "bruteforce" else "0",
                "-o", output_file,
                "--potfile-disable",
                "--force",
            ]

            if attack_mode == "dictionary":
                wordlist_path = wordlist
                if wordlist_path.endswith(".gz"):
                    args_gunzip = ["gunzip", "-c", wordlist_path]
                    args = [
                        "hashcat", "-m", str(hash_mode),
                        "-a", "0",
                        "-o", output_file,
                        "--potfile-disable",
                        "--force",
                        "-r", rules,
                        hash_file,
                        wordlist_path,
                    ]
                else:
                    args.extend(["-r", rules, hash_file, wordlist_path])

            elif attack_mode == "bruteforce":
                mask = kwargs.get("mask", "?l?l?l?l?l?l")
                args = [
                    "hashcat", "-m", str(hash_mode),
                    "-a", "3",
                    "-o", output_file,
                    "--potfile-disable",
                    "--force",
                    "--increment",
                    hash_file,
                    mask,
                ]

            elif attack_mode == "rules":
                wordlist_path = wordlist
                args = [
                    "hashcat", "-m", str(hash_mode),
                    "-a", "0",
                    "-o", output_file,
                    "--potfile-disable",
                    "--force",
                    "-r", rules,
                    hash_file,
                    wordlist_path,
                ]

            raw_lines.append(f"[INFO] Comando: {' '.join(str(a) for a in args[:8])}...")

            # Run hashcat
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            stdout = result.stdout
            stderr = result.stderr
            combined = stdout + stderr

            raw_lines.append(f"[INFO] hashcat exit code: {result.returncode}")
            if stderr:
                raw_lines.append(f"[STDERR] {stderr[:500]}")

            # Try to read cracked results
            if os.path.exists(output_file):
                try:
                    with open(output_file) as f:
                        cracked_lines = f.readlines()
                    cracked_count = len(cracked_lines)
                    raw_lines.append(f"[OK] {cracked_count} hashes cracked!")

                    for cl in cracked_lines[:20]:
                        cl = cl.strip()
                        if ":" in cl:
                            parts = cl.split(":", 1)
                            u = parts[0] if username else "hash"
                            pwd = parts[1]
                            raw_lines.append(f"  → {u}:{pwd}")
                            findings.append({
                                "file_path": "",
                                "line_start": 0, "line_end": 0,
                                "severity": "critical",
                                "title": f"Hash cracked: {u}",
                                "description": f"Hash de tipo {hash_type} roto via hashcat. Password: {pwd}",
                                "tool": self.name,
                                "rule_id": f"hashcat-cracked-{u.lower()}" if username else "hashcat-cracked",
                                "username": u,
                                "password": pwd,
                                "hash_type": hash_type,
                            })
                except (FileNotFoundError, PermissionError):
                    pass

            # Check hashcat status in stderr for progress
            progress_match = re.search(r"Progress:\s*([^/]+)/([^\s]+)", combined)
            if progress_match:
                raw_lines.append(f"[PROGRESS] {progress_match.group(0)}")

            status_match = re.search(r"Status\.\.\.:\s*(\w+)", combined)
            if status_match:
                status = status_match.group(1)
                raw_lines.append(f"[STATUS] {status}")

            # Analysis
            if cracked_count == 0:
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"Hash no crackeado: {hash_type}",
                    "description": f"Hash de tipo {hash_type} no fue roto con la wordlist/reglas proporcionadas. Intentar con wordlists mas grandes o reglas adicionales.",
                    "tool": self.name,
                    "rule_id": "hashcat-uncracked",
                    "hash_type": hash_type,
                })

            # Parse - showing potfile or existing results
            if "No hashes loaded" in combined:
                raw_lines.append("[WARN] hashcat: No hashes loaded — formato de hash incorrecto?")
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "low",
                    "title": "Hashcat: no se pudo cargar el hash",
                    "description": f"El hash proporcionado no coincide con el modo {hash_mode} ({hash_type}). Verificar formato.",
                    "tool": self.name,
                    "rule_id": "hashcat-no-load",
                })

        except FileNotFoundError:
            raw_lines.append("[WARN] hashcat no instalado")
            findings.append({
                "file_path": "",
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "Hashcat no instalado",
                "description": "Hashcat no se encuentra en PATH. Instalar: sudo apt install hashcat",
                "tool": self.name,
                "rule_id": "hashcat-not-installed",
            })
        except subprocess.TimeoutExpired:
            raw_lines.append(f"[TIMEOUT] hashcat timed out ({timeout}s)")
            if os.path.exists(output_file):
                try:
                    with open(output_file) as f:
                        partial = f.readlines()
                    raw_lines.append(f"[PARTIAL] {len(partial)} hashes crackeados antes del timeout")
                except Exception:
                    pass
        except Exception as e:
            raw_lines.append(f"[ERR] hashcat: {e}")
        finally:
            try:
                os.unlink(hash_file)
            except Exception:
                pass

        summary = f"hashcat: {cracked_count}/{1} hashes crackeados ({hash_type})"
        return EngineResult(
            success=cracked_count > 0,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def identify_hash_type(self, hash_str: str) -> str:
        length = len(hash_str)
        if length == 32 and all(c in "0123456789abcdef" for c in hash_str.lower()):
            return "ntlm" if hash_str.count("$") == 0 else "md5"
        if length == 40 and all(c in "0123456789abcdef" for c in hash_str.lower()):
            return "sha1"
        if length == 64 and all(c in "0123456789abcdef" for c in hash_str.lower()):
            return "sha256"
        if hash_str.startswith("$2a$") or hash_str.startswith("$2b$"):
            return "bcrypt"
        if hash_str.startswith("$krb5asrep$"):
            return "krb5asrep"
        if hash_str.startswith("$krb5tgs$"):
            return "krb5tgs"
        return "ntlm"

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
