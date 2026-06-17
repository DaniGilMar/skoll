from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class JohnEngine(BaseEngine):
    name = "john"
    description = "John the Ripper hash cracker. Rompe hashes NTLM, Kerberos, MD5, SHA, bcrypt, etc. via diccionario, reglas, o incremental."
    capabilities = ["password_cracking", "hash_cracking", "offline_attack", "credential_recovery"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        hash_input = kwargs.get("hash", target)
        hash_type = kwargs.get("hash_type", "ntlm")
        from skoll_agent.config.wordlists import resolve_wordlist
        wordlist = resolve_wordlist("passwords_common", kwargs.get("wordlist"))
        crack_mode = kwargs.get("crack_mode", "wordlist")
        timeout = int(kwargs.get("timeout", 300))
        username = kwargs.get("username", "")

        raw_lines.append(f"[INFO] John the Ripper cracking {hash_type}, mode={crack_mode}")

        hash_content = hash_input
        if username and ":" not in hash_input:
            hash_content = f"{username}:{hash_input}"
        elif not username:
            hash_content = f"hash:{hash_input}"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            hash_file = f.name
            f.write(hash_content.strip() + "\n")

        fmt_map = {
            "ntlm": "NT",
            "md5": "raw-md5",
            "sha1": "raw-sha1",
            "sha256": "raw-sha256",
            "sha512": "raw-sha512",
            "bcrypt": "bcrypt",
            "krb5tgs": "krb5tgs",
            "krb5asrep": "krb5asrep",
            "descrypt": "des",
            "md5crypt": "md5crypt",
            "sha256crypt": "sha256crypt",
            "sha512crypt": "sha512crypt",
            "lm": "lm",
        }

        cracked_count = 0

        try:
            john_format = fmt_map.get(hash_type, "NT")

            if crack_mode == "wordlist":
                args = ["john", f"--wordlist={wordlist}", f"--format={john_format}", hash_file]
            elif crack_mode == "rules":
                args = ["john", f"--wordlist={wordlist}", f"--format={john_format}", "--rules", hash_file]
            elif crack_mode == "incremental":
                args = ["john", f"--format={john_format}", "--incremental", hash_file]
            elif crack_mode == "single":
                args = ["john", f"--format={john_format}", "--single", hash_file]
            else:
                args = ["john", f"--wordlist={wordlist}", f"--format={john_format}", hash_file]

            raw_lines.append(f"[INFO] Comando: john {' '.join(args[1:4])}...")

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            stdout = result.stdout
            stderr = result.stderr
            combined = stdout + stderr

            raw_lines.append(f"[INFO] john exit code: {result.returncode}")
            if stderr:
                raw_lines.append(f"[STDERR] {stderr[:500]}")

            show_args = ["john", "--show", f"--format={john_format}", hash_file]
            show_result = subprocess.run(
                show_args, capture_output=True, text=True, timeout=30,
            )
            show_output = show_result.stdout + show_result.stderr

            for line in show_output.split("\n"):
                line = line.strip()
                if ":" in line and "password hash" not in line.lower() and "cracked" not in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1]:
                        u = parts[0]
                        pwd = parts[1]
                        cracked_count += 1
                        raw_lines.append(f"  -> {u}:{pwd}")
                        findings.append({
                            "file_path": "",
                            "line_start": 0, "line_end": 0,
                            "severity": "critical",
                            "title": f"Hash crackeado via John: {u}",
                            "description": f"Hash {hash_type} roto via John the Ripper. Password: {pwd}",
                            "tool": self.name,
                            "rule_id": f"john-cracked-{u.lower()}" if u != "hash" else "john-cracked",
                            "username": u if u != "hash" else "",
                            "password": pwd,
                            "hash_type": hash_type,
                        })

            if cracked_count == 0:
                raw_lines.append("[INFO] John: ningun hash crackeado")
                if "No password hashes loaded" in combined:
                    raw_lines.append("[WARN] John: No password hashes loaded - formato incorrecto?")
                    findings.append({
                        "file_path": "",
                        "line_start": 0, "line_end": 0,
                        "severity": "low",
                        "title": "John: hash no cargado",
                        "description": f"John no pudo cargar el hash como formato {john_format}. Verificar tipo de hash.",
                        "tool": self.name,
                        "rule_id": "john-no-load",
                    })
                elif "Loaded" in stderr:
                    loaded_match = re.search(r"Loaded\s+(\d+)\s+password\s+hash", stderr)
                    if loaded_match:
                        loaded = loaded_match.group(1)
                        raw_lines.append(f"[INFO] John: {loaded} hash cargado pero no crackeado")
                        findings.append({
                            "file_path": "",
                            "line_start": 0, "line_end": 0,
                            "severity": "info",
                            "title": f"Hash no crackeado ({hash_type})",
                            "description": f"Hash de tipo {hash_type} cargado pero no fue roto con el modo {crack_mode}. Intentar wordlists mas grandes o modo incremental.",
                            "tool": self.name,
                            "rule_id": "john-uncracked",
                        })

            progress_match = re.search(r"(\d+g\s+\d+:\d+:\d+:\d+)", combined)
            if progress_match:
                raw_lines.append(f"[PROGRESS] {progress_match.group(1)}")

        except FileNotFoundError:
            raw_lines.append("[WARN] john no instalado")
            findings.append({
                "file_path": "",
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "John the Ripper no instalado",
                "description": "John no se encuentra en PATH. Instalar: sudo apt install john",
                "tool": self.name,
                "rule_id": "john-not-installed",
            })
        except subprocess.TimeoutExpired:
            raw_lines.append(f"[TIMEOUT] john timed out ({timeout}s)")
        except Exception as e:
            raw_lines.append(f"[ERR] john: {e}")
        finally:
            try:
                os.unlink(hash_file)
            except Exception:
                pass

        summary = f"john: {cracked_count} hashes crackeados ({crack_mode})"
        return EngineResult(
            success=cracked_count > 0,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
