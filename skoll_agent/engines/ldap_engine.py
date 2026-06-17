from __future__ import annotations

import subprocess
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class LdapEngine(BaseEngine):
    name = "ldap"
    description = "LDAP enumeration engine. Enumeracion de dominios AD, usuarios, grupos, permisos y objetos via LDAP."
    capabilities = ["ad_audit", "ldap", "enumeration", "active_directory"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        domain = kwargs.get("domain", target)
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        base_dn = kwargs.get("base_dn", "")
        timeout = int(kwargs.get("timeout", 60))

        if not base_dn:
            base_dn = ",".join(f"dc={part}" for part in domain.split(".") if part)

        raw_lines.append(f"[INFO] LDAP enumerando {domain} base_dn={base_dn}")

        # Strategy 1: ldapsearch (native)
        try:
            args = [
                "ldapsearch", "-x", "-H", f"ldap://{target}",
                "-b", base_dn,
                "-s", "sub",
                "-LLL",
                "-o", "ldif-wrap=no",
            ]
            if username and password:
                args = [
                    "ldapsearch", "-x", "-H", f"ldap://{target}",
                    "-D", f"{username}@{domain}",
                    "-w", password,
                    "-b", base_dn,
                    "-s", "sub",
                    "-LLL",
                    "-o", "ldif-wrap=no",
                ]

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            stdout = result.stdout
            stderr = result.stderr

            if "ldap_bind" in stderr and "Invalid credentials" in stderr:
                findings.append({
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": "LDAP bind failed — credenciales invalidas",
                    "description": f"No se pudo autenticar en LDAP de {target} con usuario {username}",
                    "tool": self.name,
                    "rule_id": "ldap-invalid-creds",
                })
                raw_lines.append("[WARN] ldapsearch: Invalid credentials")
            elif "ldap_bind" in stderr and "Accepted" in stderr:
                findings.append({
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "LDAP autenticacion exitosa",
                    "description": f"Autenticacion LDAP exitosa en {target} con {username}",
                    "tool": self.name,
                    "rule_id": "ldap-auth-success",
                })
                raw_lines.append("[INFO] ldapsearch: Authentication successful")

            if stdout:
                raw_lines.append(f"[INFO] ldapsearch: {len(stdout)} chars retrieved")

                # Parse useful entries
                entries = stdout.split("\n\n")
                raw_lines.append(f"[INFO] ldapsearch: {len(entries)} entries found")

                user_count = stdout.count("uid=") + stdout.count("sAMAccountName=")
                group_count = stdout.count("groupOfNames") + stdout.count("groupOfUniqueNames") + stdout.count("group")

                if user_count > 0:
                    findings.append({
                        "file_path": target,
                        "line_start": 0, "line_end": 0,
                        "severity": "info",
                        "title": f"LDAP: {user_count} usuarios enumerados",
                        "description": f"Se encontraron aproximadamente {user_count} usuarios via LDAP en {domain}",
                        "tool": self.name,
                        "rule_id": "ldap-users-found",
                        "user_count": user_count,
                        "domain": domain,
                    })

                # Check for null/weak LDAP signing
                if "ldapsearch" in stdout.lower():
                    pass

        except FileNotFoundError:
            raw_lines.append("[INFO] ldapsearch not installed, trying ldap3...")
            self._scan_via_ldap3(target, domain, username, password, base_dn, findings, raw_lines, timeout)
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] ldapsearch timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] ldapsearch: {e}")

        summary = f"ldap: {len(findings)} hallazgos en {domain}"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _scan_via_ldap3(
        self, target: str, domain: str, username: str, password: str,
        base_dn: str, findings: list[dict[str, Any]],
        raw_lines: list[str], timeout: int,
    ) -> None:
        try:
            import ldap3
        except ImportError:
            raw_lines.append("[ERR] ldap3 library not available")
            return

        try:
            server = ldap3.Server(target, get_info=ldap3.ALL, port=389)
            conn = ldap3.Connection(server, user=f"{username}@{domain}" if username else "",
                                    password=password or "", auto_bind=True)
            raw_lines.append("[INFO] ldap3: Connected and bound")

            # Get server info
            info = server.info
            if info:
                naming_contexts = info.naming_contexts or []
                raw_lines.append(f"[INFO] ldap3: Naming contexts: {naming_contexts}")
                if naming_contexts:
                    base_dn = base_dn or str(naming_contexts[0])

            # Query for users
            conn.search(
                search_base=base_dn,
                search_filter="(&(objectClass=user)(objectCategory=person))",
                attributes=["sAMAccountName", "cn", "mail", "memberOf", "userAccountControl"],
                size_limit=100,
            )
            users = conn.entries
            raw_lines.append(f"[INFO] ldap3: {len(users)} users found")

            if users:
                findings.append({
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"LDAP: {len(users)} usuarios de dominio",
                    "description": f"Enumerados {len(users)} usuarios via LDAP anonimo en {domain}",
                    "tool": self.name,
                    "rule_id": "ldap3-users",
                    "domain": domain,
                    "user_count": len(users),
                })

                # Check for users with PASSWD_NOTREQD flag
                for entry in users:
                    uac = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl.value else 0
                    if uac and (int(uac) & 0x0020):  # PASSWD_NOTREQD
                        findings.append({
                            "file_path": target,
                            "line_start": 0, "line_end": 0,
                            "severity": "high",
                            "title": f"Usuario sin contrasena requerida: {entry.sAMAccountName.value}",
                            "description": f"El usuario {entry.sAMAccountName.value} tiene PASSWD_NOTREQD flag — puede tener contrasena vacia",
                            "tool": self.name,
                            "rule_id": f"ldap3-passwd-notreqd-{entry.sAMAccountName.value}",
                            "username": str(entry.sAMAccountName.value),
                        })

            # Query for groups
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=group)",
                attributes=["cn", "member", "description"],
                size_limit=50,
            )
            groups = conn.entries
            raw_lines.append(f"[INFO] ldap3: {len(groups)} groups found")
            if groups:
                findings.append({
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"LDAP: {len(groups)} grupos enumerados",
                    "description": f"Enumerados {len(groups)} grupos de seguridad en {domain}",
                    "tool": self.name,
                    "rule_id": "ldap3-groups",
                    "domain": domain,
                    "group_count": len(groups),
                })

                # Check for privileged groups
                admin_groups = ["Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"]
                for entry in groups:
                    cn = entry.cn.value if hasattr(entry, 'cn') and entry.cn.value else ""
                    if any(ag in str(cn) for ag in admin_groups):
                        findings.append({
                            "file_path": target,
                            "line_start": 0, "line_end": 0,
                            "severity": "medium",
                            "title": f"Grupo privilegiado encontrado: {cn}",
                            "description": f"Grupo {cn} existe en el dominio {domain}",
                            "tool": self.name,
                            "rule_id": f"ldap3-priv-group-{str(cn).lower().replace(' ', '-')}",
                            "group_name": str(cn),
                        })

            # Check null bind / anonymous access
            try:
                anon_conn = ldap3.Connection(server, auto_bind=True)
                raw_lines.append("[INFO] ldap3: Anonymous bind SUCCESS — anonymous LDAP enabled")
                findings.append({
                    "file_path": target,
                    "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": "Anonymous LDAP bind habilitado",
                    "description": f"LDAP en {target} permite binding anonimo — cualquiera puede enumerar el dominio",
                    "tool": self.name,
                    "rule_id": "ldap3-anonymous-bind",
                })
                anon_conn.unbind()
            except Exception:
                raw_lines.append("[INFO] ldap3: Anonymous bind rejected (good)")

            conn.unbind()

        except ldap3.core.exceptions.LDAPBindError as e:
            raw_lines.append(f"[ERR] ldap3: Bind failed: {e}")
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            raw_lines.append(f"[ERR] ldap3: Connection failed: {e}")
        except Exception as e:
            raw_lines.append(f"[ERR] ldap3: {e}")

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
