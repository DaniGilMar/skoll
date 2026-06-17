from __future__ import annotations

import json
import os
import subprocess
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class IamEngine(BaseEngine):
    name = "iam"
    description = "Cloud IAM auditor. Audita configuraciones IAM en AWS, Azure y GCP: roles, politicas, usuarios, permisos y riesgos de escalacion de privilegios."
    capabilities = ["cloud_security", "iam", "aws", "azure", "gcp", "cloud_audit"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        provider = kwargs.get("provider", target.lower() if target.lower() in ("aws", "azure", "gcp") else "aws")
        profile = kwargs.get("profile", "default")
        timeout = int(kwargs.get("timeout", 120))

        raw_lines.append(f"[INFO] Auditan do IAM en {provider}")

        if provider == "aws":
            self._audit_aws(profile, findings, raw_lines, timeout)
        elif provider == "azure":
            self._audit_azure(findings, raw_lines, timeout)
        elif provider == "gcp":
            self._audit_gcp(findings, raw_lines, timeout)
        else:
            raw_lines.append(f"[WARN] Proveedor no soportado: {provider}")

        summary = f"iam: {len(findings)} hallazgos en {provider}"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _audit_aws(self, profile: str, findings: list[dict[str, Any]],
                   raw_lines: list[str], timeout: int) -> None:
        # 1. Check AWS CLI available
        if not self._check_cli("aws", raw_lines):
            return

        # 2. Get caller identity
        try:
            r = subprocess.run(
                ["aws", "sts", "get-caller-identity", "--profile", profile],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                identity = json.loads(r.stdout)
                raw_lines.append(f"[INFO] AWS Identity: {identity.get('Arn', 'N/A')}")
            else:
                raw_lines.append(f"[WARN] AWS CLI no configurado: {r.stderr[:200]}")
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "AWS CLI no configurado",
                    "description": "No se pudo autenticar con AWS CLI. Verificar credenciales.",
                    "tool": self.name, "rule_id": "aws-cli-not-configured",
                })
                return
        except FileNotFoundError:
            raw_lines.append("[WARN] AWS CLI no instalado")
            return
        except Exception as e:
            raw_lines.append(f"[ERR] AWS: {e}")
            return

        # 3. List IAM users
        try:
            r = subprocess.run(
                ["aws", "iam", "list-users", "--profile", profile],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                users = json.loads(r.stdout).get("Users", [])
                raw_lines.append(f"[INFO] IAM users: {len(users)}")

                for user in users:
                    uname = user.get("UserName", "?")
                    # Check if user has console password
                    try:
                        r2 = subprocess.run(
                            ["aws", "iam", "get-login-profile", "--user-name", uname, "--profile", profile],
                            capture_output=True, text=True, timeout=10,
                        )
                        if r2.returncode == 0:
                            findings.append({
                                "file_path": "", "line_start": 0, "line_end": 0,
                                "severity": "medium",
                                "title": f"AWS IAM user with console password: {uname}",
                                "description": f"User {uname} has AWS Management Console password enabled.",
                                "tool": self.name, "rule_id": f"aws-iam-console-{uname.lower()}",
                                "provider": "aws", "user": uname,
                            })
                    except Exception:
                        pass

                    # Check attached policies
                    try:
                        r3 = subprocess.run(
                            ["aws", "iam", "list-attached-user-policies", "--user-name", uname, "--profile", profile],
                            capture_output=True, text=True, timeout=10,
                        )
                        if r3.returncode == 0:
                            policies = json.loads(r3.stdout).get("AttachedPolicies", [])
                            for pol in policies:
                                pname = pol.get("PolicyName", "")
                                if "Admin" in pname or "FullAccess" in pname or "PowerUser" in pname:
                                    findings.append({
                                        "file_path": "", "line_start": 0, "line_end": 0,
                                        "severity": "high",
                                        "title": f"AWS IAM user with high privileges: {uname} -> {pname}",
                                        "description": f"User {uname} has policy {pname} attached — may have excessive privileges.",
                                        "tool": self.name,
                                        "rule_id": f"aws-iam-overprivileged-{uname.lower()}-{pname.lower().replace(' ','')[:20]}",
                                        "provider": "aws", "user": uname, "policy": pname,
                                    })
                    except Exception:
                        pass
            else:
                raw_lines.append(f"[WARN] AWS IAM list-users failed: {r.stderr[:200]}")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] AWS IAM list-users timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] AWS IAM: {e}")

        # 4. Check for root access keys
        try:
            r = subprocess.run(
                ["aws", "iam", "get-account-summary", "--profile", profile],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                summary = json.loads(r.stdout).get("SummaryMap", {})
                root_keys = summary.get("AccountAccessKeysPresent", 0)
                root_mfa = summary.get("AccountMFAEnabled", 0)
                if root_keys:
                    findings.append({
                        "file_path": "", "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": "AWS root account has access keys",
                        "description": f"Root account has {root_keys} access key(s). AWS best practice: use IAM users instead.",
                        "tool": self.name, "rule_id": "aws-root-keys",
                    })
                if not root_mfa:
                    findings.append({
                        "file_path": "", "line_start": 0, "line_end": 0,
                        "severity": "high",
                        "title": "AWS root account MFA not enabled",
                        "description": "Root account does not have MFA enabled.",
                        "tool": self.name, "rule_id": "aws-root-no-mfa",
                    })
        except Exception:
            pass

        # 5. Check for public S3 buckets via IAM
        try:
            r = subprocess.run(
                ["aws", "s3api", "list-buckets", "--profile", profile],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                buckets = json.loads(r.stdout).get("Buckets", [])
                raw_lines.append(f"[INFO] S3 buckets: {len(buckets)}")
                for b in buckets:
                    bname = b.get("Name", "")
                    try:
                        r2 = subprocess.run(
                            ["aws", "s3api", "get-bucket-acl", "--bucket", bname, "--profile", profile],
                            capture_output=True, text=True, timeout=10,
                        )
                        if r2.returncode == 0:
                            acl = json.loads(r2.stdout).get("Grants", [])
                            for grant in acl:
                                uri = grant.get("Grantee", {}).get("URI", "")
                                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                                    findings.append({
                                        "file_path": "", "line_start": 0, "line_end": 0,
                                        "severity": "critical",
                                        "title": f"S3 bucket publicly accessible: {bname}",
                                        "description": f"Bucket {bname} has public ACL grants ({uri}). Data may be exposed.",
                                        "tool": self.name, "rule_id": f"aws-s3-public-{bname.lower()}",
                                        "provider": "aws", "bucket": bname,
                                    })
                    except Exception:
                        pass
        except Exception:
            pass

    def _audit_azure(self, findings: list[dict[str, Any]],
                     raw_lines: list[str], timeout: int) -> None:
        if not self._check_cli("az", raw_lines):
            return

        try:
            r = subprocess.run(
                ["az", "account", "show"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                account = json.loads(r.stdout)
                raw_lines.append(f"[INFO] Azure account: {account.get('name', 'N/A')}")

                # Check for RBAC roles
                r2 = subprocess.run(
                    ["az", "role", "assignment", "list", "--all"],
                    capture_output=True, text=True, timeout=timeout,
                )
                if r2.returncode == 0:
                    roles = json.loads(r2.stdout)
                    raw_lines.append(f"[INFO] Azure role assignments: {len(roles)}")
                    for role in roles:
                        rname = role.get("roleDefinitionName", "")
                        scope = role.get("scope", "")
                        principal = role.get("principalName", "")
                        if "Owner" in rname or "Contributor" in rname:
                            findings.append({
                                "file_path": "", "line_start": 0, "line_end": 0,
                                "severity": "high",
                                "title": f"Azure high-privilege role: {rname} for {principal}",
                                "description": f"Principal {principal} has role {rname} at scope {scope}.",
                                "tool": self.name,
                                "rule_id": f"azure-priv-{rname.lower().replace(' ','-')}-{principal.lower()}",
                                "provider": "azure", "principal": principal, "role": rname,
                            })
            else:
                raw_lines.append(f"[WARN] Azure CLI not logged in")
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "info", "title": "Azure CLI not logged in",
                    "description": "az account show failed. Run az login first.",
                    "tool": self.name, "rule_id": "azure-not-logged-in",
                })
        except FileNotFoundError:
            raw_lines.append("[WARN] Azure CLI no instalado")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] Azure timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] Azure: {e}")

    def _audit_gcp(self, findings: list[dict[str, Any]],
                   raw_lines: list[str], timeout: int) -> None:
        if not self._check_cli("gcloud", raw_lines):
            return

        try:
            r = subprocess.run(
                ["gcloud", "auth", "list"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                raw_lines.append(f"[INFO] GCP authenticated accounts found")
            else:
                raw_lines.append("[WARN] GCloud not authenticated")
                findings.append({
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "info", "title": "GCP not authenticated",
                    "description": "gcloud auth list failed. Run gcloud auth login first.",
                    "tool": self.name, "rule_id": "gcp-not-authenticated",
                })
                return
        except FileNotFoundError:
            raw_lines.append("[WARN] GCloud CLI no instalado")
            return
        except Exception as e:
            raw_lines.append(f"[ERR] GCP: {e}")
            return

        try:
            # List projects
            r = subprocess.run(
                ["gcloud", "projects", "list", "--format=json"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                projects = json.loads(r.stdout)
                raw_lines.append(f"[INFO] GCP projects: {len(projects)}")

                for proj in projects[:5]:
                    pid = proj.get("projectId", "")
                    # Check IAM policy
                    r2 = subprocess.run(
                        ["gcloud", "projects", "get-iam-policy", pid, "--format=json"],
                        capture_output=True, text=True, timeout=30,
                    )
                    if r2.returncode == 0:
                        policy = json.loads(r2.stdout)
                        bindings = policy.get("bindings", [])
                        for binding in bindings:
                            role = binding.get("role", "")
                            members = binding.get("members", [])
                            if "allUsers" in members or "allAuthenticatedUsers" in members:
                                findings.append({
                                    "file_path": "", "line_start": 0, "line_end": 0,
                                    "severity": "critical",
                                    "title": f"GCP IAM public access in {pid}: {role}",
                                    "description": f"Role {role} in project {pid} is granted to allUsers/allAuthenticatedUsers.",
                                    "tool": self.name,
                                    "rule_id": f"gcp-public-{pid}-{role.lower().replace('/','-')[:30]}",
                                    "provider": "gcp", "project": pid, "role": role,
                                })
                            if role in ("roles/owner", "roles/editor") and members:
                                findings.append({
                                    "file_path": "", "line_start": 0, "line_end": 0,
                                    "severity": "high",
                                    "title": f"GCP high-privilege role in {pid}: {role}",
                                    "description": f"Role {role} in project {pid} has {len(members)} member(s).",
                                    "tool": self.name,
                                    "rule_id": f"gcp-priv-{pid}-{role.lower().replace('/','-')[:30]}",
                                    "provider": "gcp", "project": pid, "role": role,
                                })
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] GCP timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] GCP: {e}")

    def _check_cli(self, tool: str, raw_lines: list[str]) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            return True
        except FileNotFoundError:
            raw_lines.append(f"[WARN] {tool} CLI no instalado")
            return False
        except Exception:
            return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
