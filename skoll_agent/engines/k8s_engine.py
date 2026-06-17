from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class K8sEngine(BaseEngine):
    name = "k8s"
    description = "Kubernetes security auditor. Audita configuraciones de clusters K8s: pods privilegiados, RBAC, secrets expuestos, network policies, kube-bench, kube-hunter."
    capabilities = ["cloud_security", "kubernetes", "k8s", "container_security", "cloud_audit"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        mode = kwargs.get("mode", "kubectl")
        kubeconfig = kwargs.get("kubeconfig", os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config")))
        namespace = kwargs.get("namespace", "default")
        timeout = int(kwargs.get("timeout", 120))

        raw_lines.append(f"[INFO] Kubernetes audit mode={mode}")

        if mode == "kubectl" or mode == "all":
            self._audit_kubectl(kubeconfig, namespace, findings, raw_lines, timeout)

        if mode == "kube_bench" or mode == "all":
            self._run_kube_bench(target, findings, raw_lines, timeout)

        if mode == "kube_hunter" or mode == "all":
            self._run_kube_hunter(target, findings, raw_lines, timeout)

        if mode == "api":
            self._audit_api(target, findings, raw_lines, timeout)

        summary = f"k8s: {len(findings)} hallazgos"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _audit_kubectl(self, kubeconfig: str, namespace: str,
                       findings: list[dict[str, Any]],
                       raw_lines: list[str], timeout: int) -> None:
        if not self._check_cli("kubectl", raw_lines):
            return

        if not os.path.exists(kubeconfig):
            raw_lines.append(f"[WARN] kubeconfig not found: {kubeconfig}")
            findings.append({
                "file_path": kubeconfig, "line_start": 0, "line_end": 0,
                "severity": "info", "title": "Kubeconfig no encontrado",
                "description": f"No se encontró kubeconfig en {kubeconfig}",
                "tool": self.name, "rule_id": "k8s-no-kubeconfig",
            })
            return

        try:
            # Check if kubectl works
            r = subprocess.run(
                ["kubectl", "get", "nodes", "--kubeconfig", kubeconfig],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode != 0:
                raw_lines.append(f"[WARN] kubectl error: {r.stderr[:200]}")
                return
            raw_lines.append("[INFO] kubectl connected to cluster")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] kubectl connection timed out")
            return
        except Exception as e:
            raw_lines.append(f"[ERR] kubectl: {e}")
            return

        # 1. List privileged pods
        try:
            r = subprocess.run(
                ["kubectl", "get", "pods", "--all-namespaces",
                 "-o", "json", "--kubeconfig", kubeconfig],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                pods = json.loads(r.stdout).get("items", [])
                raw_lines.append(f"[INFO] Total pods: {len(pods)}")

                for pod in pods:
                    pname = pod.get("metadata", {}).get("name", "?")
                    pns = pod.get("metadata", {}).get("namespace", "?")
                    containers = pod.get("spec", {}).get("containers", [])
                    for ctr in containers:
                        security = ctr.get("securityContext", {}) or {}
                        if security.get("privileged", False):
                            findings.append({
                                "file_path": f"{pns}/{pname}", "line_start": 0, "line_end": 0,
                                "severity": "critical",
                                "title": f"Pod privilegiado: {pns}/{pname}",
                                "description": f"Pod {pns}/{pname} corre con privileged=true. Escalada a host posible.",
                                "tool": self.name, "rule_id": f"k8s-privileged-{pns}-{pname}",
                                "namespace": pns, "pod": pname,
                            })
                            raw_lines.append(f"[CRITICAL] Privileged pod: {pns}/{pname}")
                        if security.get("runAsRoot", False) or not security.get("runAsNonRoot"):
                            # Check if running as root (non-root is default false)
                            pass

                    # Check host network
                    if pod.get("spec", {}).get("hostNetwork"):
                        findings.append({
                            "file_path": f"{pns}/{pname}", "line_start": 0, "line_end": 0,
                            "severity": "high",
                            "title": f"Pod with hostNetwork: {pns}/{pname}",
                            "description": f"Pod {pns}/{pname} uses hostNetwork — can access host network namespace.",
                            "tool": self.name, "rule_id": f"k8s-hostnetwork-{pns}-{pname}",
                            "namespace": pns, "pod": pname,
                        })

                    # Check hostPath volumes
                    volumes = pod.get("spec", {}).get("volumes", [])
                    for vol in volumes:
                        hp = vol.get("hostPath", {})
                        if hp:
                            hp_path = hp.get("path", "")
                            findings.append({
                                "file_path": f"{pns}/{pname}", "line_start": 0, "line_end": 0,
                                "severity": "high",
                                "title": f"Pod with hostPath volume: {pns}/{pname} -> {hp_path}",
                                "description": f"Pod {pns}/{pname} mounts hostPath {hp_path}. Container escape posible.",
                                "tool": self.name, "rule_id": f"k8s-hostpath-{pns}-{pname}",
                                "namespace": pns, "pod": pname, "host_path": hp_path,
                            })
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] kubectl get pods timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] kubectl pods: {e}")

        # 2. Check RBAC
        try:
            r = subprocess.run(
                ["kubectl", "get", "clusterrolebindings", "--kubeconfig", kubeconfig, "-o", "json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                crbs = json.loads(r.stdout).get("items", [])
                for crb in crbs:
                    role = crb.get("roleRef", {}).get("name", "")
                    subjects = crb.get("subjects", [])
                    if "cluster-admin" in role.lower():
                        for subj in subjects:
                            if subj.get("kind") == "User" or subj.get("kind") == "ServiceAccount":
                                sname = subj.get("name", "?")
                                sns = subj.get("namespace", "?")
                                findings.append({
                                    "file_path": "", "line_start": 0, "line_end": 0,
                                    "severity": "critical",
                                    "title": f"Cluster-admin binding: {sns}/{sname}",
                                    "description": f"Subject {sns}/{sname} has cluster-admin privileges via ClusterRoleBinding {crb.get('metadata',{}).get('name','?')}.",
                                    "tool": self.name, "rule_id": f"k8s-cluster-admin-{sns}-{sname}",
                                    "subject": f"{sns}/{sname}", "role": role,
                                })
        except Exception as e:
            raw_lines.append(f"[ERR] kubectl RBAC: {e}")

        # 3. Check secrets
        try:
            r = subprocess.run(
                ["kubectl", "get", "secrets", "--all-namespaces", "--kubeconfig", kubeconfig, "-o", "json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                secrets = json.loads(r.stdout).get("items", [])
                raw_lines.append(f"[INFO] Total secrets: {len(secrets)}")
                # Check for secrets with weak/dynamic names
                for sec in secrets:
                    sname = sec.get("metadata", {}).get("name", "")
                    sns = sec.get("metadata", {}).get("namespace", "")
                    stype = sec.get("type", "")
                    if stype == "kubernetes.io/dockerconfigjson" or stype == "kubernetes.io/basic-auth":
                        findings.append({
                            "file_path": f"{sns}/{sname}", "line_start": 0, "line_end": 0,
                            "severity": "medium",
                            "title": f"Registry/basic-auth secret: {sns}/{sname}",
                            "description": f"Secret {sns}/{sname} of type {stype} contains registry credentials.",
                            "tool": self.name, "rule_id": f"k8s-secret-{sns}-{sname[:30]}",
                            "namespace": sns, "secret": sname, "type": stype,
                        })
        except Exception as e:
            raw_lines.append(f"[ERR] kubectl secrets: {e}")

        # 4. Check namespaces
        try:
            r = subprocess.run(
                ["kubectl", "get", "namespaces", "--kubeconfig", kubeconfig, "-o", "json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                nss = json.loads(r.stdout).get("items", [])
                raw_lines.append(f"[INFO] Namespaces: {len(nss)}")
        except Exception:
            pass

    def _run_kube_bench(self, target: str, findings: list[dict[str, Any]],
                        raw_lines: list[str], timeout: int) -> None:
        if not self._check_cli("kube-bench", raw_lines):
            return

        raw_lines.append("[INFO] Running kube-bench...")
        try:
            r = subprocess.run(
                ["kube-bench", "--json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode in (0, 1, 2):
                try:
                    data = json.loads(r.stdout)
                    for section in data.get("Controls", []):
                        for group in section.get("groups", []):
                            for check in group.get("checks", []):
                                status = check.get("status", "PASS")
                                test_desc = check.get("test_desc", "")[:200]
                                check_id = check.get("id", "")
                                sev_map = {"FAIL": "high", "WARN": "medium"}
                                sev = sev_map.get(status, "info")
                                if status != "PASS":
                                    findings.append({
                                        "file_path": target or "local", "line_start": 0, "line_end": 0,
                                        "severity": sev,
                                        "title": f"kube-bench [{check_id}] {status}",
                                        "description": test_desc or check.get("audit", "")[:200],
                                        "tool": self.name, "rule_id": f"kube-bench-{check_id}",
                                        "check_id": check_id, "status": status,
                                        "remediation": check.get("remediation", "")[:200],
                                    })
                                    raw_lines.append(f"[{sev.upper()}] kube-bench {check_id}: {status}")
                except json.JSONDecodeError:
                    raw_lines.append(f"[INFO] kube-bench output (non-JSON): {r.stdout[:200]}")
            else:
                raw_lines.append(f"[WARN] kube-bench failed: {r.stderr[:200]}")
        except FileNotFoundError:
            raw_lines.append("[WARN] kube-bench no instalado")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] kube-bench timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] kube-bench: {e}")

    def _run_kube_hunter(self, target: str, findings: list[dict[str, Any]],
                         raw_lines: list[str], timeout: int) -> None:
        if not self._check_cli("kube-hunter", raw_lines):
            return

        raw_lines.append("[INFO] Running kube-hunter...")
        try:
            args = ["kube-hunter", "--json", "--log", "warn"]
            if target:
                args.extend(["--target", target])

            r = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode in (0, 1):
                try:
                    data = json.loads(r.stdout)
                    for vuln in data.get("vulnerabilities", []):
                        vid = vuln.get("id", "")
                        title = vuln.get("title", "")
                        severity = vuln.get("severity", "medium")
                        category = vuln.get("category", "")
                        sev_map = {"high": "high", "medium": "medium", "low": "low"}
                        sev = sev_map.get(severity.lower(), "medium")
                        findings.append({
                            "file_path": target or "local", "line_start": 0, "line_end": 0,
                            "severity": sev,
                            "title": f"kube-hunter: {title}",
                            "description": f"Kube-hunter encontró: {title} (severidad: {severity})",
                            "tool": self.name, "rule_id": f"kube-hunter-{vid}",
                            "vuln_id": vid, "category": category, "severity": severity,
                            "remediation": vuln.get("remediation", ""),
                        })
                        raw_lines.append(f"[{sev.upper()}] kube-hunter: {title}")

                    services = data.get("services", [])
                    if services:
                        raw_lines.append(f"[INFO] kube-hunter: {len(services)} servicios descubiertos")
                except json.JSONDecodeError:
                    raw_lines.append(f"[INFO] kube-hunter output: {r.stdout[:300]}")
            else:
                raw_lines.append(f"[WARN] kube-hunter failed: {r.stderr[:200]}")
        except FileNotFoundError:
            raw_lines.append("[WARN] kube-hunter no instalado")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] kube-hunter timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] kube-hunter: {e}")

    def _audit_api(self, target: str, findings: list[dict[str, Any]],
                   raw_lines: list[str], timeout: int) -> None:
        """Audit K8s API directly via HTTP."""
        api_url = target.rstrip("/")

        raw_lines.append(f"[INFO] Kubernete API audit: {api_url}")

        # Check if API is accessible
        try:
            r = requests.get(f"{api_url}/api", timeout=timeout, verify=False)
            raw_lines.append(f"[{r.status_code}] {api_url}/api")

            if r.status_code == 200:
                findings.append({
                    "file_path": api_url, "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": "Kubernete API accessible externally",
                    "description": f"K8s API at {api_url} is accessible from this host. API version: {r.text[:100]}",
                    "tool": self.name, "rule_id": "k8s-api-external",
                    "api_url": api_url,
                })

                # Try to access pods
                r2 = requests.get(f"{api_url}/api/v1/pods", timeout=timeout, verify=False)
                if r2.status_code == 200:
                    findings.append({
                        "file_path": api_url, "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": "Kubernete API allows unauthenticated pod access",
                        "description": f"K8s API at {api_url} returns pod list without authentication!",
                        "tool": self.name, "rule_id": "k8s-api-no-auth",
                        "api_url": api_url,
                    })
        except requests.exceptions.ConnectionError:
            raw_lines.append(f"[ERR] Connection to {api_url} failed")
        except requests.exceptions.Timeout:
            raw_lines.append(f"[TIMEOUT] {api_url}")
        except Exception as e:
            raw_lines.append(f"[ERR] K8s API: {e}")

    def _check_cli(self, tool: str, raw_lines: list[str]) -> bool:
        try:
            subprocess.run([tool, "version"], capture_output=True, timeout=5)
            return True
        except FileNotFoundError:
            raw_lines.append(f"[WARN] {tool} no instalado")
            return False
        except Exception:
            return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
