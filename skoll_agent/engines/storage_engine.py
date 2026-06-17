from __future__ import annotations

import json
import re
import subprocess
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class StorageEngine(BaseEngine):
    name = "storage"
    description = "Cloud storage exposure auditor. Detecta buckets S3, Azure Blob y GCP Storage expuestos publicamente, listado de objetos y configuracion insegura."
    capabilities = ["cloud_security", "storage", "aws", "azure", "gcp", "cloud_audit"]

    COMMON_BUCKET_NAMES = [
        "assets", "backup", "backups", "bucket", "build", "cdn", "config",
        "data", "db", "database", "dev", "downloads", "files", "images",
        "logs", "media", "production", "public", "releases", "resources",
        "screenshots", "secrets", "security", "source", "src", "static",
        "storage", "staging", "system", "test", "tmp", "uploads", "www",
    ]

    AWS_BUCKET_URL = "https://{bucket}.s3.amazonaws.com"
    AWS_BUCKET_URL_REGION = "https://{bucket}.s3.{region}.amazonaws.com"
    GCP_BUCKET_URL = "https://storage.googleapis.com/{bucket}"
    AZURE_BLOB_URL = "https://{account}.blob.core.windows.net/{container}"

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        provider = kwargs.get("provider", "aws")
        bucket = kwargs.get("bucket", target)
        domain = kwargs.get("domain", target if not kwargs.get("bucket") else "")
        timeout = int(kwargs.get("timeout", 30))

        raw_lines.append(f"[INFO] Auditando almacenamiento en {provider}")

        if provider == "aws":
            self._check_s3(bucket, domain, findings, raw_lines, timeout)
        elif provider == "azure":
            self._check_azure_blob(bucket, findings, raw_lines, timeout)
        elif provider == "gcp":
            self._check_gcp_storage(bucket, findings, raw_lines, timeout)
        elif provider == "enum":
            self._enumerate_buckets(domain, findings, raw_lines, timeout)
        else:
            raw_lines.append(f"[WARN] Proveedor no soportado: {provider}")

        summary = f"storage: {len(findings)} hallazgos en {provider}"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _check_s3(self, bucket: str, domain: str,
                  findings: list[dict[str, Any]],
                  raw_lines: list[str], timeout: int) -> None:
        targets = [bucket] if bucket else []
        if domain:
            targets.extend([
                domain,
                f"{domain.split('.')[0]}-assets",
                f"{domain.split('.')[0]}-backup",
                f"{domain.split('.')[0]}-backups",
                f"{domain.split('.')[0]}-data",
                f"{domain.split('.')[0]}-files",
                f"{domain.split('.')[0]}-uploads",
                f"{domain.split('.')[0]}-static",
                f"{domain.split('.')[0]}-public",
                f"{domain.split('.')[0]}-media",
            ])
        if not targets:
            targets = self.COMMON_BUCKET_NAMES

        for bname in targets:
            url = self.AWS_BUCKET_URL.format(bucket=bname)
            try:
                r = requests.get(url, timeout=timeout, verify=False)
                raw_lines.append(f"[{r.status_code}] {url}")

                if r.status_code == 200:
                    # Check if listing is enabled
                    body = r.text
                    is_listable = "<ListBucketResult" in body or ("/>" in body and "Contents" in body)
                    if is_listable:
                        # Extract object names
                        objects = re.findall(r"<Key>(.*?)</Key>", body)
                        raw_lines.append(f"[CRITICAL] S3 bucket {bname} is PUBLICLY LISTABLE! {len(objects)} objects")
                        findings.append({
                            "file_path": url, "line_start": 0, "line_end": 0,
                            "severity": "critical",
                            "title": f"S3 bucket publicly listable: {bname}",
                            "description": f"Bucket {bname} allows anonymous listing with {len(objects)} objects visible.",
                            "tool": self.name, "rule_id": f"s3-listable-{bname.lower()}",
                            "provider": "aws", "bucket": bname, "url": url,
                            "objects_count": len(objects),
                        })
                        # Check for sensitive files
                        sensitive = [o for o in objects if any(kw in o.lower() for kw in
                                     ["password", "secret", "key", "token", "credential", "config", "env", "db", "backup", "sql", "pem", "ppk", "htpasswd"])]
                        if sensitive:
                            findings.append({
                                "file_path": url, "line_start": 0, "line_end": 0,
                                "severity": "critical",
                                "title": f"Sensitive files in public S3 bucket: {bname}",
                                "description": f"Found {len(sensitive)} potentially sensitive files: {', '.join(sensitive[:10])}",
                                "tool": self.name, "rule_id": f"s3-sensitive-{bname.lower()}",
                                "provider": "aws", "bucket": bname, "sensitive_files": sensitive[:20],
                            })
                    else:
                        raw_lines.append(f"[INFO] S3 bucket {bname} accessible but not listable")
                        findings.append({
                            "file_path": url, "line_start": 0, "line_end": 0,
                            "severity": "high",
                            "title": f"S3 bucket publicly accessible: {bname}",
                            "description": f"Bucket {bname} returns HTTP 200 — objects may be accessible by guessing URLs.",
                            "tool": self.name, "rule_id": f"s3-accessible-{bname.lower()}",
                            "provider": "aws", "bucket": bname, "url": url,
                        })
                elif r.status_code == 403:
                    raw_lines.append(f"[INFO] S3 bucket {bname}: Access Denied (good)")
                elif r.status_code == 404:
                    raw_lines.append(f"[INFO] S3 bucket {bname}: Not Found")

                # Check bucket policy via AWS CLI if available
                if r.status_code in (200, 403):
                    self._check_s3_cli(bname, findings, raw_lines, timeout)

            except requests.exceptions.ConnectionError:
                raw_lines.append(f"[ERR] Connection error: {url}")
            except requests.exceptions.Timeout:
                raw_lines.append(f"[TIMEOUT] {url}")
            except Exception as e:
                raw_lines.append(f"[ERR] {url}: {e}")

    def _check_s3_cli(self, bucket: str, findings: list[dict[str, Any]],
                      raw_lines: list[str], timeout: int) -> None:
        try:
            r = subprocess.run(
                ["aws", "s3api", "get-bucket-acl", "--bucket", bucket],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                acl = json.loads(r.stdout)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    perm = grant.get("Permission", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        raw_lines.append(f"[WARN] S3 ACL: {bucket} -> {uri} ({perm})")
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        except Exception:
            pass

    def _check_gcp_storage(self, bucket: str,
                           findings: list[dict[str, Any]],
                           raw_lines: list[str], timeout: int) -> None:
        url = self.GCP_BUCKET_URL.format(bucket=bucket)
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            raw_lines.append(f"[{r.status_code}] {url}")

            if r.status_code == 200:
                body = r.text
                is_listable = "<Contents>" in body or "xmlns" in body
                if is_listable:
                    objects = re.findall(r"<Key>(.*?)</Key>", body)
                    raw_lines.append(f"[CRITICAL] GCP bucket {bucket} is PUBLICLY LISTABLE! {len(objects)} objects")
                    findings.append({
                        "file_path": url, "line_start": 0, "line_end": 0,
                        "severity": "critical",
                        "title": f"GCP Storage bucket publicly listable: {bucket}",
                        "description": f"Bucket {bucket} allows anonymous listing with {len(objects)} objects visible.",
                        "tool": self.name, "rule_id": f"gcp-listable-{bucket.lower()}",
                        "provider": "gcp", "bucket": bucket, "url": url,
                    })
                else:
                    findings.append({
                        "file_path": url, "line_start": 0, "line_end": 0,
                        "severity": "high",
                        "title": f"GCP Storage bucket publicly accessible: {bucket}",
                        "description": f"GCP bucket {bucket} returns HTTP 200 — objects may be accessible.",
                        "tool": self.name, "rule_id": f"gcp-accessible-{bucket.lower()}",
                        "provider": "gcp", "bucket": bucket,
                    })
            elif r.status_code == 403:
                raw_lines.append(f"[INFO] GCP bucket {bucket}: Access Denied")
        except Exception as e:
            raw_lines.append(f"[ERR] GCP: {e}")

        # Also check with gsutil if available
        try:
            r2 = subprocess.run(
                ["gsutil", "ls", f"gs://{bucket}"],
                capture_output=True, text=True, timeout=timeout,
            )
            if r2.returncode == 0 and r2.stdout.strip():
                objects = r2.stdout.strip().split("\n")
                raw_lines.append(f"[CRITICAL] gsutil: GCP bucket {bucket} listable! {len(objects)} objects")
                findings.append({
                    "file_path": f"gs://{bucket}", "line_start": 0, "line_end": 0,
                    "severity": "critical",
                    "title": f"GCP Storage bucket listable via gsutil: {bucket}",
                    "description": f"Anonymous gsutil ls on gs://{bucket} returned {len(objects)} objects.",
                    "tool": self.name, "rule_id": f"gcp-gsutil-{bucket.lower()}",
                    "provider": "gcp", "bucket": bucket,
                })
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _check_azure_blob(self, container: str,
                          findings: list[dict[str, Any]],
                          raw_lines: list[str], timeout: int) -> None:
        if not container or "@" not in container:
            raw_lines.append("[WARN] Azure Blob requiere formato: account@container")
            return

        account, container_name = container.split("@", 1)
        url = f"https://{account}.blob.core.windows.net/{container_name}"
        url_list = f"{url}?restype=container&comp=list"

        try:
            r = requests.get(url_list, timeout=timeout, verify=False)
            raw_lines.append(f"[{r.status_code}] {url}")

            if r.status_code == 200:
                blobs = re.findall(r"<Name>(.*?)</Name>", r.text)
                raw_lines.append(f"[CRITICAL] Azure Blob {container_name} is PUBLICLY LISTABLE! {len(blobs)} blobs")
                findings.append({
                    "file_path": url, "line_start": 0, "line_end": 0,
                    "severity": "critical",
                    "title": f"Azure Blob container publicly listable: {container}",
                    "description": f"Container {container_name} in account {account} allows anonymous listing.",
                    "tool": self.name, "rule_id": f"azure-listable-{container.lower().replace('@','-')}",
                    "provider": "azure", "container": container, "url": url,
                })
            elif r.status_code == 403:
                raw_lines.append(f"[INFO] Azure Blob {container}: Access Denied")
            elif r.status_code == 404:
                raw_lines.append(f"[INFO] Azure Blob {container}: Not Found")
        except Exception as e:
            raw_lines.append(f"[ERR] Azure: {e}")

    def _enumerate_buckets(self, domain: str, findings: list[dict[str, Any]],
                           raw_lines: list[str], timeout: int) -> None:
        if not domain:
            raw_lines.append("[WARN] Enumeration requires a domain")
            return

        domain_prefix = domain.split(".")[0]
        candidates = set()

        # Generate candidate names from domain
        candidates.add(domain)
        candidates.add(f"{domain_prefix}-backup")
        candidates.add(f"{domain_prefix}-backups")
        candidates.add(f"{domain_prefix}-assets")
        candidates.add(f"{domain_prefix}-static")
        candidates.add(f"{domain_prefix}-media")
        candidates.add(f"{domain_prefix}-uploads")
        candidates.add(f"{domain_prefix}-public")
        candidates.add(f"{domain_prefix}-data")
        candidates.add(f"{domain_prefix}-files")
        candidates.add(f"{domain_prefix}-config")
        candidates.add(f"{domain_prefix}-secrets")
        candidates.add(f"{domain_prefix}-db")
        candidates.add(f"{domain_prefix}-storage")
        candidates.add(f"{domain_prefix}-backup-data")
        candidates.add(f"{domain_prefix}-www")

        raw_lines.append(f"[INFO] Enumerating {len(candidates)} bucket candidates for {domain}...")

        for name in candidates:
            for provider_url in [self.AWS_BUCKET_URL.format(bucket=name)]:
                try:
                    r = requests.get(provider_url, timeout=timeout, verify=False)
                    if r.status_code == 200:
                        raw_lines.append(f"[FOUND] {provider_url} (HTTP {r.status_code})")
                        findings.append({
                            "file_path": provider_url, "line_start": 0, "line_end": 0,
                            "severity": "high",
                            "title": f"Potential S3 bucket: {name}",
                            "description": f"Bucket candidate {name} exists at {provider_url}",
                            "tool": self.name, "rule_id": f"s3-enum-{name.lower()}",
                            "provider": "aws", "bucket": name, "url": provider_url,
                        })
                except Exception:
                    pass

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
