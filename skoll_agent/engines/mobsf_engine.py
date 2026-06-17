from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import zipfile
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


MOBSF_PATTERNS_LEAKS = [
    (r"(?i)aws[_\-\.]?key|AKIA[0-9A-Z]{16}", "AWS Key"),
    (r"(?i)googleapis\.com/api", "Google API key"),
    (r"(?i)api[_\-\.]?key\s*=\s*['\"][^'\"]+", "Hardcoded API key"),
    (r"(?i)secret[_\-\.]?(?:key|token)?\s*=\s*['\"][^'\"]+", "Hardcoded secret"),
    (r"(?i)password\s*=\s*['\"][^'\"]{4,}", "Hardcoded password"),
    (r"(?i)token\s*=\s*['\"][a-zA-Z0-9\-_\.]{10,}", "Hardcoded token"),
    (r"https?://[a-z0-9\-\.]+\.(?:com|io|app|net|org)/api/", "API endpoint URL"),
    (r"(?i)(?:mysql|postgres(?:ql)?|mongodb|redis)://\S+", "Database connection string"),
    (r"(?i)firebase\.(?:io|com)/[a-z0-9\-]+", "Firebase URL"),
    (r"[a-fA-F0-9]{64}", "Possible SHA-256 hash (key?)"),
]

INSECURE_STORAGE_PATTERNS = [
    (r"SharedPreferences", "Android SharedPreferences (insecure by default)"),
    (r"getSharedPreferences|getPreferences", "SharedPreferences usage"),
    (r"openFileOutput|MODE_PRIVATE", "File output (check mode)"),
    (r"SQLiteDatabase|openOrCreateDatabase", "SQLite database (may store unencrypted data)"),
    (r"getExternalStorage|getExternalFilesDir", "External storage (world-readable)"),
    (r"Environment\.getExternalStorage", "External storage access"),
    (r"KeyStore", "Android KeyStore (check if used properly)"),
    (r"UserDefaults\.(synchronize|setObject|setValue)", "iOS UserDefaults"),
    (r"NSCoding|NSKeyedArchiver", "iOS NSCoding (check if sensitive)"),
    (r"CoreData|NSManagedObject", "iOS CoreData"),
    (r"NSFileManager|writeToFile", "iOS file write"),
    (r"Realm\.(?:init|write|add|create)", "Realm database"),
]

SSL_PINNING_INDICATORS = [
    (r"CertificatePinner|CertificatePin", "OkHttp CertificatePinner"),
    (r"TrustManager|X509TrustManager", "Custom TrustManager (may disable SSL)"),
    (r"SSLSocketFactory|HttpsURLConnection", "SSL Socket factory"),
    (r"NSURLSession|URLSession:", "iOS URL session"),
    (r"NSURLProtectionSpace|serverTrust|challenge", "iOS SSL handling"),
    (r"allowBackup\s*=\s*\"true\"", "Android allowBackup=true (insecure)"),
    (r"network_security_config|networkSecurityConfig", "Android network security config"),
    (r"domain-config|domain-config\s+cleartextTrafficPermitted=\"true\"", "Cleartext traffic allowed"),
    (r"android:usesCleartextTraffic\s*=\s*\"true\"", "Cleartext traffic flag"),
    (r"NSAppTransportSecurity|NSAllowsArbitraryLoads", "iOS ATS bypass"),
]


class MobsfEngine(BaseEngine):
    name = "mobsf"
    description = "Mobile Security Framework (MobSF). Analisis estatico y dinamico de apps Android/iOS: APK/IPA upload, escaneo automatizado y extraccion de hallazgos."
    capabilities = ["mobile_security", "android", "ios", "static_analysis", "dynamic_analysis"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        apk_path = kwargs.get("apk", target)
        api_url = kwargs.get("api_url", "http://127.0.0.1:8000")
        api_key = kwargs.get("api_key", "")
        timeout = int(kwargs.get("timeout", 300))
        mode = kwargs.get("mode", "static")

        raw_lines.append(f"[INFO] MobSF mode={mode} target={apk_path[:80]}")

        if mode == "static":
            self._static_analysis(apk_path, api_url, api_key, findings, raw_lines, timeout)
        elif mode == "local":
            self._local_analysis(apk_path, findings, raw_lines)
        elif mode == "dynamic":
            raw_lines.append("[INFO] MobSF dynamic analysis requires interactive setup. Skipping.")
        else:
            raw_lines.append(f"[WARN] Modo no soportado: {mode}")

        summary = f"mobsf: {len(findings)} hallazgos en {apk_path.split('/')[-1]}"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _static_analysis(self, apk_path: str, api_url: str, api_key: str,
                         findings: list[dict[str, Any]],
                         raw_lines: list[str], timeout: int) -> None:
        if not os.path.exists(apk_path):
            raw_lines.append(f"[WARN] APK no encontrado: {apk_path}")
            return

        # Upload APK to MobSF
        try:
            with open(apk_path, "rb") as f:
                r = requests.post(
                    f"{api_url}/api/v1/upload",
                    files={"file": (os.path.basename(apk_path), f, "application/octet-stream")},
                    headers={"Authorization": api_key} if api_key else {},
                    timeout=timeout,
                )
            if r.status_code == 200:
                data = r.json()
                scan_hash = data.get("hash", data.get("scan_id", ""))
                raw_lines.append(f"[INFO] MobSF upload OK: hash={scan_hash}")

                # Start scan
                r2 = requests.post(
                    f"{api_url}/api/v1/scan",
                    data={"hash": scan_hash, "scan_type": "apk"},
                    headers={"Authorization": api_key} if api_key else {},
                    timeout=timeout,
                )
                if r2.status_code == 200:
                    scan_data = r2.json()
                    raw_lines.append("[INFO] MobSF scan complete")
                    self._parse_mobsf_results(scan_data, apk_path, findings, raw_lines)
                else:
                    raw_lines.append(f"[WARN] MobSF scan error: {r2.status_code}")
            elif r.status_code == 403:
                raw_lines.append("[WARN] MobSF API key required or invalid")
            else:
                raw_lines.append(f"[WARN] MobSF upload failed: {r.status_code}")
        except requests.exceptions.ConnectionError:
            raw_lines.append(f"[WARN] MobSF no disponible en {api_url}")
            raw_lines.append("[INFO] Fallback a analisis local...")
            self._local_analysis(apk_path, findings, raw_lines)
        except requests.exceptions.Timeout:
            raw_lines.append("[TIMEOUT] MobSF connection timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] MobSF: {e}")

    def _parse_mobsf_results(self, data: dict[str, Any], apk_path: str,
                             findings: list[dict[str, Any]],
                             raw_lines: list[str]) -> None:
        # Parse findings from MobSF JSON
        apk_name = os.path.basename(apk_path)

        # Code analysis findings
        for section_key in ("code_analysis", "malware_analysis", "trackers", "manifest_analysis"):
            section = data.get(section_key, {})
            if isinstance(section, dict):
                for finding_id, finding_data in section.items():
                    if isinstance(finding_data, dict):
                        sev_map = {"high": "high", "info": "info", "good": "info", "warning": "medium", "danger": "high"}
                        sev = sev_map.get(finding_data.get("level", "info").lower(), "medium")
                        title = finding_data.get("title", finding_data.get("name", finding_id))
                        desc = finding_data.get("description", finding_data.get("detail", ""))
                        if isinstance(desc, list):
                            desc = "; ".join(str(d) for d in desc[:3])
                        findings.append({
                            "file_path": f"{apk_path}:{section_key}", "line_start": 0, "line_end": 0,
                            "severity": sev,
                            "title": f"MobSF [{section_key}] {title}"[:150],
                            "description": str(desc)[:300],
                            "tool": self.name, "rule_id": f"mobsf-{section_key}-{finding_id[:30]}",
                            "mobsf_section": section_key, "finding_id": finding_id,
                        })
                        raw_lines.append(f"[{sev.upper()}] {section_key}: {title}")

        # Certificate analysis
        cert_info = data.get("certificate_analysis", {})
        if cert_info:
            for key, val in cert_info.items():
                if isinstance(val, str) and "vulnerable" in val.lower():
                    findings.append({
                        "file_path": apk_path, "line_start": 0, "line_end": 0,
                        "severity": "high",
                        "title": f"MobSF Certificate issue: {key}",
                        "description": str(val)[:300],
                        "tool": self.name, "rule_id": f"mobsf-cert-{key[:30]}",
                    })

        # Binary analysis
        binary = data.get("binary_analysis", {})
        if isinstance(binary, dict):
            for bid, binfo in binary.items():
                if isinstance(binfo, dict) and binfo.get("level", "") in ("danger", "warning"):
                    findings.append({
                        "file_path": apk_path, "line_start": 0, "line_end": 0,
                        "severity": "high" if binfo.get("level") == "danger" else "medium",
                        "title": f"MobSF Binary: {binfo.get('title', bid)}",
                        "description": str(binfo.get("description", ""))[:300],
                        "tool": self.name, "rule_id": f"mobsf-binary-{bid[:30]}",
                    })

        # Summary
        summary = data.get("summary", {})
        if isinstance(summary, dict):
            raw_lines.append(f"[INFO] MobSF total issues: {json.dumps(summary)}")

    def _local_analysis(self, apk_path: str, findings: list[dict[str, Any]],
                        raw_lines: list[str]) -> None:
        """Fallback: local analysis without MobSF server."""
        apk_name = os.path.basename(apk_path)
        raw_lines.append(f"[INFO] Local analysis of {apk_name}")

        if not zipfile.is_zipfile(apk_path):
            raw_lines.append("[WARN] Not a valid ZIP/APK file")
            return

        # Extract and scan key files
        try:
            with zipfile.ZipFile(apk_path) as z:
                names = z.namelist()

                # Parse AndroidManifest.xml
                if "AndroidManifest.xml" in names:
                    manifest_data = z.read("AndroidManifest.xml")
                    try:
                        manifest_text = manifest_data.decode("utf-8", errors="ignore")
                        self._scan_manifest(manifest_text, apk_path, findings, raw_lines)
                    except Exception:
                        raw_lines.append("[INFO] AndroidManifest.xml binary (needs aapt)")

                # Scan DEX files
                dex_files = [n for n in names if n.endswith(".dex") or n.endswith(".jar")]
                raw_lines.append(f"[INFO] DEX/JAR files: {len(dex_files)}")

                # Scan for API keys in all files
                sensitive_exts = (".xml", ".smali", ".json", ".properties", ".plist", ".strings")
                for name in names:
                    if any(name.endswith(ext) for ext in sensitive_exts):
                        try:
                            content = z.read(name).decode("utf-8", errors="ignore")
                            self._scan_content(content, name, apk_path, findings, raw_lines)
                        except Exception:
                            pass

                # Check for bundled libraries
                libs = [n for n in names if n.startswith("lib/")]
                raw_lines.append(f"[INFO] Native libraries: {len(libs)}")
                for lib in libs:
                    if any(x in lib.lower() for x in ["frida", "xposed", "root", "su", "substrate"]):
                        findings.append({
                            "file_path": f"{apk_path}!{lib}", "line_start": 0, "line_end": 0,
                            "severity": "info",
                            "title": f"Library: {lib.split('/')[-1]}",
                            "description": f"APK contains {lib} — may indicate rooting/jailbreak detection or instrumentation.",
                            "tool": self.name, "rule_id": f"mobsf-lib-{lib.split('/')[-1][:30]}",
                        })

                # Extract resources
                res_files = [n for n in names if n.startswith("res/") and n.endswith(".xml")]
                raw_lines.append(f"[INFO] Resource XML files: {len(res_files)}")

        except zipfile.BadZipFile:
            raw_lines.append("[ERR] Bad ZIP file")
        except Exception as e:
            raw_lines.append(f"[ERR] Local analysis: {e}")

    def _scan_manifest(self, manifest: str, apk_path: str,
                       findings: list[dict[str, Any]],
                       raw_lines: list[str]) -> None:
        # Check debuggable
        if 'android:debuggable="true"' in manifest:
            findings.append({
                "file_path": f"{apk_path}!AndroidManifest.xml", "line_start": 0, "line_end": 0,
                "severity": "high",
                "title": "APK debuggable",
                "description": "AndroidManifest has android:debuggable=true. APK can be debugged.",
                "tool": self.name, "rule_id": "mobsf-debuggable",
            })

        # Check allowBackup
        if 'android:allowBackup="true"' in manifest:
            findings.append({
                "file_path": f"{apk_path}!AndroidManifest.xml", "line_start": 0, "line_end": 0,
                "severity": "medium",
                "title": "APK allowBackup enabled",
                "description": "AndroidManifest has allowBackup=true. App data can be backed up via adb.",
                "tool": self.name, "rule_id": "mobsf-allowbackup",
            })

        # Check for exported activities
        exported = re.findall(r'android:exported="true"', manifest)
        if len(exported) > 3:
            findings.append({
                "file_path": f"{apk_path}!AndroidManifest.xml", "line_start": 0, "line_end": 0,
                "severity": "medium",
                "title": f"Multiple exported components: {len(exported)}",
                "description": f"AndroidManifest has {len(exported)} exported components. May expose IPC endpoints.",
                "tool": self.name, "rule_id": "mobsf-exported",
            })

        # Check permissions
        dangerous_perms = ["INTERNET", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
                           "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_SMS",
                           "RECEIVE_SMS", "READ_CONTACTS", "READ_CALL_LOG", "BIND_ACCESSIBILITY_SERVICE"]
        for perm in dangerous_perms:
            if f"android.permission.{perm}" in manifest:
                findings.append({
                    "file_path": f"{apk_path}!AndroidManifest.xml", "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"Permission: {perm}",
                    "description": f"APK requests {perm} permission.",
                    "tool": self.name, "rule_id": f"mobsf-perm-{perm.lower()}",
                })

    def _scan_content(self, content: str, name: str, apk_path: str,
                      findings: list[dict[str, Any]],
                      raw_lines: list[str]) -> None:
        # Pattern scanning for this file
        for pattern, desc in MOBSF_PATTERNS_LEAKS:
            matches = re.findall(pattern, content)
            for m in matches[:2]:
                masked = m[:10] + "..." + m[-4:] if len(m) > 14 else m
                findings.append({
                    "file_path": f"{apk_path}!{name}", "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Potential leak: {desc}",
                    "description": f"Found '{desc}' pattern in {name}: {masked}",
                    "tool": self.name, "rule_id": f"mobsf-leak-{name.split('/')[-1][:20]}-{desc[:10].lower().replace(' ','')}",
                    "pattern": desc, "file": name, "match": masked,
                })

        for pattern, desc in INSECURE_STORAGE_PATTERNS:
            if re.search(pattern, content):
                findings.append({
                    "file_path": f"{apk_path}!{name}", "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"Insecure storage indicator: {desc}",
                    "description": f"Pattern '{desc}' found in {name}",
                    "tool": self.name, "rule_id": f"mobsf-storage-{name.split('/')[-1][:20]}",
                    "pattern": desc, "file": name,
                })

        for pattern, desc in SSL_PINNING_INDICATORS:
            if re.search(pattern, content):
                findings.append({
                    "file_path": f"{apk_path}!{name}", "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"SSL/Network indicator: {desc}",
                    "description": f"Pattern '{desc}' found in {name} — review SSL implementation.",
                    "tool": self.name, "rule_id": f"mobsf-ssl-{name.split('/')[-1][:20]}",
                    "pattern": desc, "file": name,
                })

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
