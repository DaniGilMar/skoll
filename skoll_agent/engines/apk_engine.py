from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import zipfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


APK_LEAK_PATTERNS = [
    (r"https?://[a-z0-9.\-]+\.(com|io|org|net|app|dev|co)/api/", "API endpoint URL"),
    (r"(?i)(?:aws|amazon)[_\-\.]?(?:key|secret|access)[_\-\.]?[a-zA-Z0-9=: '\"]{10,}", "AWS credential"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{30,}", "GitHub token"),
    (r"xox[bporsa]-[0-9]{10,13}-[0-9a-zA-Z]{24,}", "Slack token"),
    (r"sk-[0-9a-zA-Z]{20,}", "Stripe API key"),
    (r"pk_[0-9a-zA-Z]{20,}", "Stripe publishable key"),
    (r"(?i)api_key\s*[=:]\s*['\"][a-zA-Z0-9\-_]{10,}", "Hardcoded API key"),
    (r"(?i)secret\s*[=:]\s*['\"][a-zA-Z0-9\-_]{8,}", "Hardcoded secret"),
    (r"(?i)password\s*[=:]\s*['\"][^'\"]{4,}", "Hardcoded password"),
    (r"(?i)token\s*[=:]\s*['\"][a-zA-Z0-9\-_\.]{10,}", "Hardcoded token"),
]

INSECURE_STORAGE_IOS = [
    (r"NSUserDefaults", "iOS NSUserDefaults (unencrypted)"),
    (r"NSKeyedArchiver|NSKeyedUnarchiver", "iOS NSKeyedArchiver"),
    (r"writeToFile:|writeToURL:", "iOS file write"),
    (r"CoreData|NSManagedObjectContext", "iOS CoreData"),
    (r"Realm|RLMRealm", "iOS Realm database"),
    (r"Keychain|kSecAttrService|SecItemAdd|SecItemCopyMatching", "iOS Keychain (may be OK if used correctly)"),
    (r"UserDefaults\.(?:set|synchronize|object|array|dictionary)", "iOS UserDefaults (unencrypted)"),
    (r"NSCoder|encodeWithCoder|initWithCoder", "iOS NSCoding archive"),
    (r"UIPasteboard", "iOS UIPasteboard (shared clipboard)"),
    (r"NSLog|print\(|dump\(|debugPrint", "iOS debug logging"),
]

INSECURE_STORAGE_ANDROID = [
    (r"SharedPreferences", "Android SharedPreferences (XML, unencrypted)"),
    (r"getSharedPreferences|getPreferences", "Android SharedPreferences access"),
    (r"openFileOutput|MODE_PRIVATE|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE", "Android file output"),
    (r"SQLiteDatabase|openOrCreateDatabase|db\.execSQL|db\.rawQuery", "Android SQLite database"),
    (r"getExternalStorage|getExternalFilesDir|getExternalCacheDir", "Android external storage"),
    (r"Environment\.getExternalStorageDirectory|Environment\.getDataDirectory", "Android external storage path"),
    (r"android\.content\.ClipboardManager|ClipData", "Android clipboard"),
    (r"Log\.d|Log\.i|Log\.e|Log\.w|Log\.v", "Android logging"),
    (r"Toast\.makeText", "Android Toast (may leak in screen readers)"),
]

SSL_NETWORK_INDICATORS = [
    (r"http://[a-z0-9.\-]+", "HTTP (not HTTPS) endpoint"),
    (r"cleartextTrafficPermitted=\"?true\"?", "Cleartext traffic permitted"),
    (r"usesCleartextTraffic\s*=\s*\"?true\"?", "usesCleartextTraffic=true"),
    (r"allowBackup\s*=\s*\"?true\"?", "Android allowBackup=true"),
    (r"HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER", "SSL hostname verification disabled"),
    (r"CertificatePinner|CertificatePin", "Certificate pinning (check if properly implemented)"),
    (r"NSAllowsArbitraryLoads\s*=\s*true", "iOS ATS disabled entirely"),
    (r"NSExceptionDomains", "iOS ATS exceptions"),
    (r"\.cer|\.crt|\.pem|\.der|\.p12", "Embedded certificate file"),
]


class ApkEngine(BaseEngine):
    name = "apk"
    description = "Mobile APK/IPA analyzer. Escanea apps Android/iOS en busca de insecure storage, SSL pinning bypass, API leaks, permisos peligrosos y configuracion insegura."
    capabilities = ["mobile_security", "android", "ios", "static_analysis", "reverse_engineering"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        app_path = kwargs.get("app", target)
        platform = kwargs.get("platform", self._detect_platform(app_path))
        timeout = int(kwargs.get("timeout", 120))

        raw_lines.append(f"[INFO] Analizando {app_path} (platform: {platform})")

        if not os.path.exists(app_path):
            raw_lines.append(f"[WARN] Archivo no encontrado: {app_path}")
            return EngineResult(success=False, raw_output="", summary="apk: file not found")

        # Try to extract/unzip
        if zipfile.is_zipfile(app_path):
            self._analyze_zip(app_path, platform, findings, raw_lines)
        elif platform == "ipa":
            self._analyze_ipa(app_path, findings, raw_lines)
        else:
            raw_lines.append("[WARN] Formato no reconocido. Intentando como texto...")
            self._analyze_text_file(app_path, findings, raw_lines)

        summary = f"apk: {len(findings)} hallazgos en {app_path.split('/')[-1]}"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _detect_platform(self, path: str) -> str:
        name = os.path.basename(path).lower()
        if name.endswith(".apk") or name.endswith(".aab"):
            return "android"
        if name.endswith(".ipa"):
            return "ios"
        return "android"

    def _analyze_zip(self, app_path: str, platform: str,
                     findings: list[dict[str, Any]],
                     raw_lines: list[str]) -> None:
        try:
            with zipfile.ZipFile(app_path) as z:
                names = z.namelist()
                raw_lines.append(f"[INFO] Archivos en ZIP: {len(names)}")

                # Manifest
                if "AndroidManifest.xml" in names:
                    try:
                        data = z.read("AndroidManifest.xml")
                        text = data.decode("utf-8", errors="ignore")
                        self._analyze_manifest(text, app_path, findings, raw_lines)
                    except Exception:
                        raw_lines.append("[INFO] AndroidManifest.xml is binary (use aapt)")

                # iOS Info.plist
                plist_files = [n for n in names if n.endswith("Info.plist")]
                for plist in plist_files:
                    try:
                        data = z.read(plist)
                        text = data.decode("utf-8", errors="ignore")
                        self._analyze_plist(text, app_path, findings, raw_lines)
                    except Exception:
                        pass

                # Scan text files for patterns
                text_exts = (".xml", ".json", ".properties", ".txt", ".html", ".htm",
                             ".js", ".css", ".strings", ".plist", ".config", ".yml", ".yaml")
                for name in names:
                    if any(name.lower().endswith(ext) for ext in text_exts):
                        try:
                            content = z.read(name).decode("utf-8", errors="ignore")
                            self._scan_content(content, name, app_path, findings, raw_lines)
                        except Exception:
                            pass

                # Check resources
                res_files = [n for n in names if n.startswith("res/") and n.endswith(".xml")]
                raw_lines.append(f"[INFO] Resource XML files: {len(res_files)}")

                # Check for embedded certificates
                cert_files = [n for n in names if n.endswith((".cer", ".crt", ".pem", ".p12", ".der", ".key", ".keystore", ".bks"))]
                if cert_files:
                    raw_lines.append(f"[WARN] Embedded certificate files: {len(cert_files)}")
                    for c in cert_files:
                        findings.append({
                            "file_path": f"{app_path}!{c}", "line_start": 0, "line_end": 0,
                            "severity": "medium",
                            "title": f"Embedded certificate: {c.split('/')[-1]}",
                            "description": f"Certificate file {c} found in APK. Verify if it contains private keys.",
                            "tool": self.name, "rule_id": f"apk-cert-{c.split('/')[-1][:20]}",
                        })

        except zipfile.BadZipFile:
            raw_lines.append("[ERR] Bad ZIP file")
        except Exception as e:
            raw_lines.append(f"[ERR] ZIP analysis: {e}")

    def _analyze_ipa(self, ipa_path: str, findings: list[dict[str, Any]],
                     raw_lines: list[str]) -> None:
        raw_lines.append("[INFO] IPA analysis (basic)")
        try:
            with zipfile.ZipFile(ipa_path) as z:
                names = z.namelist()

                # Find Info.plist
                plists = [n for n in names if n.endswith("Info.plist")]
                if plists:
                    try:
                        data = z.read(plists[0])
                        text = data.decode("utf-8", errors="ignore")
                        self._analyze_plist(text, ipa_path, findings, raw_lines)
                    except Exception:
                        pass

                # Find Mach-O binaries
                machos = [n for n in names if "Payload/" in n and not n.endswith("/") and not "." in n.split("/")[-1]]
                raw_lines.append(f"[INFO] Mach-O binaries: {len(machos)}")

                # Scan plist/text files
                for name in names:
                    if name.endswith((".plist", ".json", ".strings", ".xcconfig")):
                        try:
                            content = z.read(name).decode("utf-8", errors="ignore")
                            self._scan_content(content, name, ipa_path, findings, raw_lines)
                        except Exception:
                            pass
        except Exception as e:
            raw_lines.append(f"[ERR] IPA: {e}")

    def _analyze_manifest(self, manifest: str, app_path: str,
                          findings: list[dict[str, Any]],
                          raw_lines: list[str]) -> None:
        self._check_flag(manifest, 'android:debuggable="true"', "high",
                         "App debuggable",
                         "AndroidManifest: debuggable=true — app puede ser debuggeada.",
                         "apk-debuggable", app_path, findings)

        self._check_flag(manifest, 'android:allowBackup="true"', "medium",
                         "Allow backup enabled",
                         "AndroidManifest: allowBackup=true — datos exportables via adb.",
                         "apk-allowbackup", app_path, findings)

        # Dangerous permissions
        dangerous = ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES",
                     "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES"]
        for perm in dangerous:
            if f"android.permission.{perm}" in manifest:
                findings.append({
                    "file_path": f"{app_path}!AndroidManifest.xml", "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Dangerous permission: {perm}",
                    "description": f"APK requests {perm} — may be abused for overlay attacks, keylogging, or data theft.",
                    "tool": self.name, "rule_id": f"apk-perm-{perm.lower()}",
                })

        # Exported components
        exported = re.findall(r'android:exported="true"', manifest)
        if len(exported) > 5:
            findings.append({
                "file_path": f"{app_path}!AndroidManifest.xml", "line_start": 0, "line_end": 0,
                "severity": "medium",
                "title": f"Exported components: {len(exported)}",
                "description": f"{len(exported)} components exported. May expose IPC to other apps.",
                "tool": self.name, "rule_id": "apk-exported",
            })

    def _analyze_plist(self, plist: str, app_path: str,
                       findings: list[dict[str, Any]],
                       raw_lines: list[str]) -> None:
        self._check_flag(plist, "NSAllowsArbitraryLoads", "high",
                         "ATS disabled",
                         "Info.plist: NSAllowsArbitraryLoads enabled — HTTP connections allowed.",
                         "apk-ats-disabled", app_path, findings)

        self._check_flag(plist, "NSAllowsArbitraryLoadsInMedia", "medium",
                         "ATS media exception",
                         "Info.plist: NSAllowsArbitraryLoadsInMedia enabled.",
                         "apk-ats-media", app_path, findings)

        self._check_flag(plist, "NSAllowsArbitraryLoadsForMedia", "medium",
                         "ATS media exception",
                         "Info.plist: NSAllowsArbitraryLoadsForMedia enabled.",
                         "apk-ats-media2", app_path, findings)

        self._check_flag(plist, "NSAllowsLocalNetworking", "low",
                         "ATS local networking exception",
                         "Info.plist: NSAllowsLocalNetworking enabled.",
                         "apk-ats-local", app_path, findings)

        # Check for exposed URL schemes
        url_schemes = re.findall(r"<string>([a-zA-Z][a-zA-Z0-9+\-.]*)://", plist)
        if url_schemes:
            raw_lines.append(f"[INFO] URL schemes: {url_schemes[:10]}")

    def _check_flag(self, content: str, flag: str, severity: str,
                    title: str, desc: str, rule_id: str, app_path: str,
                    findings: list[dict[str, Any]]) -> None:
        if flag in content:
            findings.append({
                "file_path": app_path, "line_start": 0, "line_end": 0,
                "severity": severity,
                "title": title,
                "description": desc,
                "tool": self.name, "rule_id": rule_id,
            })

    def _scan_content(self, content: str, name: str, app_path: str,
                      findings: list[dict[str, Any]],
                      raw_lines: list[str]) -> None:
        for pattern, desc in APK_LEAK_PATTERNS:
            matches = re.findall(pattern, content)
            for m in matches[:1]:
                masked = m[:12] + "..." + m[-4:] if len(m) > 16 else m
                findings.append({
                    "file_path": f"{app_path}!{name}", "line_start": 0, "line_end": 0,
                    "severity": "high",
                    "title": f"Leak: {desc}",
                    "description": f"Patron '{desc}' en {name}: {masked}",
                    "tool": self.name, "rule_id": f"apk-leak-{desc[:10].lower().replace(' ','')}-{name.split('/')[-1][:15]}",
                    "pattern": desc,
                })

        for pattern, desc in INSECURE_STORAGE_ANDROID:
            if re.search(pattern, content):
                findings.append({
                    "file_path": f"{app_path}!{name}", "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"Storage: {desc}",
                    "description": f"Patron de almacenamiento '{desc}' en {name}",
                    "tool": self.name, "rule_id": f"apk-storage-{name.split('/')[-1][:15]}",
                })

        for pattern, desc in SSL_NETWORK_INDICATORS:
            if re.search(pattern, content):
                findings.append({
                    "file_path": f"{app_path}!{name}", "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": f"SSL/Network: {desc}",
                    "description": f"Patron '{desc}' en {name}",
                    "tool": self.name, "rule_id": f"apk-ssl-{name.split('/')[-1][:15]}",
                })

    def _analyze_text_file(self, file_path: str, findings: list[dict[str, Any]],
                           raw_lines: list[str]) -> None:
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self._scan_content(content, os.path.basename(file_path), file_path, findings, raw_lines)
        except Exception as e:
            raw_lines.append(f"[ERR] {e}")

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
