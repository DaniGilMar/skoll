from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


FRIDA_DEFAULT_SCRIPT = """
// SSL Pinning Bypass (Universal Android)
Java.perform(function() {
    var ArrayList = Java.use('java.util.ArrayList');
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, authType, untrusted) {
        return ArrayList.$new();
    };
    console.log('[+] SSL Pinning Bypassed');
});

// Root detection bypass
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        return false;
    };
    console.log('[+] Root detection bypassed');
});
"""

FRIDA_SCRIPTS: dict[str, str] = {
    "ssl_bypass": """
Java.perform(function() {
    var ArrayList = Java.use('java.util.ArrayList');
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, authType, untrusted) {
        return ArrayList.$new();
    };
    console.log('[+] SSL Pinning Bypassed');
});
""",
    "root_bypass": """
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('binary') !== -1) return false;
        return true;
    };
    console.log('[+] Root detection bypassed');
});
""",
    "dump_classes": """
Java.perform(function() {
    var classes = Java.enumerateLoadedClasses({
        onMatch: function(name) { console.log(name); },
        onComplete: function() { console.log('[+] Class enumeration complete'); }
    });
});
""",
    "dump_activity": """
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');
    Activity.onCreate.implementation = function(savedInstanceState) {
        var Intent = Java.use('android.content.Intent');
        var intent = this.getIntent();
        if (intent) {
            var extras = intent.getExtras();
            if (extras) {
                var keys = extras.keySet();
                var it = keys.iterator();
                while (it.hasNext()) {
                    var key = it.next();
                    var val = extras.get(key);
                    console.log('[INTENT] ' + key + ' = ' + val);
                }
            }
        }
        return this.onCreate(savedInstanceState);
    };
});
""",
    "dump_shared_prefs": """
Java.perform(function() {
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    SharedPreferences.getAll.implementation = function() {
        var result = this.getAll();
        console.log('[PREFS] Dump:');
        var keys = result.keySet();
        var it = keys.iterator();
        while (it.hasNext()) {
            var key = it.next();
            console.log('[PREFS] ' + key + ' = ' + result.get(key));
        }
        return result;
    };
});
""",
}


class FridaEngine(BaseEngine):
    name = "frida"
    description = "Frida dynamic instrumentation. Bypass SSL pinning, root detection, dump clases, contenido de activities y SharedPreferences en apps Android/iOS."
    capabilities = ["mobile_security", "android", "ios", "dynamic_analysis", "ssl_pinning_bypass"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []

        package = kwargs.get("package", target)
        script_name = kwargs.get("script", "ssl_bypass")
        script_content = kwargs.get("script_content", "")
        device = kwargs.get("device", "usb")
        timeout = int(kwargs.get("timeout", 60))

        raw_lines.append(f"[INFO] Frida: {script_name} en {package} (device: {device})")

        if not self._check_frida(raw_lines):
            return EngineResult(
                success=False, raw_output="frida: not installed",
                summary="frida: CLI no disponible",
                findings=[{
                    "file_path": "", "line_start": 0, "line_end": 0,
                    "severity": "info", "title": "Frida no instalado",
                    "description": "Frida CLI no esta en PATH. Instalar: pip install frida-tools",
                    "tool": self.name, "rule_id": "frida-not-installed",
                }],
            )

        if not script_content:
            script_content = FRIDA_SCRIPTS.get(script_name, FRIDA_SCRIPTS["ssl_bypass"])

        # Write script to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            script_path = f.name
            f.write(script_content)

        try:
            # Try to list running apps first
            try:
                r = subprocess.run(
                    ["frida-ps", "-U", "-a"], capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0 and package in r.stdout:
                    raw_lines.append(f"[INFO] App {package} running")
                else:
                    raw_lines.append(f"[INFO] App {package} may not be running. Attempting spawn...")
            except Exception:
                pass

            # Execute Frida
            args = ["frida", "-U", "-f", package, "-l", script_path,
                    "--no-pause", "-o", "/tmp/frida_output.txt"]

            raw_lines.append(f"[INFO] Ejecutando: frida -U -f {package} -l {script_name}")

            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
            )
            stdout = result.stdout
            stderr = result.stderr
            combined = stdout + stderr

            # Read output file
            try:
                with open("/tmp/frida_output.txt") as f:
                    output_content = f.read()
                raw_lines.append(f"[INFO] Frida output: {len(output_content)} chars")
                raw_lines.append(output_content[:1500])
            except (FileNotFoundError, PermissionError):
                output_content = combined
                raw_lines.append(f"[INFO] Frida output: {combined[:1500]}")

            success_markers = {
                "SSL Pinning Bypassed": ("ssl_bypass", "SSL Pinning bypassed via Frida"),
                "Root detection bypassed": ("root_bypass", "Root detection bypassed via Frida"),
                "[INTENT]": ("intent_dump", "Activity intents dumped via Frida"),
                "[PREFS]": ("prefs_dump", "SharedPreferences dumped via Frida"),
                "Class enumeration complete": ("class_dump", "Classes enumerated via Frida"),
            }

            for marker, (rule_id, desc) in success_markers.items():
                if marker in output_content:
                    findings.append({
                        "file_path": package, "line_start": 0, "line_end": 0,
                        "severity": "high" if "bypass" in rule_id else "medium",
                        "title": f"Frida: {script_name} exitoso",
                        "description": desc,
                        "tool": self.name, "rule_id": f"frida-{rule_id}",
                        "package": package, "script": script_name,
                    })
                    raw_lines.append(f"[HIGH] Frida: {desc}")

            if "Error" in stderr or "Failed" in stderr:
                raw_lines.append(f"[WARN] Frida stderr: {stderr[:500]}")

            summary = f"frida: {len(findings)} hallazgos en {package}"
            return EngineResult(
                success=bool(findings),
                raw_output=output_content if 'output_content' in dir() else combined,
                findings=findings,
                summary=summary,
            )

        except FileNotFoundError:
            raw_lines.append("[WARN] frida-tools not found")
            return EngineResult(success=False, raw_output="", summary="frida: not installed")
        except subprocess.TimeoutExpired:
            raw_lines.append("[TIMEOUT] Frida timed out")
        except Exception as e:
            raw_lines.append(f"[ERR] Frida: {e}")
        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass

        summary = f"frida: {len(findings)} hallazgos"
        return EngineResult(
            success=bool(findings),
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _check_frida(self, raw_lines: list[str]) -> bool:
        try:
            r = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                raw_lines.append(f"[INFO] Frida version: {r.stdout.strip()}")
                return True
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
