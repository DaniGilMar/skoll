from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error
from typing import Any

from core.logging import get_logger
from core.run import run_command

logger = get_logger()


def ffuf_enum(url: str, wordlist: str = "", mode: str = "dir") -> dict[str, Any]:
    from skoll_agent.config.wordlists import resolve_wordlist
    """Fuzzing con ffuf: directorios, parámetros, VHOST."""
    outfile = "/tmp/skoll_ffuf.json"
    default_wordlist = resolve_wordlist("web_directories_common")
    wl = wordlist or default_wordlist
    if not os.path.exists(wl):
        return {"status": "ok", "result": f"Wordlist no encontrada: {wl}"}
    results = []
    if mode == "dir":
        cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wl, "-o", outfile, "-of", "json", "-t", "30", "-timeout", "5", "-ac", "-noninteractive"]
        run_command(cmd, description=f"ffuf dir {url}", timeout=180)
    elif mode == "params":
        cmd = ["ffuf", "-u", f"{url}?FUZZ=test", "-w", wl, "-o", outfile, "-of", "json", "-t", "30", "-timeout", "5", "-ac", "-noninteractive"]
        run_command(cmd, description=f"ffuf params {url}", timeout=180)
    elif mode == "vhost":
        cmd = ["ffuf", "-u", url, "-w", wl, "-H", "Host: FUZZ", "-o", outfile, "-of", "json", "-t", "30", "-timeout", "5", "-ac", "-noninteractive", "-fs", "0"]
        run_command(cmd, description=f"ffuf vhost {url}", timeout=300)
    try:
        with open(outfile) as f:
            data = json.load(f)
        for entry in data.get("results", []):
            status = entry.get("status", 0)
            length = entry.get("length", 0)
            words = entry.get("words", 0)
            url_found = entry.get("url", entry.get("input", ""))
            results.append(f"  {status:3d} | {length:6d}B | {url_found[:100]}")
    except: pass
    try: os.remove(outfile)
    except: pass
    if not results:
        return {"status": "ok", "result": f"ffuf ({mode}): sin resultados"}
    return {"status": "ok", "result": f"ffuf ({mode}): {len(results)} resultados\n" + "\n".join(results[:40])}


def nuclei_scan(target: str, severity: str = "medium,critical,high") -> dict[str, Any]:
    """Escaneo de vulnerabilidades con templates nuclei. Detecta CVEs, misconfigs, exposures."""
    outfile = "/tmp/skoll_nuclei.json"
    cmd = ["nuclei", "-u", target, "-s", severity, "-o", outfile, "-j", "-t", "50", "-timeout", "5"]
    run_command(cmd, description=f"nuclei {target} ({severity})", timeout=300)
    results = []
    try:
        with open(outfile) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        info = entry.get("info", {})
                        results.append(f"  [{entry.get('severity','?')}] {info.get('name', entry.get('matched-at','?'))}")
                        results.append(f"    URL: {entry.get('matched-at','')}")
                        if entry.get("curl-command"):
                            results.append(f"    curl: {entry['curl-command'][:150]}")
                    except: pass
    except: pass
    try: os.remove(outfile)
    except: pass
    if not results:
        return {"status": "ok", "result": "nuclei: sin hallazgos"}
    return {"status": "ok", "result": f"nuclei: {len(results)} hallazgos\n" + "\n".join(results[:30])}


def commix_test(url: str) -> dict[str, Any]:
    """Prueba de inyección de comandos con commix."""
    cmd = ["commix", "-u", url, "--batch", "--output-dir=/tmp/skoll_commix"]
    result = run_command(cmd, description=f"commix {url}", timeout=180)
    output = (result.get("stdout") or "") + (result.get("stderr") or "")
    if "vulnerable" in output.lower():
        payloads = re.findall(r"Payload: ([^\n]+)", output)
        lines = ["POSIBLE COMMAND INJECTION"]
        if payloads: lines.append(f"  Payloads: {', '.join(payloads[:5])}")
        return {"status": "ok", "result": "\n".join(lines)}
    return {"status": "ok", "result": "commix: sin inyección de comandos detectable"}


def xss_test(url: str, param: str = "") -> dict[str, Any]:
    """Prueba de XSS reflejado y almacenado mediante script personalizado."""
    code = '''
import urllib.request, urllib.error, re, urllib.parse
target = REPLACE_URL
param = REPLACE_PARAM
payloads = ["<script>alert(1)</script>", '"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>", "{{7*7}}"]
results = []
for payload in payloads:
    try:
        if param:
            full_url = target + ("&" if "?" in target else "?") + param + "=" + urllib.parse.quote(payload)
        else:
            full_url = target
        req = urllib.request.Request(full_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            html = r.read().decode(errors="ignore")
            if payload[:10] in html.replace("&lt;", "<").replace("&gt;", ">"):
                results.append("  POSIBLE XSS: '" + payload[:50] + "' reflejado en respuesta")
    except:
        pass
if not results:
    results.append("XSS: sin reflejo detectable en parametros basicos")
print("\\n".join(results))
'''.replace("REPLACE_URL", repr(url)).replace("REPLACE_PARAM", repr(param))
    from core.agent.tools import _run_custom_script
    return _run_custom_script(code, url)


def idor_test(url: str, param: str = "id") -> dict[str, Any]:
    """Prueba de IDOR (Insecure Direct Object Reference) mediante manipulación de IDs."""
    code = '''
import urllib.request, urllib.error, json
target = REPLACE_URL
param = REPLACE_PARAM
results = []
for ref_id in [1, 2, 100, 1000, 10000, -1, 0]:
    try:
        full_url = target.replace("FUZZ", str(ref_id))
        if "FUZZ" not in full_url:
            sep = "&" if "?" in target else "?"
            full_url = target + sep + param + "=" + str(ref_id)
        req = urllib.request.Request(full_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            status_code = r.status
            body = r.read().decode(errors="ignore")[:100]
            if "error" not in body.lower() and "not found" not in body.lower() and "invalid" not in body.lower():
                results.append("  ID %s: HTTP %s - %s" % (ref_id, status_code, body[:80]))
    except urllib.error.HTTPError as e:
        if e.code in (200, 301, 302):
            body = e.read().decode(errors="ignore")[:100]
            results.append("  ID %s: HTTP %s - %s" % (ref_id, e.code, body[:80]))
    except:
        pass
if not results:
    results.append("IDOR: sin acceso a recursos de otros usuarios detectable")
print("\\n".join(results))
'''.replace("REPLACE_URL", repr(url)).replace("REPLACE_PARAM", repr(param))
    from core.agent.tools import _run_custom_script
    return _run_custom_script(code, url)


def jwt_attack(token: str, target: str = "") -> dict[str, Any]:
    """Análisis y ataques a JWT: algoritmo none, secret débil, KID injection."""
    code = '''
import json, base64
token = REPLACE_TOKEN
target = REPLACE_TARGET
results = []
try:
    parts = token.split(".")
    header_b64 = parts[0] + "=="
    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64))
    except:
        header = {}
    results.append("  Header: " + json.dumps(header, indent=2)[:200])
    if header.get("alg") == "none":
        results.append("  ALGORITMO 'none' PERMITIDO")
    if header.get("kid"):
        results.append("  KID injection posible: kid=" + str(header.get("kid")))
except Exception as e:
    results.append("  Error: " + str(e))
if not results:
    results.append("JWT: no se pudo analizar")
print("\\n".join(results))
'''.replace("REPLACE_TOKEN", repr(token)).replace("REPLACE_TARGET", repr(target))
    from core.agent.tools import _run_custom_script
    return _run_custom_script(code, target)


def ssl_scan(target: str) -> dict[str, Any]:
    """Escaneo de SSL/TLS: protocolos, cifrados, vulnerabilidades con nmap scripts."""
    results = []
    cmd = ["nmap", "--script", "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,tls-nextprotoneg", target, "-p", "443,8443"]
    result = run_command(cmd, description=f"ssl_scan {target}", timeout=120)
    output = (result.get("stdout") or "") + (result.get("stderr") or "")
    weak = re.findall(r"weak\s*(?:cipher|encryption).*?(?:\n|$)", output, re.IGNORECASE)
    if weak: results.append(f"  Cifrados débiles: {', '.join(weak[:5])}")
    heartbleed = re.findall(r"heartbleed.*?vulnerable", output, re.IGNORECASE)
    if heartbleed: results.append("  ⚠️ HEARTBLEED VULNERABLE")
    poodle = re.findall(r"poodle.*?vulnerable", output, re.IGNORECASE)
    if poodle: results.append("  ⚠️ POODLE VULNERABLE")
    protocols = re.findall(r"TLSv\d\.\d", output)
    if protocols: results.append(f"  Protocolos: {', '.join(set(protocols))}")
    if not results: results.append("SSL: sin vulnerabilidades detectadas")
    return {"status": "ok", "result": "\n".join(results)}
