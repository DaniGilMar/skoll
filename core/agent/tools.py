from __future__ import annotations

import json
import re
import uuid
from typing import Any

from core.run import run_command
from core.osint import amass_enum, subfinder_enum, theharvester_collect, crt_lookup, dns_enum, git_leaks
from core.enum import masscan_scan, smb_enum, ldap_enum, snmp_enum, banner_grab
from core.web import ffuf_enum, nuclei_scan, commix_test, xss_test, idor_test, jwt_attack, ssl_scan


TOOL_DESCRIPTIONS = [
    {
        "name": "amass_enum",
        "description": "Enumera subdominios con Amass (DNS, certs, APIs). Lento pero exhaustivo.",
        "args": {"domain": "dominio a enumerar (ej: ejemplo.com)"},
    },
    {
        "name": "subfinder_enum",
        "description": "Enumera subdominios rápido con Subfinder (pasivo, fuentes públicas).",
        "args": {"domain": "dominio a enumerar"},
    },
    {
        "name": "theharvester_collect",
        "description": "Recolecta emails, subdominios y hosts con theHarvester (Google, Bing, LinkedIn).",
        "args": {"domain": "dominio a investigar"},
    },
    {
        "name": "crt_lookup",
        "description": "Consulta Certificate Transparency logs (crt.sh) para descubrir subdominios por certificados. Gratis, sin API key.",
        "args": {"domain": "dominio a consultar"},
    },
    {
        "name": "dns_enum",
        "description": "Enumeración DNS completa (A, AAAA, MX, NS, TXT, SOA, CNAME) con dig. Gratis, sin API key.",
        "args": {"domain": "dominio a consultar"},
    },
    {
        "name": "git_leaks",
        "description": "Busca repositorios git expuestos, .env, sitemaps y posibles filtrados de código.",
        "args": {"target": "dominio o IP"},
    },
    {
        "name": "masscan_scan",
        "description": "Escaneo masivo de puertos con masscan (ultrarrápido, SYN-only). Para mapeo inicial de todos los puertos 1-65535.",
        "args": {"target": "IP o rango CIDR", "ports": "rango de puertos (default: 1-65535)", "rate": "paquetes/segundo (default: 1000)"},
    },
    {
        "name": "banner_grab",
        "description": "Captura banners de servicios en puertos comunes (FTP, SSH, SMTP, HTTP, SMB, MySQL, PostgreSQL, Redis, MongoDB, etc.).",
        "args": {"target": "IP a escanear", "ports": "lista de puertos separados por coma (default: puertos comunes)"},
    },
    {
        "name": "smb_enum",
        "description": "Enumeración SMB completa: usuarios, shares, OS, null session, con enum4linux + smbclient. Ejecútalo si nmap reporta puerto 445 abierto.",
        "args": {"target": "IP del target"},
    },
    {
        "name": "ldap_enum",
        "description": "Enumeración LDAP con bind anónimo. Extrae namingContexts, usuarios, grupos, admins. Ejecútalo si nmap reporta puertos 389/636 abiertos.",
        "args": {"target": "IP del target", "domain": "dominio (opcional)"},
    },
    {
        "name": "snmp_enum",
        "description": "Enumeración SNMP: prueba comunidades (public, private, etc.), extrae sistema, interfaces, procesos, usuarios. Ejecútalo si nmap reporta puerto 161 abierto.",
        "args": {"target": "IP del target", "community": "community string (default: public)"},
    },
    {
        "name": "ffuf_enum",
        "description": "Fuzzing rápido con ffuf: directorios, parámetros GET, VHOST. Úsalo para descubrir rutas ocultas, parámetros o subdominios.",
        "args": {"url": "URL base (ej: http://target/)", "mode": "dir/params/vhost (default: dir)"},
    },
    {
        "name": "nuclei_scan",
        "description": "Escaneo masivo de CVEs y misconfiguraciones con nuclei templates. Detecta vulnerabilidades conocidas por CVE.",
        "args": {"target": "URL o IP", "severity": "severidad mínima (medium,critical,high)"},
    },
    {
        "name": "commix_test",
        "description": "Prueba de inyección de comandos (command injection) en parámetros GET con commix.",
        "args": {"url": "URL completa con parámetro (ej: http://target/page.php?cmd=test)"},
    },
    {
        "name": "xss_test",
        "description": "Prueba de XSS reflejado y almacenado. Envía payloads y comprueba si se reflejan en la respuesta.",
        "args": {"url": "URL completa", "param": "nombre del parámetro a testear (opcional)"},
    },
    {
        "name": "idor_test",
        "description": "Prueba de IDOR (Insecure Direct Object Reference). Intenta acceder a recursos cambiando IDs numéricos.",
        "args": {"url": "URL con FUZZ donde reemplazar IDs, o URL + ?param=", "param": "nombre del parámetro ID (default: id)"},
    },
    {
        "name": "jwt_attack",
        "description": "Analiza tokens JWT: algoritmo none, KID injection, secret débil, decodificación de header/payload.",
        "args": {"token": "JWT token a analizar", "target": "URL del endpoint (opcional)"},
    },
    {
        "name": "ssl_scan",
        "description": "Escanea SSL/TLS: protocolos soportados, cifrados débiles, Heartbleed, POODLE con nmap scripts.",
        "args": {"target": "IP o hostname"},
    },
    {
        "name": "scan_ports",
        "description": "Escanea puertos abiertos con nmap. Úsalo para descubrir qué servicios corre el target.",
        "args": {"target": "IP o hostname", "flags": "flags de nmap (ej: -sV -sC --top-ports 1000)"},
    },
    {
        "name": "identify_web",
        "description": "Identifica tecnologías web con whatweb. Úsalo cuando haya puertos 80/443 abiertos.",
        "args": {"target": "IP o hostname"},
    },
    {
        "name": "sql_injection",
        "description": "Prueba inyección SQL con sqlmap en la URL dada. Úsalo si hay formularios o parámetros GET/POST.",
        "args": {"url": "URL completa (ej: http://target:80/)"},
    },
    {
        "name": "directory_enum",
        "description": "Enumera directorios/rutas con gobuster. Úsalo para descubrir rutas ocultas en la web.",
        "args": {"url": "URL base (ej: http://target/)"},
    },
    {
        "name": "web_vuln_scan",
        "description": "Escanea vulnerabilidades web con nikto. Detecta configuraciones inseguras, cabeceras faltantes, etc.",
        "args": {"target": "IP o hostname"},
    },
    {
        "name": "fetch_page",
        "description": "Descarga una página web y extrae enlaces, formularios y endpoints WebSocket (ws://, wss://). Úsalo para descubrir rutas y funcionalidades ocultas en el HTML.",
        "args": {"url": "URL completa (ej: http://target:80/)"},
    },
    {
        "name": "websocket_test",
        "description": "Conecta a un endpoint WebSocket y prueba mensajes malformados, inyecciones y manipulación del protocolo. Incluye fuzzing básico de payloads.",
        "args": {"url": "URL WebSocket completa (ej: ws://target:80/chat)", "payloads": "payloads separados por coma (opcional)"},
    },
    {
        "name": "custom_script",
        "description": "EJECUTA CUALQUIER SCRIPT PYTHON que generes para probar un vector específico (CSRF, SSTI, SSRF, deserialización, race condition, etc.). El script recibe 'target' como variable. Imprime resultados para que el agente los evalúe.",
        "args": {"code": "código Python a ejecutar", "target": "IP o hostname"},
    },
    {
        "name": "http_request",
        "description": "Hace una petición HTTP personalizada. Útil para probar endpoints, cabeceras, métodos HTTP, etc.",
        "args": {"url": "URL completa", "method": "GET/POST/PUT/DELETE/OPTIONS", "headers": "JSON de cabeceras (opcional)", "body": "cuerpo de la petición (opcional)"},
    },
    {
        "name": "done",
        "description": "LLÁMALA CUANDO HAYAS ENCONTRADO UNA VULNERABILIDAD O HAYAS AGOTADO TODOS LOS VECTORES. Incluye un resumen de lo encontrado.",
        "args": {"summary": "resumen de hallazgos encontrados"},
    },
]


def format_tools_for_llm() -> str:
    lines = ["HERRAMIENTAS DISPONIBLES:", ""]
    for t in TOOL_DESCRIPTIONS:
        lines.append(f"  {t['name']}: {t['description']}")
        for k, v in t["args"].items():
            lines.append(f"    - {k}: {v}")
        lines.append("")
    return "\n".join(lines)


def run_tool(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    match tool_name:
        case "amass_enum":
            return amass_enum(args.get("domain", ""))
        case "subfinder_enum":
            return subfinder_enum(args.get("domain", ""))
        case "theharvester_collect":
            return theharvester_collect(args.get("domain", ""))
        case "crt_lookup":
            return crt_lookup(args.get("domain", ""))
        case "dns_enum":
            return dns_enum(args.get("domain", ""))
        case "git_leaks":
            return git_leaks(args.get("target", ""))
        case "masscan_scan":
            return masscan_scan(args.get("target", ""), args.get("ports", "1-65535"), int(args.get("rate", 1000)))
        case "banner_grab":
            return banner_grab(args.get("target", ""), args.get("ports", ""))
        case "smb_enum":
            return smb_enum(args.get("target", ""))
        case "ldap_enum":
            return ldap_enum(args.get("target", ""), args.get("domain", ""))
        case "snmp_enum":
            return snmp_enum(args.get("target", ""), args.get("community", "public"))
        case "ffuf_enum":
            return ffuf_enum(args.get("url", ""), args.get("mode", "dir"))
        case "nuclei_scan":
            return nuclei_scan(args.get("target", ""), args.get("severity", "medium,critical,high"))
        case "commix_test":
            return commix_test(args.get("url", ""))
        case "xss_test":
            return xss_test(args.get("url", ""), args.get("param", ""))
        case "idor_test":
            return idor_test(args.get("url", ""), args.get("param", "id"))
        case "jwt_attack":
            return jwt_attack(args.get("token", ""), args.get("target", ""))
        case "ssl_scan":
            return ssl_scan(args.get("target", ""))
        case "scan_ports":
            return _run_nmap(args.get("target", ""), args.get("flags", "-sV -sC --min-rate 5000 -T5 --top-ports 1000"))
        case "identify_web":
            return _run_whatweb(args.get("target", ""))
        case "sql_injection":
            return _run_sqlmap(args.get("url", ""))
        case "directory_enum":
            return _run_gobuster(args.get("url", ""))
        case "web_vuln_scan":
            return _run_nikto(args.get("target", ""))
        case "fetch_page":
            return _run_fetch_page(args.get("url", ""))
        case "websocket_test":
            return _run_websocket_test(args.get("url", ""), args.get("payloads", ""))
        case "custom_script":
            return _run_custom_script(args.get("code", ""), args.get("target", ""))
        case "http_request":
            return _run_http_request(args.get("url", ""), args.get("method", "GET"), args.get("headers"), args.get("body"))
        case "done":
            return {"status": "done", "summary": args.get("summary", "")}
        case _:
            return {"status": "error", "error": f"Herramienta desconocida: {tool_name}"}


def _run_nmap(target: str, flags: str) -> dict[str, Any]:
    if not target:
        return {"status": "error", "error": "target requerido"}
    cmd = ["nmap", *flags.split(), target, "-oX", "-"]
    result = run_command(cmd, description=f"scan_ports {target}", timeout=600)
    if result["returncode"] != 0 and not result["timed_out"]:
        return {"status": "error", "error": result["stderr"][:500]}
    stdout = result["stdout"]
    if not stdout.strip():
        return {"status": "ok", "result": "Sin resultados"}
    import xml.etree.ElementTree as ET
    observations = []
    try:
        root = ET.fromstring(stdout)
        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                port_id = port.get("port", "0")
                protocol = port.get("protocol", "tcp")
                state_el = port.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                service_el = port.find("service")
                service = service_el.get("name", "") if service_el is not None else ""
                observations.append(f"  puerto {port_id}/{protocol}: {state} - {service}")
    except ET.ParseError:
        return {"status": "error", "error": "Error parseando XML de nmap"}
    if not observations:
        return {"status": "ok", "result": "0 puertos abiertos encontrados"}
    return {"status": "ok", "result": f"Puertos encontrados:\n" + "\n".join(observations)}


def _run_whatweb(target: str) -> dict[str, Any]:
    if not target:
        return {"status": "error", "error": "target requerido"}
    url = f"http://{target}" if not target.startswith("http") else target
    cmd = ["whatweb", "--no-errors", "-a", "3", url]
    result = run_command(cmd, description=f"identify_web {url}", timeout=120)
    if result["returncode"] not in (0, 1):
        return {"status": "ok", "result": "Sin respuesta web"}
    output = result["stdout"].strip()
    if not output:
        return {"status": "ok", "result": "Sin respuesta web"}
    return {"status": "ok", "result": f"Tecnologías detectadas: {output[:2000]}"}


def _run_sqlmap(url: str) -> dict[str, Any]:
    if not url:
        return {"status": "error", "error": "url requerida"}
    cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level", "1", "--risk", "1", "--time-sec", "3", "--forms", "--crawl", "1", "--output-dir", "/tmp/skoll_sqlmap"]
    result = run_command(cmd, description=f"sql_injection {url}", timeout=180)
    stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
    if "parameter" in stdout.lower() and "vulnerable" in stdout.lower():
        return {"status": "ok", "result": "POSIBLE SQLi detectada. Revisar output completo."}
    return {"status": "ok", "result": "Sin inyecciones SQL detectadas"}


def _run_gobuster(url: str) -> dict[str, Any]:
    if not url:
        return {"status": "error", "error": "url requerida"}
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "20", "--timeout", "5s"]
    result = run_command(cmd, description=f"directory_enum {url}", timeout=300)
    output = (result.get("stdout") or "") + (result.get("stderr") or "")
    lines = [l for l in output.split("\n") if l.strip() and l.strip().startswith("/")]
    if lines:
        return {"status": "ok", "result": "Rutas encontradas:\n" + "\n".join(lines[:30])}
    return {"status": "ok", "result": "Sin rutas descubiertas"}


def _run_nikto(target: str) -> dict[str, Any]:
    if not target:
        return {"status": "error", "error": "target requerido"}
    url = f"http://{target}" if not target.startswith("http") else target
    outfile = f"/tmp/skoll_nikto_{uuid.uuid4().hex[:8]}.txt"
    cmd = ["nikto", "-h", url, "-o", outfile, "-Format", "txt", "-Tuning", "123467"]
    result = run_command(cmd, description=f"web_vuln_scan {url}", timeout=600)
    try:
        with open(outfile) as f:
            content = f.read()
        return {"status": "ok", "result": f"Hallazgos nikto:\n{content[:4000]}"}
    except (FileNotFoundError, PermissionError):
        return {"status": "ok", "result": "nikto completado sin hallazgos relevantes"}
    finally:
        import os
        try: os.remove(outfile)
        except: pass


def _run_custom_script(code: str, target: str) -> dict[str, Any]:
    if not code:
        return {"status": "error", "error": "code requerido"}
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("import sys\n")
        f.write(f"target = {repr(target)}\n")
        f.write(code)
        fname = f.name
    try:
        result = run_command(["python3", fname], description=f"custom_script {target}", timeout=120)
        return {"status": "ok", "result": (result.get("stdout") or "")[:3000] + (result.get("stderr") or "")[:1000]}
    finally:
        try: os.remove(fname)
        except: pass


def _run_http_request(url: str, method: str, headers: str | None, body: str | None) -> dict[str, Any]:
    import json
    code = f"""
import urllib.request, urllib.error
req = urllib.request.Request({repr(url)}, method={repr(method)})
headers = {repr(json.loads(headers) if headers else {})}
for k, v in headers.items():
    req.add_header(k, v)
if {repr(body or "")}:
    req.data = {repr((body or "").encode())}.encode() if isinstance({repr((body or "").encode())}, str) else {repr((body or "").encode())}
try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(f"Status: {{resp.status}}")
        print(f"Headers: {{dict(resp.headers)}}")
        print(f"Body: {{resp.read().decode(errors='ignore')[:2000]}}")
except urllib.error.HTTPError as e:
    print(f"Status: {{e.code}}")
    print(f"Headers: {{dict(e.headers)}}")
    print(f"Body: {{e.read().decode(errors='ignore')[:2000]}}")
except Exception as e:
    print(f"Error: {{e}}")
"""
    return _run_custom_script(code, "")


def _run_fetch_page(url: str) -> dict[str, Any]:
    import re
    if not url:
        return {"status": "error", "error": "url requerida"}
    result = run_command(["curl", "-s", "-L", "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", url],
                         description=f"fetch_page {url}", timeout=30)
    html = (result.get("stdout") or "")[:50000]
    if not html:
        return {"status": "ok", "result": "Página vacía o no accesible"}

    out = []
    ws_urls = re.findall(r'wss?://[^\s"\'<>]+', html)
    if ws_urls:
        out.append(f"WebSockets: {', '.join(ws_urls[:10])}")
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if forms:
        out.append(f"Formularios: {', '.join(forms[:10])}")
    scripts = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if scripts:
        out.append(f"Scripts JS: {', '.join(scripts[:10])}")
    api_paths = re.findall(r'["\'](/api/[^"\']*)["\']', html)
    if api_paths:
        out.append(f"Endpoints API: {', '.join(api_paths[:10])}")
    title = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    if title:
        out.append(f"Título: {title.group(1)}")
    out.append(f"HTML size: {len(html)} bytes")
    return {"status": "ok", "result": "\n".join(out)}


def _run_websocket_test(url: str, payloads: str = "") -> dict[str, Any]:
    if not url:
        return {"status": "error", "error": "url requerida"}
    import asyncio
    try:
        import websockets
    except ImportError:
        return {"status": "error", "error": "websockets library not installed"}

    default_payloads = ['{"message":"test"}', '{"message":"<script>alert(1)</script>"}', '{"message":""}', '{"message":"\' OR 1=1 --"}', "ping", "</ready>"]
    if payloads:
        test_payloads = [p.strip() for p in payloads.split(",")]
    else:
        test_payloads = default_payloads

    results = []

    async def test_ws():
        try:
            async with websockets.connect(url, close_timeout=5) as ws:
                results.append(f"✅ Conectado a {url}")
                for payload in test_payloads[:5]:
                    try:
                        await ws.send(payload)
                        resp = await asyncio.wait_for(ws.recv(), timeout=5)
                        results.append(f"  Enviado: {payload[:80]}")
                        results.append(f"  Respuesta: {(resp[:200] if resp else 'None')}")
                    except asyncio.TimeoutError:
                        results.append(f"  Payload '{payload[:50]}' → Timeout")
                    except Exception as e:
                        results.append(f"  Payload '{payload[:50]}' → Error: {type(e).__name__}")
        except Exception as e:
            results.append(f"❌ No se pudo conectar a {url}: {e}")

    asyncio.run(test_ws())

    if not results:
        return {"status": "ok", "result": "Sin respuesta del WebSocket"}
    return {"status": "ok", "result": "\n".join(results)}
