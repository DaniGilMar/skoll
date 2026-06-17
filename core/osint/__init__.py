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


def amass_enum(domain: str) -> dict[str, Any]:
    cmd = ["amass", "enum", "-d", domain, "-o", "/tmp/skoll_amass.txt", "-nocolor"]
    run_command(cmd, description=f"amass {domain}", timeout=300)
    subs = []
    try:
        with open("/tmp/skoll_amass.txt") as f:
            subs = [l.strip() for l in f if l.strip()]
    except: pass
    return {"status": "ok", "result": f"Amass: {len(subs)} subdominios\n" + "\n".join(subs[:50])}


def subfinder_enum(domain: str) -> dict[str, Any]:
    outfile = "/tmp/skoll_subfinder.txt"
    cmd = ["subfinder", "-d", domain, "-o", outfile, "-silent"]
    run_command(cmd, description=f"subfinder {domain}", timeout=120)
    subs = []
    try:
        with open(outfile) as f:
            subs = [l.strip() for l in f if l.strip()]
    except: pass
    return {"status": "ok", "result": f"Subfinder: {len(subs)} subdominios\n" + "\n".join(subs[:50])}


def theharvester_collect(domain: str) -> dict[str, Any]:
    sources = "google,bing,linkedin,yahoo,baidu"
    cmd = ["theHarvester", "-d", domain, "-b", sources, "-f", "/tmp/skoll_harvester.html"]
    run_command(cmd, description=f"theHarvester {domain}", timeout=180)
    hosts, emails = [], []
    try:
        with open("/tmp/skoll_harvester.html") as f:
            content = f.read()
        hosts = re.findall(r'class="host">([^<]+)', content)
        emails = re.findall(r'class="email">([^<]+)', content)
    except: pass
    lines = []
    if emails: lines.append(f"Emails ({len(emails)}):\n  " + "\n  ".join(emails[:30]))
    if hosts: lines.append(f"Hosts ({len(hosts)}):\n  " + "\n  ".join(hosts[:30]))
    if not lines: lines.append("Sin resultados de theHarvester")
    return {"status": "ok", "result": "\n".join(lines)}


def crt_lookup(domain: str) -> dict[str, Any]:
    """Certificate Transparency logs vía crt.sh + certspotter — gratis, sin API key."""
    seen = set()
    # Try crt.sh JSON API
    for prefix in ("%25.", ""):
        url = f"https://crt.sh/?q={prefix}{domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
            for entry in data:
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n and domain in n:
                        seen.add(n)
        except: pass
    # Try certspotter as fallback
    if not seen:
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
            for entry in data:
                for n in entry.get("dns_names", []):
                    n = n.strip().lower().lstrip("*.")
                    if domain in n:
                        seen.add(n)
        except: pass
    if not seen:
        return {"status": "ok", "result": "CT logs: sin resultados (servicios pueden estar caídos)"}
    sorted_subs = sorted(seen)[:40]
    return {"status": "ok", "result": f"CT logs: {len(seen)} subdominios\n  " + "\n  ".join(sorted_subs)}


def dns_enum(domain: str) -> dict[str, Any]:
    """Enumeración DNS completa con dig — gratis, sin API key."""
    lines = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        try:
            cmd = ["dig", "+short", rtype, domain]
            r = run_command(cmd, description=f"dig {rtype} {domain}", timeout=10)
            out = (r.get("stdout") or "").strip()
            if out:
                records = [l.strip() for l in out.split("\n") if l.strip()][:10]
                lines.append(f"{rtype}: {', '.join(records[:5])}")
        except: pass
    if not lines:
        lines.append("Sin registros DNS")
    return {"status": "ok", "result": "Registros DNS:\n" + "\n".join(lines)}


def git_leaks(target: str) -> dict[str, Any]:
    """Busca repositorios git expuestos y posibles leaks."""
    results = []
    for scheme in ("https", "http"):
        for path in ("/.git/config", "/.env", "/sitemap.xml", "/backup.zip", "/.gitignore", "/.htaccess", "/config.json", "/dump.sql"):
            url = f"{scheme}://{target}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    content = r.read().decode(errors="ignore")[:200]
                    results.append(f"EXPUESTO: {url} → {content[:100]}")
            except urllib.error.HTTPError as e:
                if e.code not in (404, 403):
                    results.append(f"HTTP {e.code}: {url}")
            except: pass
    if not results:
        results.append("No se encontraron leaks en endpoints comunes")
    return {"status": "ok", "result": "\n".join(results)}
