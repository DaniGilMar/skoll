from __future__ import annotations

import os
import re
import socket
import tempfile
from typing import Any

from core.logging import get_logger
from core.run import run_command

logger = get_logger()


def masscan_scan(target: str, ports: str = "1-65535", rate: int = 1000) -> dict[str, Any]:
    """Escaneo masivo de puertos. Intenta masscan (root), fallback a nmap."""
    import xml.etree.ElementTree as ET
    outfile = "/tmp/skoll_masscan.json"
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oJ", outfile, "--wait", "0"]
    result = run_command(cmd, description=f"masscan {target} (puertos {ports})", timeout=300)
    open_ports = []
    if result.get("returncode") == 0:
        try:
            with open(outfile) as f:
                content = f.read()
            import json
            data = json.loads(content)
            for entry in data:
                if isinstance(entry, dict) and entry.get("ports"):
                    for p in entry["ports"]:
                        if p.get("status", "") == "open":
                            open_ports.append(f"  puerto {p['port']}/{p.get('protocol', 'tcp')}: open")
        except: pass
    try: os.remove(outfile)
    except: pass
    # Fallback a nmap si masscan falló (sin root)
    if not open_ports:
        nmap_ports = "--top-ports 1000" if ports in ("1-65535", "") else f"-p {ports}"
        result2 = run_command(["nmap", "-T5", "--min-rate", "5000", nmap_ports, target, "-oX", "-"], description=f"nmap fallback {target}", timeout=600)
        try:
            root = ET.fromstring(result2.get("stdout", ""))
            for port in root.findall(".//port"):
                state_el = port.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    port_id = port.get("port", "?")
                    protocol = port.get("protocol", "tcp")
                    service_el = port.find("service")
                    service = service_el.get("name", "") if service_el is not None else ""
                    open_ports.append(f"  puerto {port_id}/{protocol}: open - {service}")
        except: pass
    if not open_ports:
        return {"status": "ok", "result": "Escaneo: 0 puertos abiertos encontrados"}
    return {"status": "ok", "result": f"Escaneo: {len(open_ports)} puertos abiertos\n" + "\n".join(open_ports[:50])}


def smb_enum(target: str) -> dict[str, Any]:
    """Enumeración SMB: usuarios, shares, OS, sesiones. Usa enum4linux + smbclient."""
    lines = []
    # enum4linux
    result = run_command(["enum4linux", "-a", target], description=f"enum4linux {target}", timeout=120)
    output = (result.get("stdout") or "") + (result.get("stderr") or "")
    # Extract useful info
    users = re.findall(r"user:\s*\[([^\]]+)\]", output, re.IGNORECASE)
    if users: lines.append(f"Usuarios SMB ({len(users)}): {', '.join(users[:20])}")
    shares = re.findall(r"//[^\s]+", output)
    if shares: lines.append(f"Shares: {', '.join(shares[:10])}")
    os_match = re.search(r"(?:OS|platform):\s*([^\n]+)", output, re.IGNORECASE)
    if os_match: lines.append(f"OS: {os_match.group(1).strip()}")
    # smbclient - check null session
    result2 = run_command(["smbclient", "-L", f"//{target}/", "-N", "--option", "client min protocol=NT1"], description=f"smbclient -L {target}", timeout=30)
    out2 = (result2.get("stdout") or "") + (result2.get("stderr") or "")
    if "NT_STATUS_ACCESS_DENIED" not in out2 and "protocol negotiation failed" not in out2:
        disk_shares = re.findall(r"^\s*([^\s]+)\s+Disk", out2, re.MULTILINE)
        if disk_shares: lines.append(f"Shares accesibles (null session): {', '.join(disk_shares)}")
    if not lines: lines.append("SMB: sin información accesible (requiere credenciales)")
    return {"status": "ok", "result": "\n".join(lines)}


def ldap_enum(target: str, domain: str = "") -> dict[str, Any]:
    """Enumeración LDAP con bind anónimo. Extrae namingContexts, usuarios, grupos."""
    lines = []
    result = run_command(["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", "", "-s", "base", "namingContexts"], description=f"ldapsearch base {target}", timeout=15)
    out = (result.get("stdout") or "")
    contexts = re.findall(r"namingContexts:\s*([^\n]+)", out)
    if not contexts:
        return {"status": "ok", "result": "LDAP: bind anónimo no permitido o sin namingContexts"}
    lines.append(f"namingContexts: {', '.join(contexts)}")
    # Try to enumerate users from each context
    for ctx in contexts:
        r = run_command(["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", ctx, "(objectClass=person)", "cn", "mail", "sAMAccountName"], description=f"ldapsearch users {target}", timeout=30)
        o = (r.get("stdout") or "")
        users = re.findall(r"cn:\s*([^\n]+)", o)
        if users: lines.append(f"  Usuarios en {ctx}: {', '.join(users[:15])}")
        groups = re.findall(r"(?:cn|name):\s*([^\n]+)", o)
        admin_groups = [g for g in groups if "admin" in g.lower()]
        if admin_groups: lines.append(f"  Grupos admin: {', '.join(admin_groups)}")
    return {"status": "ok", "result": "\n".join(lines)}


def snmp_enum(target: str, community: str = "public") -> dict[str, Any]:
    """Enumeración SNMP: comunidades abiertas, sistema, procesos, interfaces, usuarios."""
    lines = []
    # Test common community strings
    wl_path = "/usr/share/wordlists/snmp-strings.txt" if os.path.exists("/usr/share/wordlists/snmp-strings.txt") else "/dev/null"
    result = run_command(["onesixtyone", "-c", wl_path, target], description=f"onesixtyone {target}", timeout=60)
    out = (result.get("stdout") or "") + (result.get("stderr") or "")
    if target in out and "responding" in out:
        communities = re.findall(r"\[([^\]]+)\]", out)
        lines.append(f"Comunidades SNMP: {', '.join(communities[:5])}")
    # snmpwalk on system info
    for comm in [community] + (communities if 'communities' in dir() else []):
        result2 = run_command(["snmpwalk", "-v2c", "-c", comm, "-t", "5", target, "1.3.6.1.2.1.1"], description=f"snmpwalk sys {target} community={comm}", timeout=30)
        out2 = result2.get("stdout", "")
        if out2:
            sys_info = re.findall(r"SNMPv2-MIB::sys(?:Descr|Name|Location|Contact)\.[^=]+=\s*(.+)", out2)
            if sys_info: lines.append(f"  {comm}: {', '.join(sys_info[:5])}")
            break
    if not lines: lines.append("SNMP: sin comunidades abiertas o no responde")
    return {"status": "ok", "result": "\n".join(lines)}


def banner_grab(target: str, ports: str = "21,22,23,25,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017") -> dict[str, Any]:
    """Conexión TCP a puertos comunes para capturar banners de servicio."""
    results = []
    for port_str in ports.split(","):
        port = int(port_str.strip())
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if banner:
                results.append(f"  Puerto {port}: {banner[:150]}")
        except: pass
    if not results:
        return {"status": "ok", "result": "Banner grab: sin banners obtenidos (puertos filtrados o no responden)"}
    return {"status": "ok", "result": "Banners:\n" + "\n".join(results)}
