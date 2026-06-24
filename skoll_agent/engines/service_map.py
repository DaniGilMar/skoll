from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolBinding:
    tool_name: str
    params: dict[str, Any] = field(default_factory=dict)


# Map from service name (lowercase, as reported by nmap/naabu)
# to the list of tools that should be run when that service is detected.
SERVICE_MAP: dict[str, list[ToolBinding]] = {
    "http":          [ToolBinding("httpx"), ToolBinding("katana", {"depth": 1}), ToolBinding("gobuster", {"wordlist": "/usr/share/wordlists/dirb/common.txt", "timeout": 120})],
    "https":         [ToolBinding("httpx"), ToolBinding("katana", {"depth": 1}), ToolBinding("gobuster", {"wordlist": "/usr/share/wordlists/dirb/common.txt", "timeout": 120})],
    "http-proxy":    [ToolBinding("httpx"), ToolBinding("katana", {"depth": 1}), ToolBinding("gobuster", {"wordlist": "/usr/share/wordlists/dirb/common.txt", "timeout": 120})],
    "unknown":       [ToolBinding("httpx")],
    # Databases
    "mysql":         [ToolBinding("mysql", {"timeout": 30})],
    "ms-sql-s":      [ToolBinding("mysql", {"timeout": 30})],
    "postgresql":    [ToolBinding("postgres", {"timeout": 30})],
    "postgres":      [ToolBinding("postgres", {"timeout": 30})],
    "redis":         [ToolBinding("redis", {"timeout": 30})],
    "mongodb":       [ToolBinding("postgres", {"timeout": 30})],
    # File sharing
    "microsoft-ds":  [ToolBinding("smb"), ToolBinding("smbmap"), ToolBinding("enum4linux")],
    "netbios-ssn":   [ToolBinding("enum4linux")],
    "ftp":           [ToolBinding("ftp", {"timeout": 30})],
    # Auth services
    "ssh":           [ToolBinding("hydra", {"service": "ssh", "timeout": 60})],
    "telnet":        [ToolBinding("hydra", {"service": "telnet", "timeout": 60})],
}

# Map from port number to service name (for ports that nmap may not fingerprint).
PORT_MAP: dict[int, str] = {
    80: "http",
    443: "https",
    8080: "http",
    8443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    9200: "elasticsearch",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    139: "netbios-ssn",
    445: "microsoft-ds",
}


def tools_for_service(service: str) -> list[ToolBinding]:
    return SERVICE_MAP.get(service.lower(), [])


def tools_for_port(port: int) -> list[ToolBinding]:
    svc = PORT_MAP.get(port)
    if svc:
        return tools_for_service(svc)
    return []


def all_bindings() -> dict[str, list[ToolBinding]]:
    return dict(SERVICE_MAP)
