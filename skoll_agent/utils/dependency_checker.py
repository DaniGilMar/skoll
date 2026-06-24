from __future__ import annotations

import shutil
from typing import Optional


TOOL_ALIASES: dict[str, list[str]] = {
    "httpx": ["httpx-toolkit", "httpx"],
    "smb": ["smbclient"],
    "msfconsole": ["msfconsole"],
    "smbmap": ["smbmap"],
    "enum4linux": ["enum4linux"],
    "cve2msf": ["msfconsole"],
    "exploit_dispatcher": ["msfconsole"],
    "reporting": [],  # Python engine, no binary
    "ghostcat": [],  # Python engine (raw sockets), no binary
}

# Tools required for the pipeline to function.
# Tools marked optional=False must be present or the pipeline aborts early.
REQUIRED_TOOLS: dict[str, dict] = {
    "nmap":       {"optional": False, "hint": "apt install nmap"},
    "naabu":      {"optional": False, "hint": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    "httpx":      {"optional": False, "hint": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "katana":     {"optional": False, "hint": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    "nuclei":     {"optional": False, "hint": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "gobuster":   {"optional": True,  "hint": "apt install gobuster"},
    "ffuf":       {"optional": True,  "hint": "apt install ffuf"},
    "nikto":      {"optional": True,  "hint": "apt install nikto"},
    "sqlmap":     {"optional": True,  "hint": "apt install sqlmap"},
    "hydra":      {"optional": True,  "hint": "apt install hydra"},
    "whatweb":    {"optional": True,  "hint": "apt install whatweb"},
    "masscan":    {"optional": True,  "hint": "apt install masscan"},
    "smb":        {"optional": True,  "hint": "apt install smbclient"},
    "smbmap":     {"optional": True,  "hint": "pip install smbmap"},
    "enum4linux": {"optional": True,  "hint": "apt install enum4linux"},
    "msfconsole": {"optional": True,  "hint": "apt install metasploit-framework"},
    "cve2msf":    {"optional": True,  "hint": "msfconsole required"},
    "exploit_dispatcher": {"optional": True, "hint": "msfconsole required"},
    "reporting":  {"optional": True,  "hint": "pip install weasyprint"},
}


class DependencyChecker:
    """Scan PATH at startup and report availability of every tool."""

    def __init__(self) -> None:
        self._cache: Optional[dict[str, Optional[str]]] = None

    def check_all(self) -> dict[str, Optional[str]]:
        if self._cache is not None:
            return self._cache
        result: dict[str, Optional[str]] = {}
        for name, info in REQUIRED_TOOLS.items():
            candidates = TOOL_ALIASES.get(name, [name])
            found: Optional[str] = None
            for c in candidates:
                p = shutil.which(c)
                if p:
                    found = p
                    break
            result[name] = found
            if not found and not info["optional"]:
                msg = f"  MISSING {name}: {info['hint']}"
                print(msg)
        self._cache = result
        return result

    def missing(self) -> list[str]:
        return [n for n, p in self.check_all().items() if p is None]

    def missing_optional(self) -> list[str]:
        return [
            n for n, p in self.check_all().items()
            if p is None and REQUIRED_TOOLS.get(n, {}).get("optional", True)
        ]

    def missing_required(self) -> list[str]:
        return [
            n for n, p in self.check_all().items()
            if p is None and not REQUIRED_TOOLS.get(n, {}).get("optional", False)
        ]

    def available(self) -> list[str]:
        return [n for n, p in self.check_all().items() if p is not None]

    def health_summary(self) -> str:
        all_tools = self.check_all()
        total = len(all_tools)
        ok = sum(1 for p in all_tools.values() if p is not None)
        missing = total - ok
        status = "✅" if missing == 0 else f"⚠️ ({missing} missing)"
        return f"Dependencies: {ok}/{total} available {status}"
