from __future__ import annotations

import os as _os

WORDLISTS_BASE = "/usr/share/wordlists"

WORDLISTS: dict[str, str] = {
    # Passwords
    "passwords_fast": f"{WORDLISTS_BASE}/fasttrack.txt",
    "passwords_common": f"{WORDLISTS_BASE}/rockyou.txt",
    "passwords_top100": f"{WORDLISTS_BASE}/seclists/Passwords/Most-Popular-Letter-Passes.txt",

    # Usernames
    "usernames": f"{WORDLISTS_BASE}/seclists/Usernames/cirt-default-usernames.txt",
    "usernames_fast": f"{WORDLISTS_BASE}/seclists/Usernames/top-usernames-shortlist.txt",

    # Web directory busting
    "web_directories_common": f"{WORDLISTS_BASE}/dirb/common.txt",
    "web_directories_medium": f"{WORDLISTS_BASE}/dirbuster/directory-list-2.3-medium.txt",

    # API discovery
    "kiterunner_routes": f"{WORDLISTS_BASE}/kiterunner/routes-large.kite",
}

FALLBACKS: dict[str, str] = {
    "passwords_top100": "passwords_common",
    "passwords_common": "passwords_fast",
    "passwords_fast": "passwords_common",
    "kiterunner_routes": "web_directories_medium",
    "usernames": "usernames_fast",
}


def get_wordlist(key: str) -> str:
    path = WORDLISTS.get(key, "")
    if path and _os.path.exists(path):
        return path
    fallback_key = FALLBACKS.get(key)
    if fallback_key:
        return get_wordlist(fallback_key)
    return WORDLISTS.get("passwords_fast", "")


def resolve_wordlist(key: str, custom_path: str | None = None) -> str:
    if custom_path:
        return custom_path
    return get_wordlist(key)


# Tool → wordlist key mapping
TOOL_WORDLISTS: dict[str, dict[str, str]] = {
    "hydra": {
        "ssh": f"{WORDLISTS_BASE}/fasttrack.txt",
        "ftp": f"{WORDLISTS_BASE}/fasttrack.txt",
        "telnet": f"{WORDLISTS_BASE}/fasttrack.txt",
        "mysql": f"{WORDLISTS_BASE}/rockyou.txt",
        "postgresql": f"{WORDLISTS_BASE}/rockyou.txt",
        "imap": f"{WORDLISTS_BASE}/rockyou.txt",
        "pop3": f"{WORDLISTS_BASE}/rockyou.txt",
        "smtp": f"{WORDLISTS_BASE}/fasttrack.txt",
    },
    "gobuster": f"{WORDLISTS_BASE}/dirbuster/directory-list-2.3-medium.txt",
    "ffuf": f"{WORDLISTS_BASE}/dirb/common.txt",
    "hashcat": f"{WORDLISTS_BASE}/rockyou.txt",
    "john": f"{WORDLISTS_BASE}/rockyou.txt",
    "kiterunner": f"{WORDLISTS_BASE}/kiterunner/routes-large.kite",
    "msfconsole": f"{WORDLISTS_BASE}/fasttrack.txt",
}


def get_tool_wordlist(tool_name: str, service: str | None = None) -> str:
    mapping = TOOL_WORDLISTS.get(tool_name, "")
    if isinstance(mapping, dict):
        path = mapping.get(service or "", "")
        if path and _os.path.exists(path):
            return path
        for fallback in mapping.values():
            if _os.path.exists(fallback):
                return fallback
        return get_wordlist("passwords_fast")
    if isinstance(mapping, str):
        if _os.path.exists(mapping):
            return mapping
        return get_wordlist("web_directories_common")
    return get_wordlist("passwords_fast")


def check_wordlists() -> list[dict[str, str | bool | int]]:
    results = []
    for name, path in WORDLISTS.items():
        exists = _os.path.exists(path)
        size = _os.path.getsize(path) if exists else 0
        results.append({"name": name, "path": path, "exists": exists, "size": size})
    return results
