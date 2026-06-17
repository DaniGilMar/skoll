from __future__ import annotations

import os
import shutil
from typing import Any


def check_wordlists() -> list[dict[str, Any]]:
    paths = [
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/seclists/Passwords/darkweb2017-top100.txt",
    ]
    results = []
    for p in paths:
        results.append({
            "path": p, "exists": os.path.exists(p),
            "size": os.path.getsize(p) if os.path.exists(p) else 0,
        })
    return results


def check_kali_tools() -> list[dict[str, Any]]:
    tools = [
        "nmap", "masscan", "hydra", "sqlmap", "gobuster",
        "nikto", "whatweb", "davtest", "msfconsole", "searchsploit",
    ]
    results = []
    for tool in tools:
        path = shutil.which(tool)
        results.append({"tool": tool, "found": path is not None, "path": path or ""})
    return results


def check_llm_providers() -> list[dict[str, Any]]:
    results = []
    if os.environ.get("GROQ_API_KEY"):
        results.append({"provider": "Groq", "status": "ok", "models": 8})
    else:
        results.append({"provider": "Groq", "status": "missing API key", "models": 0})
    if os.environ.get("OPENROUTER_API_KEY"):
        results.append({"provider": "OpenRouter", "status": "ok", "models": 4})
    else:
        results.append({"provider": "OpenRouter", "status": "missing API key", "models": 0})
    if os.environ.get("GOOGLE_API_KEY"):
        results.append({"provider": "Google AI Studio", "status": "ok", "models": 1})
    else:
        results.append({"provider": "Google AI Studio", "status": "missing API key", "models": 0})
    return results


def run_checks() -> dict[str, Any]:
    return {
        "wordlists": check_wordlists(),
        "kali_tools": check_kali_tools(),
        "llm_providers": check_llm_providers(),
    }
