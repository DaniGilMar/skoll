from __future__ import annotations

import re
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


# Only match real CTF flag formats — NO generic hex strings (nmap outputs hundreds of false positives)
FLAG_PATTERNS: list[tuple[str, str]] = [
    (r"flag\{[^}]+\}", "flag{}"),
    (r"CTF\{[^}]+\}", "CTF{}"),
    (r"THM\{[^}]+\}", "THM{}"),
    (r"HTB\{[^}]+\}", "HTB{}"),
    (r"FLAG\{[^}]+\}", "FLAG{}"),
]

# Strings that look like hashes/flags but are not
NEGATIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"AAAAB3NzaC1", re.IGNORECASE),        # SSH pubkey header
    re.compile(r"ssh-rsa\s+AAA", re.IGNORECASE),
    re.compile(r"ssh-ed25519\s+AAA", re.IGNORECASE),
    re.compile(r"ecdsa-sha2", re.IGNORECASE),
    re.compile(r"BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE KEY", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+", re.IGNORECASE),  # JWT tokens
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", re.IGNORECASE),     # timestamps
]

FLAG_MIN_LENGTH = 6
FLAG_MAX_LENGTH = 128


class FlagEngine(BaseEngine):
    name = "flag"
    description = "Flag detector — busca flags CTF en texto plano"
    capabilities = ["post-process"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        text = kwargs.get("text", "")
        source = kwargs.get("source", target)
        lines = text.split("\n")

        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        for lineno, line in enumerate(lines, 1):
            neg_match = any(neg.search(line) for neg in NEGATIVE_PATTERNS)
            if neg_match:
                continue

            for pattern, pname in FLAG_PATTERNS:
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    value = match.group()
                    if len(value) < FLAG_MIN_LENGTH or len(value) > FLAG_MAX_LENGTH:
                        continue
                    if not any(c.isdigit() for c in value) and len(value) < 12:
                        continue
                    if value in seen:
                        continue

                    # Check it's not part of a longer meaningless string
                    if not re.match(r"flag|CTF|THM|HTB|FLAG", value, re.IGNORECASE):
                        # For hex hashes, they should be bounded by non-hex chars
                        if re.match(r"^[a-f0-9]+$", value, re.IGNORECASE):
                            start = max(0, match.start() - 1)
                            end = min(len(line), match.end() + 1)
                            if start >= 0 and end <= len(line):
                                before = line[start:match.start()]
                                after = line[match.end():end]
                                if (not before or not before[-1].isalnum()) and \
                                   (not after or not after[0].isalnum()):
                                    pass  # good boundary
                                else:
                                    continue  # part of longer word, skip

                    seen.add(value)
                    findings.append({
                        "file_path": source,
                        "line_start": lineno,
                        "line_end": lineno,
                        "severity": "critical",
                        "title": f"Flag encontrada ({pname})",
                        "description": f"Valor: {value}",
                        "tool": "flag",
                        "rule_id": f"flag-{pname}",
                        "flag_value": value,
                    })

        return EngineResult(
            success=True,
            raw_output="\n".join(
                f"{f['title']}: {f['description']}" for f in findings
            ) if findings else "No flags found",
            findings=findings,
            summary=f"Flag scan: {len(findings)} matches" if findings else "No flags detected",
            error="",
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
