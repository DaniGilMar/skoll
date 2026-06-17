from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TierConfig:
    """Perfil de análisis: define qué engines ejecutar y con qué flags."""
    name: str = ""
    description: str = ""
    nmap_flags: str = "-sV -sC --min-rate 3000 -T4 --top-ports 1000"
    nmap_script: str = ""
    nikto: bool = False
    gobuster: bool = False
    gobuster_wordlist: str = ""
    whatweb: bool = True
    sqlmap: bool = False
    hydra: bool = False
    exploit: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "nmap_flags": self.nmap_flags,
            "nikto": self.nikto,
            "gobuster": self.gobuster,
            "whatweb": self.whatweb,
            "sqlmap": self.sqlmap,
            "hydra": self.hydra,
            "exploit": self.exploit,
        }


# Perfiles predefinidos
FAST = TierConfig(
    name="fast",
    description="Escaneo rápido: nmap + whatweb + sqlmap",
    nmap_flags="-sV -sC --min-rate 5000 -T5 --top-ports 1000",
    whatweb=True,
    sqlmap=True,
)

FULL = TierConfig(
    name="full",
    description="Escaneo completo: nmap + nikto + gobuster + whatweb + sqlmap",
    nmap_flags="-sV -sC --min-rate 3000 -T4 -p-",
    nikto=True,
    gobuster=True,
    whatweb=True,
    sqlmap=True,
)

STEALTH = TierConfig(
    name="stealth",
    description="Escaneo sigiloso: nmap lento + whatweb + sqlmap, sin scripts agresivos",
    nmap_flags="-sS -sV -T2 --top-ports 500",
    whatweb=True,
    sqlmap=True,
)

TIERS: dict[str, TierConfig] = {
    "fast": FAST,
    "full": FULL,
    "stealth": STEALTH,
}


def get_tier(name: str) -> TierConfig:
    return TIERS.get(name, FAST)
