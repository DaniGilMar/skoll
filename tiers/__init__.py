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
    gobuster_wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    whatweb: bool = True
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
            "hydra": self.hydra,
            "exploit": self.exploit,
        }


# Perfiles predefinidos
FAST = TierConfig(
    name="fast",
    description="Escaneo rápido: nmap top 1000 puertos + whatweb",
    nmap_flags="-sV -sC --min-rate 5000 -T5 --top-ports 1000",
    whatweb=True,
)

FULL = TierConfig(
    name="full",
    description="Escaneo completo: nmap full port scan + nikto + gobuster + whatweb",
    nmap_flags="-sV -sC --min-rate 3000 -T4 -p-",
    nikto=True,
    gobuster=True,
    whatweb=True,
    hydra=False,
)

STEALTH = TierConfig(
    name="stealth",
    description="Escaneo sigiloso: nmap lento + whatweb, sin scripts agresivos",
    nmap_flags="-sS -sV -T2 --top-ports 500",
    whatweb=True,
)

TIERS: dict[str, TierConfig] = {
    "fast": FAST,
    "full": FULL,
    "stealth": STEALTH,
}


def get_tier(name: str) -> TierConfig:
    return TIERS.get(name, FAST)
