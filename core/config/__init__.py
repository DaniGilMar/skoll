from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SkollConfig:
    """Configuración unificada de Skoll.
    
    Orden de precedencia:
    1. Variables de entorno
    2. Archivo .env
    3. Defaults
    """

    # Proveedores LLM
    groq_api_key: str = ""
    openrouter_api_key: str = ""
    google_api_key: str = ""
    default_provider: str = "groq"

    # Directorios
    evidence_db: str = "/tmp/skoll_evidence.db"
    memory_db: str = "/tmp/skoll_memory.db"
    reports_dir: str = str(Path.home() / "Documentos" / "Skoll_Informes")
    sessions_dir: str = str(Path.home() / ".skoll" / "sessions")

    # Pipeline
    max_iterations: int = 3
    phase_timeout: int = 600
    
    # Web
    web_host: str = "0.0.0.0"
    web_port: int = 8000

    @classmethod
    def load(cls) -> SkollConfig:
        """Carga configuración desde entorno + .env."""
        env_path = Path("/opt/skoll/.env")
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())

        return cls(
            groq_api_key=os.getenv("GROQ_API_KEY", ""),
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY", ""),
            google_api_key=os.getenv("GOOGLE_API_KEY", ""),
            default_provider=os.getenv("AI_PROVIDER", "groq"),
            evidence_db=os.getenv("SKOLL_EVIDENCE_DB", "/tmp/skoll_evidence.db"),
            memory_db=os.getenv("SKOLL_MEMORY_DB", "/tmp/skoll_memory.db"),
            reports_dir=os.getenv("SKOLL_REPORTS_DIR", str(Path.home() / "Documentos" / "Skoll_Informes")),
            sessions_dir=os.getenv("SKOLL_SESSIONS_DIR", str(Path.home() / ".skoll" / "sessions")),
        )

    @property
    def has_groq(self) -> bool:
        return bool(self.groq_api_key)

    @property
    def has_openrouter(self) -> bool:
        return bool(self.openrouter_api_key)

    @property
    def has_google(self) -> bool:
        return bool(self.google_api_key)


_config: SkollConfig | None = None


def get_config() -> SkollConfig:
    global _config
    if _config is None:
        _config = SkollConfig.load()
    return _config
