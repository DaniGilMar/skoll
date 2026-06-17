from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ToolPlugin(ABC):
    """Contrato unificado para todos los plugins de herramientas.

    Cada plugin implementa tres métodos:
    1. run(target) → ejecuta la herramienta, devuelve raw output
    2. parse(raw) → convierte output a dict estructurado
    3. normalize(parsed) → convierte a formato común del Evidence Store
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre corto de la herramienta (ej: 'nmap', 'hydra')."""

    @abstractmethod
    def run(self, target: str, **kwargs: Any) -> str:
        """Ejecuta la herramienta contra target. Devuelve raw output."""

    @abstractmethod
    def parse(self, raw: str) -> list[dict[str, Any]]:
        """Convierte raw output a lista de observaciones estructuradas.
        
        Cada observación es un dict con campos comunes:
        - host: str
        - port: int (opcional)
        - service: str (opcional)
        - protocol: str (opcional)
        - state: str (opcional)
        - flags: list[str] (opcional) — indicadores raw como "SMB_SIGNING_DISABLED"
        - raw_data: dict — campos específicos de la herramienta
        """

    @abstractmethod
    def normalize(self, parsed: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convierte observaciones al formato canónico del Evidence Store.
        
        Output garantizado:
        {
            "host": str,
            "tool": str,
            "observations": [
                {
                    "port": int | None,
                    "service": str,
                    "protocol": str,
                    "state": str,
                    "flags": [str],
                    "raw": dict,
                }
            ]
        }
        """
