from __future__ import annotations

"""
Engines de Skoll — plugins para herramientas de pentest.

Cada engine implementa: run(target) -> list[Observation]
"""

from pathlib import Path

ENGINES_DIR = Path(__file__).parent
