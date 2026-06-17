from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skoll_agent.engines.base_engine import BaseEngine


_engines: dict[str, type[BaseEngine]] = {}


def register_engine(name: str, engine_cls: type[BaseEngine]) -> None:
    _engines[name] = engine_cls


def get_engine(name: str) -> type[BaseEngine]:
    if name not in _engines:
        msg = f"Engine '{name}' not found. Available: {list(_engines.keys())}"
        raise KeyError(msg)
    return _engines[name]


def list_engines() -> dict[str, str]:
    return {name: cls.description for name, cls in _engines.items()}


def get_engines_by_capability(capability: str) -> list[type[BaseEngine]]:
    return [cls for cls in _engines.values() if capability in cls.capabilities]


ENGINES_HELP = """## HERRAMIENTAS DISPONIBLES EN EL SISTEMA

{engines_desc}

Usa `run_tool` para ejecutar cualquiera de estas herramientas. Los resultados se agregarán automáticamente al estado del agente.
"""
