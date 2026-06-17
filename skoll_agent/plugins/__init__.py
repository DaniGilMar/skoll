from __future__ import annotations

from typing import Any

from skoll_agent.plugins.base import ToolPlugin

_registry: dict[str, type[ToolPlugin]] = {}


def register_plugin(name: str, cls: type[ToolPlugin]) -> None:
    _registry[name] = cls


def get_plugin(name: str) -> type[ToolPlugin]:
    if name not in _registry:
        raise KeyError(f"Plugin '{name}' not registered. Available: {list(_registry.keys())}")
    return _registry[name]


def list_plugins() -> dict[str, type[ToolPlugin]]:
    return dict(_registry)
