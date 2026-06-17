from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skoll_agent.skills.base_skill import BaseSkill


_skills: dict[str, type[BaseSkill]] = {}


def register_skill(name: str, skill_cls: type[BaseSkill]) -> None:
    _skills[name] = skill_cls


def get_skill(name: str) -> type[BaseSkill]:
    if name not in _skills:
        msg = f"Skill '{name}' not found. Available: {list(_skills.keys())}"
        raise KeyError(msg)
    return _skills[name]


def list_skills() -> list[str]:
    return list(_skills.keys())


def get_all_skills() -> dict[str, type[BaseSkill]]:
    return dict(_skills)
