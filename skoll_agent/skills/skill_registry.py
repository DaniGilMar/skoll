from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

SKILLS_DIR = Path(__file__).resolve().parent

PHASE_SKILL_MAP: dict[str, list[str]] = {
    "RECON": ["reconnaissance", "technologies", "protocols"],
    "ENUM": ["reconnaissance", "technologies", "protocols"],
    "VALIDATE": ["vulnerabilities"],
    "ANALYZE": ["vulnerabilities", "technologies", "payloads"],
    "EXPLOIT": ["payloads", "postexploit", "vulnerabilities"],
    "CHAIN": ["postexploit", "frameworks", "vulnerabilities"],
    "REPORT": [],
    "COMPLETE": [],
}


class Skill:
    def __init__(self, name: str, file_path: Path, category: str, description: str = ""):
        self.name = name
        self.file_path = file_path
        self.category = category
        self.description = description
        self._content: str | None = None

    @property
    def content(self) -> str:
        if self._content is None:
            try:
                self._content = self.file_path.read_text(encoding="utf-8")
            except Exception:
                self._content = ""
        return self._content

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
        }


class SkillRegistry:
    def __init__(self, skills_dir: str | Path | None = None):
        self.skills_dir = Path(skills_dir) if skills_dir else SKILLS_DIR
        self.skills: dict[str, Skill] = {}
        self.keywords: dict[str, str] = {}
        self.loaded = False

    def load_all(self) -> None:
        self.skills = {}
        self.keywords = {}

        for md_file in self.skills_dir.rglob("*.md"):
            category = md_file.parent.name
            name = md_file.stem
            description = self._extract_description(md_file)
            skill = Skill(name=name, file_path=md_file, category=category, description=description)
            self.skills[name] = skill

        keywords_path = self.skills_dir / "skills.json"
        if keywords_path.exists():
            try:
                data = json.loads(keywords_path.read_text(encoding="utf-8"))
                raw = data.get("skill_keywords", data)
                if isinstance(raw, dict):
                    self.keywords = {k.lower(): v for k, v in raw.items()}
            except Exception:
                pass

        self.loaded = True

    def get_skill(self, name: str) -> Skill | None:
        if not self.loaded:
            self.load_all()
        return self.skills.get(name)

    def get_skills_for_phase(self, phase: str) -> list[Skill]:
        if not self.loaded:
            self.load_all()
        phase_upper = phase.upper()
        categories = PHASE_SKILL_MAP.get(phase_upper, [])
        result = []
        for skill in self.skills.values():
            if skill.category in categories:
                result.append(skill)
        return result

    def get_skills_by_keyword(self, text: str) -> list[Skill]:
        if not self.loaded:
            self.load_all()
        text_lower = text.lower()
        matched: list[Skill] = []
        for keyword, skill_path in self.keywords.items():
            if keyword in text_lower:
                name = Path(skill_path).stem
                skill = self.skills.get(name)
                if skill and skill not in matched:
                    matched.append(skill)
        return matched

    def format_skills_block(self, skills: list[Skill], max_chars: int = 6000) -> str:
        if not skills:
            return ""
        parts = ["<available_skills>"]
        total = 0
        for skill in skills:
            header = f"\n## {skill.name} ({skill.category})"
            if total + len(header) + 200 > max_chars:
                break
            parts.append(header)
            content = skill.content
            if total + len(content) > max_chars:
                content = content[: max_chars - total - len(header)]
            parts.append(content)
            total += len(header) + len(content)
        parts.append("\n</available_skills>")
        return "\n".join(parts)

    def skill_context_for_phase(self, phase: str, extra_keywords: str = "", max_chars: int = 4000) -> str:
        skills = self.get_skills_for_phase(phase)
        if extra_keywords:
            keyword_skills = self.get_skills_by_keyword(extra_keywords)
            for ks in keyword_skills:
                if ks not in skills:
                    skills.append(ks)
        return self.format_skills_block(skills, max_chars=max_chars)

    @staticmethod
    def _extract_description(path: Path) -> str:
        try:
            content = path.read_text(encoding="utf-8")
            match = re.search(r"^description:\s*(.+)$", content, re.MULTILINE)
            if match:
                return match.group(1).strip().strip('"').strip("'")
        except Exception:
            pass
        return ""


_registry: SkillRegistry | None = None


def get_registry() -> SkillRegistry:
    global _registry
    if _registry is None:
        _registry = SkillRegistry()
        _registry.load_all()
    return _registry
