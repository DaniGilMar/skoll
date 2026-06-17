from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from skoll.utils import EXCLUDE_DIRS, INTERESTING_EXTENSIONS, leer_archivo


@dataclass
class FileInfo:
    path: str
    relative_path: str
    extension: str
    size: int
    lines: int
    risk_score: float = 0.0
    risk_indicators: list[str] = field(default_factory=list)


@dataclass
class ProjectContext:
    root_path: str
    files: list[FileInfo] = field(default_factory=list)
    structure: str = ""
    total_files: int = 0
    total_lines: int = 0
    total_size: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    summary: str = ""


RISK_PATTERNS: dict[str, list[str]] = {
    "network": [r"(?i)(requests|urllib|socket|http|curl|fetch|axios)", r"api\.(get|post|put|delete)"],
    "database": [r"(?i)(sqlite|mysql|postgres|mongodb|redis|execute|query|select\s+\*|cursor)"],
    "exec": [r"(?i)(eval|exec|compile|os\.system|subprocess|popen|spawn)"],
    "file_ops": [r"(?i)(open\(|write\(|chmod|chown|remove\(|unlink\(|shutil)"],
    "crypto": [r"(?i)(hashlib|cryptography|encrypt|decrypt|md5|sha1)"],
    "secrets": [r"(?i)(api_key|secret|password|token|credential|auth_token)", r"(?i)(-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE)"],
    "injection": [r"(?i)(f\"|\"\\s*\+\s*|format\(.*\$|\.format\(.*user)", r"(?i)(sql|ldap|command|path)\s*injection"],
    "auth": [r"(?i)(login|authenticate|session|cookie|jwt|oauth|saml)"],
}


def _compute_risk_score(content: str, file_info: FileInfo) -> tuple[float, list[str]]:
    score = 0.0
    indicators: list[str] = []
    for category, patterns in RISK_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if matches:
                score += len(matches) * 1.5 if category in ("exec", "injection", "secrets") else len(matches) * 0.5
                if len(matches) > 0 and category not in [x.split(":")[0] for x in indicators]:
                    indicators.append(f"{category}: {len(matches)} matches")
    return round(score, 1), indicators


def _index_single_file(file_path: str, ctx: ProjectContext, max_chars: int) -> int:
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in INTERESTING_EXTENSIONS and file_path.lower() != "dockerfile":
        return 0
    content = leer_archivo(file_path)
    if not content.strip():
        return 0
    total_chars = len(content)
    lines = content.count("\n") + 1
    rel_path = os.path.basename(file_path)
    finfo = FileInfo(
        path=file_path,
        relative_path=rel_path,
        extension=ext,
        size=os.path.getsize(file_path),
        lines=lines,
    )
    risk_score, indicators = _compute_risk_score(content, finfo)
    finfo.risk_score = risk_score
    finfo.risk_indicators = indicators
    ctx.files.append(finfo)
    ctx.total_files += 1
    ctx.total_lines += lines
    ctx.total_size += finfo.size
    lang = ext.lstrip(".") or "dockerfile"
    ctx.languages[lang] = ctx.languages.get(lang, 0) + 1
    return total_chars


def index_project(project_path: str, max_chars: int = 200000) -> ProjectContext:
    ctx = ProjectContext(root_path=os.path.abspath(project_path))
    total_chars = 0
    structure_lines: list[str] = []

    if os.path.isfile(project_path):
        total_chars = _index_single_file(project_path, ctx, max_chars)
        ctx.root_path = os.path.dirname(os.path.abspath(project_path))
        basename = os.path.basename(project_path)
        ctx.structure = f"  {basename}  ({ctx.total_lines} lines)"
        ctx.summary = (
            f"Project: {basename} (in {ctx.root_path})\n"
            f"Files: {ctx.total_files} | Lines: {ctx.total_lines}\n"
            f"Risk: [{ctx.files[0].risk_score:.1f}] {basename}\n"
        )
        return ctx

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        if any(ex in root.split(os.sep) for ex in EXCLUDE_DIRS if ex.startswith(".")):
            continue

        rel_dir = os.path.relpath(root, project_path)
        if rel_dir == ".":
            structure_lines.append("/")
        else:
            structure_lines.append(f"  {rel_dir}/")

        for file in sorted(files):
            ext = os.path.splitext(file)[1].lower()
            if not ext and file.lower() != "dockerfile":
                continue
            if ext not in INTERESTING_EXTENSIONS and file.lower() != "dockerfile":
                continue
            if ext in (".md",):
                continue

            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, project_path)
            size = os.path.getsize(filepath)

            if total_chars >= max_chars:
                structure_lines.append(f"    {file} (truncated)")
                continue

            content = leer_archivo(filepath)
            total_chars += len(content)
            lines = content.count("\n") + 1

            finfo = FileInfo(
                path=filepath,
                relative_path=rel_path,
                extension=ext,
                size=size,
                lines=lines,
            )
            risk_score, indicators = _compute_risk_score(content, finfo)
            finfo.risk_score = risk_score
            finfo.risk_indicators = indicators

            ctx.files.append(finfo)
            ctx.total_files += 1
            ctx.total_lines += lines
            ctx.total_size += size

            lang = ext.lstrip(".") or "dockerfile"
            ctx.languages[lang] = ctx.languages.get(lang, 0) + 1

            structure_lines.append(f"    {file}  ({lines} lines, risk: {risk_score})")

            if risk_score > 5:
                for ind in indicators:
                    structure_lines.append(f"      → {ind}")

    ctx.structure = "\n".join(structure_lines)
    ctx.files.sort(key=lambda f: f.risk_score, reverse=True)

    high_risk = [f for f in ctx.files if f.risk_score > 5]
    lang_summary = ", ".join(f"{k}: {v}" for k, v in sorted(ctx.languages.items(), key=lambda x: -x[1]))

    ctx.summary = (
        f"Project: {project_path}\n"
        f"Files: {ctx.total_files} | Lines: {ctx.total_lines} | Size: {round(ctx.total_size / 1024, 1)} KB\n"
        f"Languages: {lang_summary}\n"
        f"High-risk files: {len(high_risk)}\n"
        f"Risk distribution:\n"
    )
    for f in ctx.files[:10]:
        ctx.summary += f"  [{f.risk_score:4.1f}] {f.relative_path}\n"

    return ctx


def context_to_prompt(ctx: ProjectContext, max_files: int = 20) -> str:
    lines = [ctx.summary, "\n### Project Structure:\n"]
    for f in ctx.files[:max_files]:
        flags = ""
        if f.risk_score > 10:
            flags = " ⚠️ CRITICAL"
        elif f.risk_score > 5:
            flags = " ⚠️ HIGH"
        indicators = ", ".join(f.risk_indicators[:3]) if f.risk_indicators else ""
        lines.append(f"  [{f.risk_score:4.1f}] {f.relative_path} ({f.lines} lines){flags}")
        if indicators:
            lines.append(f"         └─ {indicators}")
    return "\n".join(lines)
