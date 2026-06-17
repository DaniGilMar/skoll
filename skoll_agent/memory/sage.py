from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SAGE_DIR = Path.home() / ".skoll" / "sage"
SAGE_DIR.mkdir(parents=True, exist_ok=True)


def _target_key(target: str) -> str:
    return target.replace(":", "_").replace("/", "_").replace(".", "_")[:64]


def store_scan_result(
    target: str,
    phase: str,
    findings: list[dict[str, Any]],
    ports: list[dict[str, Any]],
    summary: str,
) -> None:
    key = _target_key(target)
    filepath = SAGE_DIR / f"{key}.json"

    existing: dict[str, Any] = {"sessions": []}
    if filepath.exists():
        try:
            existing = json.loads(filepath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {"sessions": []}

    session = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "findings_count": len(findings),
        "ports": ports[:20],
        "findings": findings[-30:],
        "summary": summary[:500],
    }
    existing.setdefault("sessions", []).append(session)
    existing["sessions"] = existing["sessions"][-10:]

    existing["last_updated"] = datetime.now(timezone.utc).isoformat()
    existing["target"] = target
    existing["total_findings"] = sum(s["findings_count"] for s in existing["sessions"])

    filepath.write_text(json.dumps(existing, indent=2, default=str), encoding="utf-8")


def recall_target(target: str) -> dict[str, Any]:
    key = _target_key(target)
    filepath = SAGE_DIR / f"{key}.json"
    if not filepath.exists():
        return {}
    try:
        return json.loads(filepath.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def recall_context_for_scan(target: str) -> list[dict[str, Any]]:
    data = recall_target(target)
    if not data:
        return []

    sessions = data.get("sessions", [])
    if not sessions:
        return []

    context: list[dict[str, Any]] = []
    for s in sessions[-3:]:
        context.append({
            "timestamp": s.get("timestamp", ""),
            "phase": s.get("phase", ""),
            "findings_count": s.get("findings_count", 0),
            "summary": s.get("summary", "")[:200],
            "ports": s.get("ports", []),
        })

    return context


def format_sage_context(target: str) -> str:
    context = recall_context_for_scan(target)
    if not context:
        return ""

    lines = [
        f"## SAGE Memory — Historical Context for {target}",
        f"Previous scans: {len(context)} session(s)",
    ]
    for i, s in enumerate(context, 1):
        lines.append(f"\n### Session {i} ({s.get('phase', '?')})")
        lines.append(f"- Date: {s.get('timestamp', '?')[:19]}")
        lines.append(f"- Findings: {s.get('findings_count', 0)}")
        ports = s.get("ports", [])
        if ports:
            port_strs = []
            for p in ports[:5]:
                port_strs.append(f'{p.get("port","?")}/{p.get("protocol","?")} {p.get("service","?")}')
            lines.append(f"- Ports: {', '.join(port_strs)}")
        summary = s.get("summary", "")
        if summary:
            lines.append(f"- Summary: {summary[:200]}")

    return "\n".join(lines)


def _extract_features(data: dict[str, Any]) -> dict[str, set[str]]:
    """Extrae características para búsqueda por similitud."""
    features: dict[str, set[str]] = {
        "ports": set(),
        "services": set(),
        "protocols": set(),
        "findings": set(),
        "technologies": set(),
    }
    for s in data.get("sessions", []):
        for p in s.get("ports", []):
            port_str = str(p.get("port", ""))
            if port_str:
                features["ports"].add(port_str)
            svc = p.get("service", "")
            if svc:
                features["services"].add(svc.lower())
            proto = p.get("protocol", "")
            if proto:
                features["protocols"].add(proto.lower())
        for f in s.get("findings", []):
            title = f.get("title", "")
            if title:
                features["findings"].add(title.lower())
            tech = f.get("technologies", [])
            if isinstance(tech, list):
                for t in tech:
                    features["technologies"].add(t.lower())
            elif isinstance(tech, str):
                features["technologies"].add(tech.lower())
    return features


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def find_similar_targets(
    target: str,
    top_n: int = 5,
    min_similarity: float = 0.1,
) -> list[dict[str, Any]]:
    """Busca targets similares usando Jaccard similarity sobre puertos/servicios/hallazgos."""
    current = recall_target(target)
    if not current:
        return []

    current_features = _extract_features(current)

    similar: list[dict[str, Any]] = []
    for fpath in SAGE_DIR.glob("*.json"):
        if _target_key(target) in fpath.name:
            continue
        try:
            other_data = json.loads(fpath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        other_features = _extract_features(other_data)
        other_target = other_data.get("target", fpath.stem)

        port_sim = _jaccard(current_features["ports"], other_features["ports"])
        svc_sim = _jaccard(current_features["services"], other_features["services"])
        findings_sim = _jaccard(current_features["findings"], other_features["findings"])
        tech_sim = _jaccard(current_features["technologies"], other_features["technologies"])

        # Weighted average: ports matter most, then services, then findings
        combined = (
            port_sim * 0.35 + svc_sim * 0.30 +
            findings_sim * 0.20 + tech_sim * 0.15
        )

        if combined >= min_similarity:
            similar.append({
                "target": other_target,
                "similarity": round(combined, 3),
                "sessions": len(other_data.get("sessions", [])),
                "last_updated": other_data.get("last_updated", ""),
                "total_findings": other_data.get("total_findings", 0),
                "port_similarity": round(port_sim, 3),
                "service_similarity": round(svc_sim, 3),
            })

    similar.sort(key=lambda x: x["similarity"], reverse=True)
    return similar[:top_n]


def format_similar_targets(target: str) -> str:
    similar = find_similar_targets(target)
    if not similar:
        return ""

    lines = ["## SAGE — Similar Targets Found", ""]
    for s in similar:
        lines.append(
            f"- **{s['target']}** (sim={s['similarity']:.1%}) "
            f"- {s['sessions']} sessions, {s['total_findings']} findings"
        )
    return "\n".join(lines)


def clear_target(target: str) -> None:
    key = _target_key(target)
    filepath = SAGE_DIR / f"{key}.json"
    if filepath.exists():
        filepath.unlink()
