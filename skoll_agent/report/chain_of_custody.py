from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any


class ChainOfCustody:
    """Registro inmutable de todas las acciones realizadas durante la auditoría.

    Cada entrada se registra con timestamp, hash del contenido previo,
    y hash de archivos de evidencia para cadena de custodia.
    """

    def __init__(self, target: str, session_id: str = ""):
        self.target = target
        self.session_id = session_id
        self.entries: list[dict[str, Any]] = []
        self.previous_hash = "0" * 64
        self._log_dir = os.path.expanduser("~/.skoll/custody")
        os.makedirs(self._log_dir, exist_ok=True)

    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def log(
        self,
        action: str,
        tool: str = "",
        target: str = "",
        params: dict[str, Any] | None = None,
        result_summary: str = "",
        evidence_files: list[str] | None = None,
        severity: str = "info",
    ) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unix_ts": time.time(),
            "action": action,
            "tool": tool,
            "target": target or self.target,
            "params": params or {},
            "result_summary": result_summary[:500],
            "severity": severity,
            "previous_hash": self.previous_hash,
        }

        # Hash de archivos de evidencia
        file_hashes: dict[str, str] = {}
        if evidence_files:
            for fpath in evidence_files:
                if os.path.exists(fpath):
                    with open(fpath, "rb") as f:
                        file_hashes[fpath] = hashlib.sha256(f.read()).hexdigest()
        entry["evidence_files"] = file_hashes

        serialized = json.dumps(entry, sort_keys=True, default=str)
        entry_hash = self._hash(serialized)
        entry["entry_hash"] = entry_hash
        self.previous_hash = entry_hash

        self.entries.append(entry)

        # Persistir a disco
        self._save()

        return entry_hash

    def log_tool_result(self, tool: str, target: str, extra: dict[str, Any] | None, result: Any) -> str:
        summary = ""
        if hasattr(result, "summary"):
            summary = result.summary
        elif isinstance(result, dict):
            summary = result.get("summary", "")
        return self.log(
            action="tool_execution",
            tool=tool, target=target, params=extra,
            result_summary=str(summary)[:500],
            severity="info",
        )

    def log_finding(self, finding: Any) -> str:
        title = ""
        severity = "info"
        if hasattr(finding, "title"):
            title = finding.title
            severity = getattr(finding, "severity", "info")
        elif isinstance(finding, dict):
            title = finding.get("title", "")
            severity = finding.get("severity", "info")
        return self.log(
            action="finding",
            tool=getattr(finding, "tool", "") if hasattr(finding, "tool") else finding.get("tool", ""),
            result_summary=title,
            severity=str(severity),
        )

    def log_phase(self, phase: str, status: str, summary: str = "") -> str:
        return self.log(
            action=f"phase_{phase}",
            result_summary=summary,
            severity="info" if status == "completed" else "warning" if status == "skipped" else "error",
        )

    def log_flag(self, flag_value: str, source: str) -> str:
        return self.log(
            action="flag_found",
            result_summary=f"Flag: {flag_value} (from {source})",
            severity="high",
        )

    def export_json(self) -> str:
        return json.dumps({
            "target": self.target,
            "session_id": self.session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_actions": len(self.entries),
            "last_hash": self.previous_hash,
            "entries": self.entries,
        }, indent=2, default=str)

    def export_markdown(self) -> str:
        lines = [
            "# Chain of Custody — Skoll Security Assessment",
            f"**Target:** {self.target}",
            f"**Session:** {self.session_id}",
            f"**Total Actions:** {len(self.entries)}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            "",
            "---",
        ]
        for idx, entry in enumerate(self.entries, 1):
            ts = entry.get("timestamp", "?")
            action = entry.get("action", "?")
            tool = entry.get("tool", "")
            target = entry.get("target", "")
            summary = entry.get("result_summary", "")[:100]
            sev = entry.get("severity", "info")
            lines.append(f"### {idx}. [{sev.upper()}] {action}")
            lines.append(f"- **Time:** {ts}")
            if tool:
                lines.append(f"- **Tool:** {tool}")
            if target:
                lines.append(f"- **Target:** {target}")
            if summary:
                lines.append(f"- **Summary:** {summary}")
            lines.append(f"- **Hash:** `{entry.get('entry_hash', '')[:16]}...`")
            if entry.get("evidence_files"):
                for fpath, fhash in entry["evidence_files"].items():
                    lines.append(f"- **Evidence:** `{fpath}` → `{fhash[:16]}...`")
            lines.append("")
        lines.append(f"---\n*Integrity chain: last hash = `{self.previous_hash[:16]}...`*")
        return "\n".join(lines)

    def verify_integrity(self) -> bool:
        prev = "0" * 64
        for entry in self.entries:
            stored_hash = entry.get("entry_hash", "")
            serialized_no_hash = json.dumps(
                {k: v for k, v in entry.items() if k != "entry_hash"},
                sort_keys=True, default=str,
            )
            computed = self._hash(serialized_no_hash)
            if computed != stored_hash:
                return False
            expected_prev = entry.get("previous_hash", "")
            if expected_prev != prev:
                return False
            prev = stored_hash
        return True

    def _save(self) -> None:
        safe_target = self.target.replace(".", "_").replace(":", "_")
        path = os.path.join(self._log_dir, f"custody_{safe_target}_{self.session_id or 'current'}.json")
        try:
            with open(path, "w") as f:
                f.write(self.export_json())
        except Exception:
            pass
