from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.logging import get_logger

logger = get_logger()


class ReportGenerator:
    """Generador de informes — output a directorio configurable."""

    def __init__(self, campaign_id: str, reports_dir: str = ""):
        self.campaign_id = campaign_id
        if not reports_dir:
            from core.config import get_config
            reports_dir = get_config().reports_dir
        self._base = Path(reports_dir) / campaign_id

    def generate(
        self,
        findings: list[dict[str, Any]],
        campaign_summary: dict[str, Any] | None = None,
        llm_analysis: str = "",
        judge_verdict: str = "",
        scan_target: str = "",
        hosts: list[dict[str, Any]] | None = None,
    ) -> dict[str, str]:
        run_dir = self._create_run_dir()
        files: dict[str, str] = {}

        findings_json = {
            "campaign_id": self.campaign_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": findings,
        }
        fpath = run_dir / "findings.json"
        fpath.write_text(json.dumps(findings_json, indent=2, default=str))
        files["json"] = str(fpath)

        md = self._build_markdown(findings, campaign_summary, llm_analysis, scan_target, hosts or [])
        mpath = run_dir / "informe.md"
        mpath.write_text(md)
        files["markdown"] = str(mpath)

        logger.info("report", f"Informe generado: {mpath}")
        return files

    def _create_run_dir(self) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        d = self._base / ts
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _build_markdown(
        self, findings: list[dict[str, Any]], summary: dict[str, Any] | None,
        llm: str, target: str, hosts: list[dict[str, Any]],
    ) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sorted_f = sorted(
            findings, key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                f.get("severity", "low").lower(), 1
            ), reverse=True,
        )

        lines = [
            f"# Informe de Seguridad — {self.campaign_id}",
            "",
            f"**Generado:** {ts}",
            f"**Objetivo:** `{target}`" if target else "",
            "",
            "## Resumen",
            "",
        ]

        by_sev = {}
        for f in sorted_f:
            s = f.get("severity", "low").lower()
            by_sev[s] = by_sev.get(s, 0) + 1
        for s in ["critical", "high", "medium", "low", "info"]:
            if by_sev.get(s):
                lines.append(f"- **{s.upper()}:** {by_sev[s]}")

        if summary:
            lines.append(f"- **Hosts:** {summary.get('hosts_count', 0)}")
            lines.append(f"- **Correlaciones:** {summary.get('correlations', 0)}")

        lines += ["", "## Hallazgos", ""]

        for i, f in enumerate(sorted_f, 1):
            sev = f.get("severity", "low").upper()
            host = f.get("host", "")
            port = f.get("port", "")
            mitre = f.get("mitre", "")
            cvss = f.get("cvss_score", "")
            rec = f.get("recommendation", "")

            lines.append(f"### {i}. [{sev}] {f.get('title', '?')}")
            loc = host + (f":{port}" if port else "")
            if loc:
                lines.append(f"- **Ubicación:** {loc}")
            if mitre:
                lines.append(f"- **MITRE:** `{mitre}`")
            if cvss:
                lines.append(f"- **CVSS:** {cvss}")
            if rec:
                lines.append(f"- **Recomendación:** {rec}")
            lines.append("")

        if llm:
            lines += ["---", "## Análisis LLM", "", llm, ""]

        lines += ["---", f"*Generado por Skoll — {ts}*", ""]
        return "\n".join(lines)
