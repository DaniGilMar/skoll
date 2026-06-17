from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORTS_ROOT = Path(os.environ.get("SKOLL_REPORTS_DIR", "/home/dani/Documentos/Skoll_Informes"))


class ReportGeneratorV2:
    """Generador de informes desacoplado del pipeline.

    Toma findings deterministas + memoria de campaña + análisis LLM
    y escribe archivos en REPORTS_ROOT / {campaign_id} / {timestamp} /.

    No depende de PipelineState ni de ningún otro componente interno.
    """

    def __init__(
        self,
        campaign_id: str,
        output_dir: str | Path = REPORTS_ROOT,
    ):
        self.campaign_id = campaign_id
        self._base = Path(output_dir) / campaign_id

    def generate(
        self,
        findings: list[dict[str, Any]],
        campaign_summary: dict[str, Any] | None = None,
        llm_analysis: str = "",
        judge_verdict: str = "",
        scan_target: str = "",
        hosts: list[dict[str, Any]] | None = None,
    ) -> dict[str, str]:
        """Genera informe completo. Devuelve dict con rutas de archivos."""
        run_dir = self._create_run_dir()
        files: dict[str, str] = {}

        findings_json = self._build_findings_json(findings, campaign_summary)
        fpath = run_dir / "findings.json"
        fpath.write_text(json.dumps(findings_json, indent=2, default=str))
        files["json"] = str(fpath)

        md = self._build_markdown(
            findings=findings,
            campaign_summary=campaign_summary,
            llm_analysis=llm_analysis,
            judge_verdict=judge_verdict,
            scan_target=scan_target,
            hosts=hosts or [],
        )
        mpath = run_dir / "informe.md"
        mpath.write_text(md)
        files["markdown"] = str(mpath)

        if campaign_summary:
            spath = run_dir / "summary.json"
            spath.write_text(json.dumps(campaign_summary, indent=2, default=str))
            files["summary"] = str(spath)

        return files

    def _create_run_dir(self) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        run_dir = self._base / ts
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def _build_findings_json(
        self,
        findings: list[dict[str, Any]],
        campaign_summary: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "campaign_summary": campaign_summary or {},
            "findings": findings,
        }

    def _severity_order(self, sev: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
            sev.lower(), 1
        )

    def _severity_icon(self, sev: str) -> str:
        icons = {
            "critical": "🔥",
            "high": "⚠️",
            "medium": "⚡",
            "low": "ℹ️",
            "info": "🔵",
        }
        return icons.get(sev.lower(), "●")

    def _build_markdown(
        self,
        findings: list[dict[str, Any]],
        campaign_summary: dict[str, Any] | None,
        llm_analysis: str,
        judge_verdict: str,
        scan_target: str,
        hosts: list[dict[str, Any]],
    ) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sorted_findings = sorted(
            findings, key=lambda f: self._severity_order(f.get("severity", "low")),
            reverse=True,
        )

        lines: list[str] = []
        lines.append(f"# Informe de Seguridad — {self.campaign_id}")
        lines.append("")
        lines.append(f"**Generado:** {ts}")
        if scan_target:
            lines.append(f"**Objetivo:** `{scan_target}`")
        lines.append("")

        by_sev: dict[str, int] = {}
        for f in sorted_findings:
            s = f.get("severity", "low").lower()
            by_sev[s] = by_sev.get(s, 0) + 1

        lines.append("## Resumen")
        lines.append("")
        sev_labels = ["critical", "high", "medium", "low", "info"]
        for s in sev_labels:
            count = by_sev.get(s, 0)
            if count:
                lines.append(f"- **{s.upper()}:** {count}")
        if campaign_summary:
            cs = campaign_summary
            lines.append(f"- **Hosts analizados:** {cs.get('hosts_count', 0)}")
            lines.append(f"- **Correlaciones:** {cs.get('correlations', 0)}")
            lines.append(f"- **Escaneos:** {cs.get('scan_count', 0)}")
        lines.append("")

        if hosts:
            lines.append("## Hosts detectados")
            lines.append("")
            lines.append("| IP | Hostname | OS | Puertos | Servicios |")
            lines.append("|---|---|---|---|---|")
            for h in hosts:
                lines.append(
                    f"| {h.get('ip', '')} | {h.get('hostname', '')} | "
                    f"{h.get('os', '')} | {h.get('port_count', 0)} | "
                    f"{h.get('service_count', 0)} |"
                )
            lines.append("")

        lines.append("## Hallazgos")
        lines.append("")
        if not sorted_findings:
            lines.append("*No se encontraron hallazgos.*")
            lines.append("")

        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "low").lower()
            icon = self._severity_icon(sev)
            title = f.get("title", "Sin título")
            host = f.get("host", "")
            port = f.get("port", "")
            service = f.get("service", "")
            mitre = f.get("mitre", "")
            cvss = f.get("cvss_score", "")
            cve_refs = f.get("cve_refs", [])
            recommendation = f.get("recommendation", "")

            lines.append(f"### {i}. {icon} [{sev.upper()}] {title}")
            lines.append("")
            if host:
                loc = host
                if port:
                    loc += f":{port}"
                if service:
                    loc += f" ({service})"
                lines.append(f"- **Ubicación:** {loc}")
            if mitre:
                lines.append(f"- **MITRE ATT&CK:** `{mitre}`")
            if cvss:
                lines.append(f"- **CVSS:** {cvss}")
            if cve_refs:
                lines.append(
                    f"- **CVE:** {', '.join(cve_refs)}"
                )
            if recommendation:
                lines.append(f"- **Recomendación:** {recommendation}")
            lines.append("")

        if llm_analysis:
            lines.append("---")
            lines.append("## Análisis LLM")
            lines.append("")
            lines.append(llm_analysis)
            lines.append("")

        if judge_verdict:
            lines.append("---")
            lines.append("## Validación (Juez Gemini)")
            lines.append("")
            try:
                j = json.loads(judge_verdict)
                if isinstance(j, dict):
                    v = j.get("veredicto", "N/A")
                    r = j.get("razon", "")
                    c = j.get("confianza", "")
                    lines.append(f"**Veredicto:** {v}")
                    lines.append(f"**Confianza:** {c}")
                    lines.append(f"**Razón:** {r}")
                else:
                    lines.append(judge_verdict)
            except json.JSONDecodeError:
                lines.append(judge_verdict)
            lines.append("")

        lines.append("---")
        lines.append(
            f"*Generado por Skoll v2 — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*"
        )
        lines.append("")

        return "\n".join(lines)
