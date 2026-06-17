from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from skoll_agent.pipeline.models import PipelineState


class ReportGenerator:
    def __init__(self, pipeline: PipelineState, target: str, session_id: str = ""):
        self.pipeline = pipeline
        self.target = target
        self.session_id = session_id
        self.start_time = datetime.now(timezone.utc)

    def generate_html(self) -> str:
        p = self.pipeline
        findings = p.all_findings
        ports = p.open_ports()
        flags = p.all_flags
        web = p.all_web()

        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

        overall_risk = "CRITICAL" if by_severity["critical"] > 0 else (
            "HIGH" if by_severity["high"] > 0 else (
                "MEDIUM" if by_severity["medium"] > 0 else "LOW"
            )
        )

        sev_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8",
        }

        chain_phase = p.phases.get("chain", {})
        if hasattr(chain_phase, "metadata"):
            chain_data = chain_phase.metadata.get("chain_analysis", {})
        elif isinstance(chain_phase, dict):
            chain_data = chain_phase.get("metadata", {}).get("chain_analysis", {})
        else:
            chain_data = {}
        remediation = chain_data.get("remediation_summary", []) if isinstance(chain_data, dict) else []

        findings_rows = ""
        for f in findings:
            sev = f.get("severity", "info").lower()
            color = sev_colors.get(sev, "#6c757d")
            findings_rows += f"""
            <tr>
                <td><span class="severity" style="background:{color}">{sev.upper()}</span></td>
                <td>{f.get('tool', '?')}</td>
                <td>{f.get('title', '?')}</td>
                <td>{f.get('description', '')[:200]}</td>
                <td>{f.get('port', '') or ''}</td>
            </tr>"""

        ports_rows = "".join(
            f"<tr><td>{p.port}</td><td>{p.protocol}</td><td>{p.service}</td><td>{p.product}</td><td>{p.version}</td></tr>"
            for p in ports
        )

        flags_rows = "".join(
            f"<tr><td><code>{f.value}</code></td><td>{f.pattern}</td><td>{f.source}</td></tr>"
            for f in flags
        )

        web_rows = "".join(
            f"<tr><td>{w.url}</td><td>{w.title}</td><td>{', '.join(w.tech[:5])}</td></tr>"
            for w in web
        )

        chain_rows = ""
        chains = chain_data.get("chains", [])
        for c in chains:
            chain_rows += f"""
            <div class="chain-item">
                <h3>{c.get('name', 'Attack Chain')}</h3>
                <p><strong>Risk:</strong> {c.get('risk', 'N/A')}</p>
                <p><strong>Root Cause:</strong> {c.get('root_cause', 'N/A')}</p>
                <ul>
                    {''.join(f'<li>{fi}</li>' for fi in c.get('findings', []))}
                </ul>
            </div>"""

        remediation_html = ""
        if remediation:
            remediation_html = "<ol>" + "".join(f"<li>{r}</li>" for r in remediation) + "</ol>"

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<style>
    @page {{
        margin: 2.5cm 2cm;
        @top-center {{
            content: "Skoll Security Assessment";
            font-size: 9pt; color: #666;
        }}
        @bottom-center {{
            content: "Página " counter(page);
            font-size: 8pt; color: #666;
        }}
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 10pt; line-height: 1.5; color: #333; }}
    .cover {{
        page-break-after: always;
        display: flex; flex-direction: column;
        justify-content: center; align-items: center;
        height: 100vh; text-align: center;
    }}
    .cover h1 {{ font-size: 28pt; color: #1a1a2e; margin-bottom: 10px; }}
    .cover h2 {{ font-size: 16pt; color: #555; font-weight: normal; }}
    .cover .meta {{ margin-top: 40px; font-size: 11pt; color: #777; }}
    .cover .logo {{ font-size: 48pt; margin-bottom: 20px; }}
    .section {{ page-break-inside: avoid; }}
    h2 {{ font-size: 16pt; color: #1a1a2e; border-bottom: 2px solid #e9ecef; padding-bottom: 6px; margin: 25px 0 15px; }}
    h3 {{ font-size: 12pt; margin: 15px 0 8px; color: #444; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9pt; }}
    th, td {{ border: 1px solid #dee2e6; padding: 6px 8px; text-align: left; }}
    th {{ background: #f8f9fa; font-weight: 600; }}
    .severity {{ display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff; font-size: 8pt; font-weight: 600; }}
    .summary-box {{ display: flex; gap: 12px; margin: 15px 0; flex-wrap: wrap; }}
    .stat {{ flex: 1; min-width: 100px; padding: 12px; border: 1px solid #dee2e6; border-radius: 6px; text-align: center; }}
    .stat .num {{ font-size: 22pt; font-weight: 700; }}
    .stat .label {{ font-size: 8pt; color: #777; text-transform: uppercase; letter-spacing: 0.5px; }}
    .chain-item {{ background: #f8f9fa; border-left: 4px solid #1a1a2e; padding: 12px; margin: 10px 0; border-radius: 0 6px 6px 0; }}
    .chain-item h3 {{ margin-top: 0; }}
    code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 9pt; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6; font-size: 8pt; color: #999; }}
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
    <div class="logo">ᛋ</div>
    <h1>Skoll Security Assessment</h1>
    <h2>Informe de Auditoría de Seguridad</h2>
    <div class="meta">
        <p><strong>Target:</strong> {self.target}</p>
        <p><strong>Fecha:</strong> {timestamp}</p>
        <p><strong>Session:</strong> {self.session_id}</p>
        <p><strong>Hallazgos:</strong> {len(findings)}</p>
        <p><strong>Riesgo General:</strong> <span class="severity" style="background:{sev_colors.get(overall_risk.lower(), '#6c757d')}">{overall_risk}</span></p>
    </div>
</div>

<!-- RESUMEN EJECUTIVO -->
<div class="section">
<h2>1. Resumen Ejecutivo</h2>
<p>Se realizó una auditoría de seguridad automatizada contra <strong>{self.target}</strong>.
Se identificaron <strong>{len(findings)}</strong> hallazgos de seguridad.</p>

<div class="summary-box">
    <div class="stat">
        <div class="num" style="color:{sev_colors['critical']}">{by_severity['critical']}</div>
        <div class="label">Crítico</div>
    </div>
    <div class="stat">
        <div class="num" style="color:{sev_colors['high']}">{by_severity['high']}</div>
        <div class="label">Alto</div>
    </div>
    <div class="stat">
        <div class="num" style="color:{sev_colors['medium']}">{by_severity['medium']}</div>
        <div class="label">Medio</div>
    </div>
    <div class="stat">
        <div class="num" style="color:{sev_colors['low']}">{by_severity['low']}</div>
        <div class="label">Bajo</div>
    </div>
    <div class="stat">
        <div class="num" style="color:{sev_colors['info']}">{by_severity['info']}</div>
        <div class="label">Info</div>
    </div>
    <div class="stat">
        <div class="num" style="color:{sev_colors['critical'] if flags else '#6c757d'}">{len(flags)}</div>
        <div class="label">Flags</div>
    </div>
</div>

<h3>Principales Riesgos</h3>
<table>
    <tr><th>Severidad</th><th>Herramienta</th><th>Hallazgo</th><th>Descripción</th></tr>
    {findings_rows}
</table>
</div>

<!-- REMEDIACIÓN -->
<div class="section">
<h2>2. Prioridades de Remediación</h2>
{remediation_html or '<p>No se generaron recomendaciones automáticas.</p>'}
</div>

<!-- CADENAS DE ATAQUE -->
<div class="section">
<h2>3. Cadenas de Ataque</h2>
{chain_rows or '<p>No se identificaron cadenas de ataque.</p>'}
</div>

<!-- PUERTOS -->
<div class="section">
<h2>4. Puertos y Servicios</h2>
<table>
    <tr><th>Puerto</th><th>Protocolo</th><th>Servicio</th><th>Producto</th><th>Versión</th></tr>
    {ports_rows or '<tr><td colspan="5">Sin puertos descubiertos</td></tr>'}
</table>
</div>

<!-- WEB -->
<div class="section">
<h2>5. Servicios Web</h2>
<table>
    <tr><th>URL</th><th>Título</th><th>Tecnologías</th></tr>
    {web_rows or '<tr><td colspan="3">Sin servicios web</td></tr>'}
</table>
</div>

<!-- FLAGS -->
<div class="section">
<h2>6. Flags Detectadas</h2>
<table>
    <tr><th>Flag</th><th>Patrón</th><th>Fuente</th></tr>
    {flags_rows or '<tr><td colspan="3">Sin flags detectadas</td></tr>'}
</table>
</div>

<!-- METADATA -->
<div class="section">
<h2>7. Metadatos de la Auditoría</h2>
<table>
    <tr><td><strong>Pipeline</strong></td><td>Skoll RAPTOR-style</td></tr>
    <tr><td><strong>Iteraciones</strong></td><td>{p.iteration}</td></tr>
    <tr><td><strong>Metodología</strong></td><td>PTES / OWASP</td></tr>
    <tr><td><strong>Generado por</strong></td><td>Skoll Pipeline</td></tr>
</table>
</div>

<div class="footer">
    <p>Skoll Security Assessment — Generado automáticamente por Skoll Pipeline — {timestamp}</p>
    <p>Este informe confidencial contiene información sensible de seguridad. Solo para el cliente identificado.</p>
</div>

</body>
</html>"""

    def generate_pdf(self, output_path: str = "") -> str:
        html = self.generate_html()
        if not output_path:
            reports_dir = os.path.expanduser("~/.skoll/reports")
            os.makedirs(reports_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe_target = self.target.replace(".", "_").replace(":", "_")
            output_path = os.path.join(reports_dir, f"skoll_{safe_target}_{ts}.pdf")

        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(output_path)
        except Exception as e:
            # Fallback: guardar HTML si PDF falla
            html_path = output_path.replace(".pdf", ".html")
            with open(html_path, "w") as f:
                f.write(html)
            output_path = html_path
            raise RuntimeError(f"PDF generation failed: {e}. HTML saved to {html_path}") from e

        return output_path
