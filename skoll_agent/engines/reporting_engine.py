from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


import os as _os
REPORTS_DIR = _os.environ.get("SKOLL_REPORTS_DIR", "/home/dani/Documentos/Skoll_Informes")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SEVERITY_COLORS = {
    "critical": "#dc3545", "high": "#fd7e14",
    "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8",
}

CVSS_SEVERITY_MAP: dict[str, tuple[float, float, str]] = {
    "critical": (9.0, 10.0, "CRITICAL"),
    "high": (7.0, 8.9, "HIGH"),
    "medium": (4.0, 6.9, "MEDIUM"),
    "low": (0.1, 3.9, "LOW"),
    "info": (0.0, 0.0, "NONE"),
}

MITRE_MAP: dict[str, list[dict[str, str]]] = {
    "nmap": [
        {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
    ],
    "masscan": [
        {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
    ],
    "gobuster": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    ],
    "ffuf": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    ],
    "nikto": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    ],
    "nuclei": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "whatweb": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    ],
    "hydra": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "sqlmap": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505", "name": "Server Software Component", "tactic": "Persistence"},
    ],
    "ftp": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "smb": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "smbmap": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1135", "name": "Network Share Discovery", "tactic": "Discovery"},
    ],
    "enum4linux": [
        {"id": "T1069", "name": "Permission Groups Discovery", "tactic": "Discovery"},
        {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    ],
    "redis": [
        {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Initial Access"},
    ],
    "mysql": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "postgres": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "msfconsole": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    ],
    "cve": [
        {"id": "T1588", "name": "Obtain Capabilities", "tactic": "Resource Development"},
    ],
    "cve2msf": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Initial Access"},
    ],
    "ldap": [
        {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
        {"id": "T1482", "name": "Domain Trust Discovery", "tactic": "Discovery"},
    ],
    "kerberos": [
        {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access"},
    ],
    "impacket": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1550", "name": "Use Alternative Authentication Material", "tactic": "Defense Evasion"},
    ],
    "bloodhound": [
        {"id": "T1069", "name": "Permission Groups Discovery", "tactic": "Discovery"},
        {"id": "T1482", "name": "Domain Trust Discovery", "tactic": "Discovery"},
    ],
    "hashcat": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access"},
    ],
    "john": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "spray": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "iam": [
        {"id": "T1525", "name": "Implant Container Image", "tactic": "Persistence"},
        {"id": "T1613", "name": "Container and Resource Discovery", "tactic": "Discovery"},
    ],
    "storage": [
        {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"},
    ],
    "secrets": [
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    ],
    "k8s": [
        {"id": "T1613", "name": "Container and Resource Discovery", "tactic": "Discovery"},
        {"id": "T1525", "name": "Implant Container Image", "tactic": "Persistence"},
    ],
    "sliver": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    ],
    "empire": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    ],
    "redteam": [
        {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
        {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
    ],
}

REMEDIATION_TEMPLATES: dict[str, list[str]] = {
    "critical": [
        "Apply vendor security patches immediately (within 24-48 hours)",
        "Disable the vulnerable service if patching is not immediately possible",
        "Implement network segmentation to limit exposure of the vulnerable service",
        "Deploy virtual patching via WAF/IPS rules as temporary mitigation",
        "Conduct incident response triage: check for signs of compromise",
    ],
    "high": [
        "Apply security patches within the next patch cycle (1-2 weeks)",
        "Review and harden configuration of the affected service",
        "Implement additional authentication controls",
        "Enable comprehensive logging and monitoring for the affected service",
    ],
    "medium": [
        "Apply patches during the regular maintenance window",
        "Review security configuration and harden where possible",
        "Implement principle of least privilege for the affected service",
        "Add to security monitoring and alerting rules",
    ],
    "low": [
        "Document as informational finding",
        "Address during next scheduled hardening review",
        "Consider low-priority configuration changes",
    ],
    "info": [
        "Document for reference",
    ],
}


class ReportingEngine(BaseEngine):
    name = "reporting"
    description = "FASE 11 — Reporting: genera Executive Summary, Technical Deep Dive, CVSS scoring, MITRE ATT&CK mapping, y Remediation Roadmap"
    capabilities = ["reporting", "executive_summary", "technical_deep_dive", "cvss_scoring", "mitre_attack", "remediation_roadmap"]

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings: list[dict[str, Any]] = kwargs.get("findings", [])
        ports: list[dict[str, Any]] = kwargs.get("ports", [])
        web_services: list[dict[str, Any]] = kwargs.get("web_services", [])
        chain_analysis: dict[str, Any] = kwargs.get("chain_analysis", {})
        pipeline_summary: str = kwargs.get("pipeline_summary", "")
        session_id: str = kwargs.get("session_id", "")
        report_type: str = kwargs.get("report_type", "full")
        raw_lines: list[str] = []
        report_findings: list[dict[str, Any]] = []

        os.makedirs(REPORTS_DIR, exist_ok=True)

        safe_target = target.replace(".", "_").replace(":", "_")
        ts = time.strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(REPORTS_DIR, f"skoll_report_{safe_target}_{ts}.md")
        html_path = os.path.join(REPORTS_DIR, f"skoll_report_{safe_target}_{ts}.html")

        by_severity = self._count_by_severity(findings)
        cves = self._extract_cves(findings)
        overall_risk = self._calculate_overall_risk(by_severity)

        raw_lines.append(f"[INFO] Generating {report_type} report for {target}")
        raw_lines.append(f"[INFO] Findings: {len(findings)} | CVEs: {len(cves)} | Risk: {overall_risk}")
        raw_lines.append(f"[INFO] Output: {report_path}")

        mitre_entries = self._map_mitre(findings)
        cvss_entries = self._score_cvss(findings)

        report_content = self._generate_markdown_report(
            target=target, session_id=session_id, ts=ts,
            findings=findings, ports=ports, web_services=web_services,
            by_severity=by_severity, cves=cves, overall_risk=overall_risk,
            mitre_entries=mitre_entries, cvss_entries=cvss_entries,
            chain_analysis=chain_analysis, pipeline_summary=pipeline_summary,
            report_type=report_type,
        )

        html_content = self._convert_to_html(report_content)

        try:
            with open(report_path, "w") as f:
                f.write(report_content)
            report_findings.append({
                "file_path": report_path, "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": f"Reporte de seguridad generado (Markdown)",
                "description": f"Informe completo guardado en {report_path}\nFormato: Markdown profesional con todas las secciones",
                "tool": self.name, "rule_id": "report-markdown",
                "report_path": report_path, "report_format": "markdown",
            })
            raw_lines.append(f"[OK] Markdown report saved: {report_path}")
        except Exception as e:
            raw_lines.append(f"[ERR] Failed to save markdown report: {e}")

        try:
            with open(html_path, "w") as f:
                f.write(html_content)
            report_findings.append({
                "file_path": html_path, "line_start": 0, "line_end": 0,
                "severity": "info",
                "title": f"Reporte de seguridad generado (HTML)",
                "description": f"Informe completo guardado en {html_path}\nFormato: HTML con tabla de contenidos y diseño profesional",
                "tool": self.name, "rule_id": "report-html",
                "report_path": html_path, "report_format": "html",
            })
            raw_lines.append(f"[OK] HTML report saved: {html_path}")
        except Exception as e:
            raw_lines.append(f"[ERR] Failed to save HTML report: {e}")

        raw_lines.append(f"[SUMMARY] Report generated: {len(cvss_entries)} CVSS scores, {len(mitre_entries)} MITRE mappings")

        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=report_findings,
            summary=f"reporting: {len(findings)} findings, risk={overall_risk}, reports in {REPORTS_DIR}",
        )

    def _count_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _extract_cves(self, findings: list[dict[str, Any]]) -> list[str]:
        import re
        pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        cves: set[str] = set()
        for f in findings:
            cve_id = f.get("cve_id", "")
            if cve_id and pattern.fullmatch(cve_id.strip()):
                cves.add(cve_id.upper())
            title = f.get("title", "")
            desc = f.get("description", "")
            for text in (title, desc):
                for m in pattern.finditer(text):
                    cves.add(m.group(0).upper())
        return sorted(cves)

    def _calculate_overall_risk(self, by_severity: dict[str, int]) -> str:
        if by_severity.get("critical", 0) > 0:
            return "CRITICAL"
        if by_severity.get("high", 0) > 0:
            return "HIGH"
        if by_severity.get("medium", 0) > 0:
            return "MEDIUM"
        if by_severity.get("low", 0) > 0:
            return "LOW"
        return "INFO"

    def _score_cvss(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scored: list[dict[str, Any]] = []
        for f in findings:
            sev = f.get("severity", "info").lower()
            title = f.get("title", "Unknown finding")
            cve_id = f.get("cve_id", "")
            cvss_range = CVSS_SEVERITY_MAP.get(sev, (0.0, 0.0, "NONE"))
            base_score = round((cvss_range[0] + cvss_range[1]) / 2, 1)
            vector_parts = [
                "CVSS:3.1",
                f"AV:{'N' if sev in ('critical', 'high') else 'A'}",
                f"AC:L",
                f"PR:{'N' if sev == 'critical' else 'L'}",
                f"UI:{'N' if sev in ('critical', 'high') else 'R'}",
                f"S:{'C' if sev in ('critical', 'high') else 'U'}",
                f"C:{'H' if sev in ('critical', 'high') else 'L'}",
                f"I:{'H' if sev in ('critical', 'high', 'medium') else 'L'}",
                f"A:{'H' if sev == 'critical' else 'L'}",
            ]
            vector = "/".join(vector_parts)
            scored.append({
                "title": title,
                "cve_id": cve_id,
                "severity": sev.upper(),
                "cvss_score": base_score,
                "cvss_severity": cvss_range[2],
                "cvss_vector": vector,
                "tool": f.get("tool", "?"),
            })
        return scored

    def _map_mitre(self, findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        mapped: list[dict[str, str]] = []
        seen: set[str] = set()
        for f in findings:
            tool = f.get("tool", "").lower()
            techniques = MITRE_MAP.get(tool, [])
            for tech in techniques:
                key = f"{tech['id']}|{tool}"
                if key not in seen:
                    seen.add(key)
                    mapped.append({
                        "tool": tool,
                        "mitre_id": tech["id"],
                        "technique": tech["name"],
                        "tactic": tech["tactic"],
                    })
        return mapped

    def _generate_markdown_report(self, target: str, session_id: str, ts: str,
                                   findings: list[dict[str, Any]],
                                   ports: list[dict[str, Any]],
                                   web_services: list[dict[str, Any]],
                                   by_severity: dict[str, int],
                                   cves: list[str],
                                   overall_risk: str,
                                   mitre_entries: list[dict[str, Any]],
                                   cvss_entries: list[dict[str, Any]],
                                   chain_analysis: dict[str, Any],
                                   pipeline_summary: str,
                                   report_type: str) -> str:
        lines: list[str] = []

        cover = f"""# Skoll Security Assessment — Informe de Seguridad

<div style="text-align: center; border: 3px double #1a1a2e; padding: 30px; margin: 20px 0; border-radius: 8px;">
<h1 style="font-size: 2.5em; color: #1a1a2e; margin-bottom: 5px;">ᛋ Skoll Security Assessment</h1>
<h2 style="color: #555; font-weight: normal;">Informe de Auditoría de Seguridad</h2>
<hr style="width: 50%; margin: 20px auto; border-color: #ccc;">
<p><strong>Target:</strong> {target}</p>
<p><strong>Fecha:</strong> {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
<p><strong>Session:</strong> {session_id or 'N/A'}</p>
<p><strong>Hallazgos:</strong> {len(findings)}</p>
<p><strong>CVEs Identificados:</strong> {len(cves)}</p>
<p><strong>Riesgo General:</strong> <span style="background: {SEVERITY_COLORS.get(overall_risk.lower(), '#6c757d')}; color: white; padding: 4px 12px; border-radius: 4px;">{overall_risk}</span></p>
</div>

<div style="page-break-after: always;"></div>
"""
        lines.append(cover)

        lines.append(f"""---
# Índice

1. [Executive Summary](#1-executive-summary)
2. [CVSS v3.1 Scoring](#2-cvss-v31-scoring)
3. [MITRE ATT&CK Mapping](#3-mitre-attck-mapping)
4. [Technical Deep Dive](#4-technical-deep-dive)
5. [Remediation Roadmap](#5-remediation-roadmap)
6. [Análisis de Cadenas de Ataque](#6-analisis-de-cadenas-de-ataque)
7. [Apéndice: Puertos y Servicios](#7-apendice-puertos-y-servicios)
8. [Apéndice: Servicios Web](#8-apendice-servicios-web)

<div style="page-break-after: always;"></div>
""")

        exec_summary = f"""# 1. Executive Summary

## Resumen Ejecutivo

Se realizó una auditoría de seguridad automatizada contra **{target}** utilizando la metodología RAPTOR v2 del framework Skoll. El análisis comprende reconocimiento, enumeración, validación, análisis multi-agente con 11 especialistas de IA, explotación controlada y generación de reportes.

### Métricas Clave

| Métrica | Valor |
|---------|-------|
| **Hallazgos Totales** | {len(findings)} |
| **CVEs Identificados** | {len(cves)} |
| **Riesgo General** | **{overall_risk}** |
| **Target** | {target} |
| **Metodología** | PTES / OWASP / RAPTOR v2 |

### Distribución por Severidad

| Severidad | Cantidad | Impacto |
|-----------|:--------:|:-------:|
| 🔴 **Crítico** | {by_severity.get('critical', 0)} | Compromiso total del sistema |
| 🟠 **Alto** | {by_severity.get('high', 0)} | Acceso no autorizado significativo |
| 🟡 **Medio** | {by_severity.get('medium', 0)} | Exposición de información limitada |
| 🟢 **Bajo** | {by_severity.get('low', 0)} | Problemas de configuración menores |
| 🔵 **Informativo** | {by_severity.get('info', 0)} | Observaciones y recomendaciones |

### Hallazgos Críticos y de Alta Severidad

"""
        critical_high = [f for f in findings if f.get("severity", "info").lower() in ("critical", "high")]
        if critical_high:
            for f in critical_high:
                sev = f.get("severity", "info").upper()
                tool = f.get("tool", "?")
                title = f.get("title", "?")
                desc = f.get("description", "")[:200]
                cve_id = f.get("cve_id", "") or ""
                cve_str = f" (`{cve_id}`)" if cve_id else ""
                exec_summary += f"- **[{sev}]** [{tool}]{cve_str} **{title}**: {desc}\n"
        else:
            exec_summary += "No se identificaron hallazgos críticos o de alta severidad.\n"

        if cves:
            exec_summary += f"\n### CVEs Identificados ({len(cves)})\n\n"
            exec_summary += "| CVE | Contexto |\n|-----|----------|\n"
            cve_contexts = self._map_cve_to_findings(cves, findings)
            for cve in cves:
                ctx = cve_contexts.get(cve, "Vulnerabilidad identificada")
                exec_summary += f"| `{cve}` | {ctx} |\n"

        exec_summary += f"\n### Vector de Ataque Principal\n\n"
        attack_vector = chain_analysis.get("attack_vector", "") or pipeline_summary or "No determinado"
        exec_summary += f"{attack_vector}\n\n"

        exec_summary += "\n<div style=\"page-break-after: always;\"></div>\n"
        lines.append(exec_summary)

        cvss_section = "# 2. CVSS v3.1 Scoring\n\n"
        cvss_section += "## Puntuación CVSS v3.1\n\n"
        cvss_section += "A continuación se presentan las puntuaciones CVSS v3.1 calculadas para cada hallazgo, basadas en la severidad, el contexto del servicio y el impacto potencial.\n\n"

        if cvss_entries:
            cvss_section += "| # | Hallazgo | CVE | Severidad | CVSS Score | Vector |\n|---|----------|:---:|:---------:|:----------:|--------|\n"
            for i, c in enumerate(cvss_entries, 1):
                cve_str = f"`{c['cve_id']}`" if c["cve_id"] else "-"
                title_short = c["title"][:60]
                score_bar = self._cvss_bar(c["cvss_score"])
                cvss_section += f"| {i} | {title_short} | {cve_str} | {c['severity']} | {c['cvss_score']} {score_bar} | `{c['cvss_vector']}` |\n"
        else:
            cvss_section += "No hay hallazgos para puntuar.\n"

        cvss_section += """
### Escala CVSS v3.1

| Severidad | Rango | Color |
|-----------|:-----:|:-----:|
| CRITICAL | 9.0 - 10.0 | 🔴 Rojo |
| HIGH | 7.0 - 8.9 | 🟠 Naranja |
| MEDIUM | 4.0 - 6.9 | 🟡 Amarillo |
| LOW | 0.1 - 3.9 | 🟢 Verde |
| NONE | 0.0 | ⚪ Ninguno |

"""
        cvss_section += "\n<div style=\"page-break-after: always;\"></div>\n"
        lines.append(cvss_section)

        mitre_section = "# 3. MITRE ATT&CK Mapping\n\n"
        mitre_section += "## Mapeo a MITRE ATT&CK®\n\n"
        mitre_section += "Los hallazgos se han mapeado a tácticas y técnicas del framework MITRE ATT&CK® v14 para contextualizar el comportamiento del adversario.\n\n"

        if mitre_entries:
            by_tactic: dict[str, list[dict[str, Any]]] = {}
            for m in mitre_entries:
                by_tactic.setdefault(m["tactic"], []).append(m)

            for tactic in ["Initial Access", "Execution", "Persistence", "Defense Evasion",
                           "Credential Access", "Discovery", "Lateral Movement", "Collection",
                           "Command and Control", "Resource Development"]:
                entries = by_tactic.get(tactic, [])
                if entries:
                    mitre_section += f"### {tactic}\n\n"
                    mitre_section += "| Técnica | ID | Herramienta |\n|---------|:---:|:-----------:|\n"
                    for e in entries:
                        mitre_section += f"| {e['technique']} | `{e['mitre_id']}` | {e['tool']} |\n"
                    mitre_section += "\n"

        mitre_section += "\n<details>\n<summary>Ver todas las técnicas ({len(mitre_entries)} total)</summary>\n\n"
        mitre_section += "| # | Táctica | Técnica | ID | Herramienta |\n|---|:-------:|---------|:---:|:-----------:|\n"
        for i, m in enumerate(mitre_entries, 1):
            mitre_section += f"| {i} | {m['tactic']} | {m['technique']} | `{m['mitre_id']}` | {m['tool']} |\n"
        mitre_section += "\n</details>\n"

        mitre_section += "\n<div style=\"page-break-after: always;\"></div>\n"
        lines.append(mitre_section)

        tech_dive = "# 4. Technical Deep Dive\n\n"
        tech_dive += "## Análisis Técnico Detallado\n\n"
        tech_dive += "### Todos los Hallazgos\n\n"

        critical_f = [f for f in findings if f.get("severity", "info").lower() == "critical"]
        high_f = [f for f in findings if f.get("severity", "info").lower() == "high"]
        medium_f = [f for f in findings if f.get("severity", "info").lower() == "medium"]
        low_f = [f for f in findings if f.get("severity", "info").lower() == "low"]
        info_f = [f for f in findings if f.get("severity", "info").lower() == "info"]

        def render_findings_group(f_list: list[dict[str, Any]], label: str) -> str:
            if not f_list:
                return f"*No hay hallazgos {label.lower()}.*\n\n"
            s = ""
            for idx, f in enumerate(f_list, 1):
                title = f.get("title", "Unknown")
                tool = f.get("tool", "?")
                desc = f.get("description", "")
                cve_id = f.get("cve_id", "")
                rule_id = f.get("rule_id", "")
                port = f.get("port", "")
                recommendation = f.get("recommendation", "")
                s += f"#### {idx}. {title}\n\n"
                s += f"- **Herramienta:** `{tool}`\n"
                s += f"- **Regla:** `{rule_id}`\n"
                if cve_id:
                    s += f"- **CVE:** `{cve_id}`\n"
                if port:
                    s += f"- **Puerto:** {port}\n"
                s += f"\n**Descripción:**\n{desc}\n\n"
                if recommendation:
                    s += f"**Recomendación:** {recommendation}\n\n"
                s += "---\n\n"
            return s

        if critical_f:
            tech_dive += "### 🔴 Hallazgos Críticos\n\n"
            tech_dive += render_findings_group(critical_f, "Críticos")
        if high_f:
            tech_dive += "### 🟠 Hallazgos de Alta Severidad\n\n"
            tech_dive += render_findings_group(high_f, "Altos")
        if medium_f:
            tech_dive += "### 🟡 Hallazgos de Severidad Media\n\n"
            tech_dive += render_findings_group(medium_f, "Medios")
        if low_f:
            tech_dive += "### 🟢 Hallazgos de Baja Severidad\n\n"
            tech_dive += render_findings_group(low_f, "Bajos")
        if info_f:
            tech_dive += "### 🔵 Hallazgos Informativos\n\n"
            tech_dive += render_findings_group(info_f, "Informativos")

        tech_dive += "\n<div style=\"page-break-after: always;\"></div>\n"
        lines.append(tech_dive)

        remediation = "# 5. Remediation Roadmap\n\n"
        remediation += "## Plan de Remediación\n\n"
        remediation += "### Prioridades por Severidad\n\n"

        remediation += self._generate_remediation_plan(by_severity, findings, cves)
        remediation += self._generate_verification_steps()

        remediation += "\n<div style=\"page-break-after: always;\"></div>\n"
        lines.append(remediation)

        attack_chains = "# 6. Análisis de Cadenas de Ataque\n\n"
        chains = chain_analysis.get("chains", [])
        if chains:
            for c in chains:
                attack_chains += f"### {c.get('name', 'Attack Chain')}\n\n"
                attack_chains += f"- **Riesgo:** {c.get('risk', 'N/A')}\n"
                attack_chains += f"- **Causa Raíz:** {c.get('root_cause', 'N/A')}\n\n"
                attack_chains += "**Hallazgos en la cadena:**\n\n"
                for fi in c.get("findings", []):
                    attack_chains += f"- {fi}\n"
                attack_chains += "\n"
        else:
            attack_vector = chain_analysis.get("attack_vector", "")
            if attack_vector:
                attack_chains += f"**Vector de ataque identificado:**\n{attack_vector}\n\n"
            else:
                attack_chains += "No se identificaron cadenas de ataque complejas.\n\n"

        attack_chains += "\n<div style=\"page-break-after: always;\"></div>\n"
        lines.append(attack_chains)

        appendix = "# 7. Apéndice: Puertos y Servicios\n\n"
        appendix += "## Puertos Descubiertos\n\n"
        if ports:
            appendix += "| Puerto | Protocolo | Servicio | Producto | Versión |\n|:------:|:---------:|:--------:|:--------:|:-------:|\n"
            for p in ports:
                appendix += f"| {p.get('port', '?')} | {p.get('protocol', 'tcp')} | {p.get('service', '?')} | {p.get('product', '-')} | {p.get('version', '-')} |\n"
        else:
            appendix += "No se descubrieron puertos.\n"

        appendix += "\n---\n\n"
        appendix += "# 8. Apéndice: Servicios Web\n\n"
        appendix += "## Tecnologías Web Detectadas\n\n"
        if web_services:
            appendix += "| URL | Título | Tecnologías |\n|:---:|:------:|:-----------:|\n"
            for w in web_services:
                techs = ", ".join(w.get("tech", [])[:5]) if w.get("tech") else "-"
                appendix += f"| {w.get('url', '?')} | {w.get('title', '?')} | {techs} |\n"
        else:
            appendix += "No se detectaron servicios web.\n"

        appendix += f"""

---
<div style="text-align: center; color: #888; font-size: 0.9em;">

*Generado por **Skoll Security Framework** — RAPTOR v2 Pipeline*
*Metodología: PTES / OWASP / MITRE ATT&CK v14*
*Fecha: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}*
*Target: {target}*

*Este informe contiene información confidencial de seguridad. Solo para el cliente identificado.*

</div>
"""
        lines.append(appendix)

        return "\n".join(lines)

    def _generate_remediation_plan(self, by_severity: dict[str, int],
                                    findings: list[dict[str, Any]],
                                    cves: list[str]) -> str:
        s = """"""
        priority_order = [("critical", "🔴", "Crítico (24-48h)"),
                          ("high", "🟠", "Alto (1-2 semanas)"),
                          ("medium", "🟡", "Medio (1 mes)"),
                          ("low", "🟢", "Bajo (próximo hardening)")]

        for sev, icon, timeframe in priority_order:
            count = by_severity.get(sev, 0)
            if count == 0:
                continue
            templates = REMEDIATION_TEMPLATES.get(sev, [])
            s += f"### {icon} Prioridad {timeframe} ({count} hallazgos)\n\n"
            for t in templates:
                s += f"- [ ] {t}\n"
            s += "\n"

        if cves:
            s += "### Acciones Específicas para CVEs\n\n"
            for cve in cves:
                s += f"- [ ] Investigar y parchear `{cve}`\n"
                s += f"  - Verificar si el CVE aplica al producto y versión exactos\n"
                s += f"  - Aplicar parche del vendor o mitigación compensatoria\n"
                s += f"  - Verificar que el parche no afecta la funcionalidad del sistema\n"
            s += "\n"

        s += """### Roadmap Temporal Recomendado

| Fase | Plazo | Acciones |
|:----:|:-----:|:--------:|
| **Fase 1** | 24-48h | Parchear todos los hallazgos críticos. Verificar si hay indicios de compromiso (IOCs). |
| **Fase 2** | 1-2 semanas | Parchear hallazgos de alta severidad. Revisar configuraciones. |
| **Fase 3** | 1 mes | Abordar hallazgos de severidad media. Implementar monitoreo. |
| **Fase 4** | 3 meses | Revisión general de hardening. Re-evaluación de seguridad. |

"""
        return s

    def _generate_verification_steps(self) -> str:
        return """### Verificación de Remediación

Después de aplicar las remediaciones, se recomienda:

1. **Re-escanear** el target con las mismas herramientas para confirmar que los hallazgos se han resuelto
2. **Pruebas de regresión** para verificar que los parches no introducen nuevos problemas
3. **Revisión de logs** para detectar actividad maliciosa previa a la remediación
4. **Actualización del plan de respuesta a incidentes** basado en las lecciones aprendidas
5. **Programar auditorías periódicas** (trimestrales recomendadas)

"""

    def _map_cve_to_findings(self, cves: list[str], findings: list[dict[str, Any]]) -> dict[str, str]:
        import re
        pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        result: dict[str, str] = {}
        for cve in cves:
            context = "Vulnerabilidad identificada"
            for f in findings:
                f_cve = f.get("cve_id", "")
                if f_cve and f_cve.upper() == cve:
                    context = f.get("description", context)[:150]
                    break
                title = f.get("title", "")
                desc = f.get("description", "")
                for text in (title, desc):
                    if pattern.search(text) and cve.upper() in text.upper():
                        context = f.get("description", context)[:150]
                        break
            result[cve] = context
        return result

    def _cvss_bar(self, score: float) -> str:
        bars = int(score / 2)
        if score >= 9.0:
            return "🔴" + "━" * bars
        elif score >= 7.0:
            return "🟠" + "━" * bars
        elif score >= 4.0:
            return "🟡" + "━" * bars
        elif score > 0:
            return "🟢" + "━" * bars
        return ""

    def _convert_to_html(self, markdown_content: str) -> str:
        try:
            import markdown
            body = markdown.markdown(markdown_content, extensions=["tables", "fenced_code", "codehilite"])
        except ImportError:
            body = f"<pre>{markdown_content[:100000]}</pre>"

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Skoll Security Assessment</title>
<style>
    @page {{ margin: 2.5cm 2cm; }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 10pt; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px; }}
    h1 {{ font-size: 22pt; color: #1a1a2e; margin: 25px 0 10px; border-bottom: 3px solid #1a1a2e; padding-bottom: 8px; }}
    h2 {{ font-size: 16pt; color: #1a1a2e; margin: 20px 0 8px; border-bottom: 2px solid #e9ecef; padding-bottom: 5px; }}
    h3 {{ font-size: 12pt; margin: 15px 0 6px; color: #444; }}
    h4 {{ font-size: 11pt; margin: 12px 0 4px; color: #555; }}
    p {{ margin: 8px 0; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9pt; }}
    th, td {{ border: 1px solid #dee2e6; padding: 6px 10px; text-align: left; }}
    th {{ background: #f8f9fa; font-weight: 600; }}
    tr:nth-child(even) {{ background: #fafafa; }}
    code {{ background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-size: 9pt; }}
    pre {{ background: #f5f5f5; padding: 12px; border-radius: 5px; overflow-x: auto; font-size: 9pt; }}
    blockquote {{ border-left: 4px solid #1a1a2e; padding: 8px 15px; margin: 10px 0; background: #f9f9fb; }}
    hr {{ border: none; border-top: 1px solid #dee2e6; margin: 20px 0; }}
    details {{ margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; }}
    summary {{ cursor: pointer; font-weight: 600; color: #1a1a2e; }}
    .severity {{ display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff; font-size: 8pt; font-weight: 600; }}
    ul, ol {{ margin: 8px 0; padding-left: 25px; }}
    li {{ margin: 3px 0; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6; font-size: 8pt; color: #999; text-align: center; }}
</style>
</head>
<body>
{body}
<div class="footer">
    <p>Generado por Skoll Security Framework — RAPTOR v2 Pipeline</p>
    <p>Metodología: PTES / OWASP / MITRE ATT&CK v14</p>
    <p>Este informe contiene información confidencial de seguridad.</p>
</div>
</body>
</html>"""

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
