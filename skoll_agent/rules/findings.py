from __future__ import annotations

from typing import Any

from skoll_agent.rules.engine import get_rules_engine


class FindingsEngine:
    """Capa determinista que fusiona evidencia + reglas → findings finales.

    Nunca usa LLM. 0 tokens gastados aquí.
    """

    def __init__(self) -> None:
        self._rules = get_rules_engine()

    def process_evidence(
        self,
        evidence_list: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Procesa lista de evidencia y devuelve findings consolidados."""
        pre_findings: list[dict[str, Any]] = []
        seen_keys: set[str] = set()

        for ev in evidence_list:
            observations = ev.get("observations", [])
            for obs in observations:
                obs["host"] = ev.get("host", "")
                obs["tool"] = ev.get("tool", "")

                results = self._rules.evaluate(obs)
                for f in results:
                    dedup_key = (
                        f"{f['host']}:{f.get('port','')}:{f['rule_id']}"
                    )
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    pre_findings.append(f)

        return self._consolidate(pre_findings)

    def _consolidate(
        self, pre_findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Consolida findings duplicados, eligiendo la mayor severidad."""
        consolidated: dict[str, dict[str, Any]] = {}
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        for f in pre_findings:
            key = f"{f['host']}:{f.get('port', '')}:{f['rule_id']}"
            existing = consolidated.get(key)
            if not existing:
                consolidated[key] = dict(f)
                continue

            # Si el mismo finding aparece de múltiples observaciones,
            # mantener la mayor severidad
            curr_sev = severity_order.get(f.get("severity", "low"), 1)
            exist_sev = severity_order.get(
                existing.get("severity", "low"), 1
            )
            if curr_sev > exist_sev:
                consolidated[key]["severity"] = f["severity"]
                for extra_field in (
                    "cvss_vector",
                    "cvss_score",
                    "cve_refs",
                    "recommendation",
                ):
                    if f.get(extra_field):
                        consolidated[key][extra_field] = f[extra_field]

        # Ordenar por severidad descendente
        return sorted(
            consolidated.values(),
            key=lambda x: severity_order.get(x.get("severity", "low"), 1),
            reverse=True,
        )


_findings: FindingsEngine | None = None


def get_findings_engine() -> FindingsEngine:
    global _findings
    if _findings is None:
        _findings = FindingsEngine()
    return _findings
