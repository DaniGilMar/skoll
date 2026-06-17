from __future__ import annotations

import json
from pathlib import Path
from typing import Any

RULES_PATH = Path(__file__).resolve().parent / "rules_config.json"
KB_PATH = Path(__file__).resolve().parent / "knowledge_base"


class RulesEngine:
    """Motor de reglas determinista. Nunca usa LLM.
    
    Toma observaciones del Evidence Store, aplica reglas,
    y produce pre-hallazgos con severidad, MITRE y CVE asociados.
    """

    def __init__(self, rules_path: str | Path = RULES_PATH):
        self._rules = self._load_rules(rules_path)
        self._kb = self._load_knowledge_base()

    def _load_rules(self, path: str | Path) -> list[dict[str, Any]]:
        p = Path(path)
        if not p.exists():
            return []
        with open(p) as f:
            data = json.load(f)
        return data.get("rules", [])

    def _load_knowledge_base(self) -> dict[str, Any]:
        kb: dict[str, Any] = {}
        if KB_PATH.exists():
            for f_path in KB_PATH.glob("*.json"):
                with open(f_path) as f:
                    kb[f_path.stem] = json.load(f)
        return kb

    def evaluate(self, observation: dict[str, Any]) -> list[dict[str, Any]]:
        """Evalúa una observación contra todas las reglas.
        
        Returns lista de pre-hallazgos (0, 1, o múltiples).
        """
        results: list[dict[str, Any]] = []
        for rule in self._rules:
            if self._matches(rule, observation):
                result = self._build_finding(rule, observation)
                if result:
                    results.append(result)
        return results

    def _matches(self, rule: dict[str, Any], obs: dict[str, Any]) -> bool:
        conditions = rule.get("conditions", [])
        for cond in conditions:
            if not self._eval_condition(cond, obs):
                return False
        return True

    def _eval_condition(self, condition: str, obs: dict[str, Any]) -> bool:
        try:
            if " == " in condition:
                field, value = condition.split(" == ", 1)
                field = field.strip()
                value = value.strip().strip("'\"")
                return str(self._get_field(obs, field)) == value
            if " != " in condition:
                field, value = condition.split(" != ", 1)
                field = field.strip()
                value = value.strip().strip("'\"")
                return str(self._get_field(obs, field)) != value
            if " in " in condition:
                field, value = condition.split(" in ", 1)
                field = field.strip()
                value = value.strip().strip("'\"")
                vals = [v.strip().strip("'\"") for v in value.split(",")]
                return str(self._get_field(obs, field)) in vals
            if " contains " in condition:
                field, value = condition.split(" contains ", 1)
                field = field.strip()
                value = value.strip().strip("'\"")
                flags = self._get_field(obs, field)
                if isinstance(flags, list):
                    return value in flags
                return value in str(flags)
        except Exception:
            return False
        return False

    def _get_field(self, obs: dict[str, Any], field: str) -> Any:
        parts = field.split(".")
        current = obs
        for p in parts:
            if isinstance(current, dict):
                current = current.get(p, "")
            else:
                return ""
        return current

    def _build_finding(self, rule: dict[str, Any], obs: dict[str, Any]) -> dict[str, Any] | None:
        rule_id = rule.get("id", "")
        kb_entry = self._kb.get("mitre", {}).get(rule_id, {})

        finding = {
            "rule_id": rule_id,
            "title": rule.get("title", rule_id),
            "description": rule.get("description", ""),
            "severity": kb_entry.get("severity", rule.get("severity", "medium")),
            "mitre": kb_entry.get("mitre", rule.get("mitre", "")),
            "cve_refs": kb_entry.get("cve_refs", rule.get("cve_refs", [])),
            "recommendation": kb_entry.get(
                "recommendation",
                rule.get("recommendation", ""),
            ),
            "host": obs.get("host", ""),
            "port": obs.get("port"),
            "service": obs.get("service", ""),
        }

        # Enriquecer con CVSS si existe en KB
        cvss = self._kb.get("cvss", {}).get(rule_id)
        if cvss:
            finding["cvss_vector"] = cvss.get("vector", "")
            finding["cvss_score"] = cvss.get("score", 0.0)

        return finding if finding.get("title") else None


_evaluator: RulesEngine | None = None


def get_rules_engine() -> RulesEngine:
    global _evaluator
    if _evaluator is None:
        _evaluator = RulesEngine()
    return _evaluator
