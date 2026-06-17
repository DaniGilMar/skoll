from __future__ import annotations

import re
from typing import Any

from skoll_agent.memory.state import Finding, Severity


class SeverityValidator:
    def __init__(self):
        self.rules: dict[str, list[dict[str, Any]]] = {
            Severity.CRITICAL: [
                {"pattern": r"(?i)(sql\s*inj|command\s*inj|rce|remote\s*code|eval\s*\(|exec\s*\()", "label": "direct_rce_or_injection"},
                {"pattern": r"(?i)(hardcoded.*(?:password|secret|key|token)|password\s*=\s*['\"])", "label": "hardcoded_credential"},
                {"pattern": r"(?i)(os\.system|subprocess\.call|popen)", "label": "os_command_injection"},
            ],
            Severity.HIGH: [
                {"pattern": r"(?i)(path\s*traversal|directory\s*traversal|\.\./|\.\.\\\)", "label": "path_traversal"},
                {"pattern": r"(?i)(xxe|xml\s*external|deserialization|pickle\.load)", "label": "xxe_or_deserialization"},
                {"pattern": r"(?i)(sqlite|execute\s*\(.*\+|\"\\s*\+\s*\$|f\".*\{.*\{)", "label": "probable_sqli"},
            ],
            Severity.MEDIUM: [
                {"pattern": r"(?i)(xss|cross.site|innerHTML|dangerouslySetInnerHTML)", "label": "xss"},
                {"pattern": r"(?i)(csrf|missing.*auth|no.*auth)", "label": "missing_auth"},
                {"pattern": r"(?i)(debug|print|console\.log|var_dump)", "label": "debug_output"},
            ],
            Severity.LOW: [
                {"pattern": r"(?i)(deprecated|TODO|FIXME|HACK|XXX)", "label": "code_smell"},
                {"pattern": r"(?i)(http://|ftp://)", "label": "unsecure_protocol"},
            ],
        }

    def validate(self, finding: Finding, code_context: str = "") -> Severity:
        text = f"{finding.title} {finding.description} {code_context}"

        for severity, patterns in self.rules.items():
            for rule in patterns:
                if re.search(rule["pattern"], text):
                    return severity

        return finding.severity

    def auto_classify(self, title: str, description: str) -> tuple[Severity, str]:
        text = f"{title} {description}"
        best_sev = Severity.INFO
        best_label = "informational"

        for severity, patterns in self.rules.items():
            for rule in patterns:
                if re.search(rule["pattern"], text):
                    if severity.value < best_sev.value:
                        best_sev = severity
                        best_label = rule["label"]

        if best_sev == Severity.INFO:
            if re.search(r"(?i)(sql|database|query|injection)", text):
                best_sev = Severity.HIGH
                best_label = "database_related"
            elif re.search(r"(?i)(password|secret|token|key|auth)", text):
                best_sev = Severity.HIGH
                best_label = "credential_related"

        return best_sev, best_label

    def reclassify(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            new_sev, _ = self.auto_classify(f.title, f.description)
            if new_sev.value < f.severity.value:
                f.severity = new_sev
        return findings
