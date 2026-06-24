from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from skoll_agent.engines.service_map import ToolBinding, tools_for_service, tools_for_port


@dataclass
class ToolPlan:
    """A single tool invocation within a phase."""
    tool_name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class PhasePlan:
    """Execution plan for a single pipeline phase."""
    tools: list[ToolPlan] = field(default_factory=list)
    fallback: list[ToolPlan] = field(default_factory=list)
    skip: bool = False
    skip_reason: str = ""


class AdaptiveRouter:
    """Given the current context (open ports, findings, etc.),
    decide which tools to run in the next phase.
    """

    # Tools that should always run regardless of what was found.
    ALWAYS_RUN: dict[str, list[ToolPlan]] = {
        "recon": [
            ToolPlan("naabu", {"top_ports": 1000, "timeout": 120}),
        ],
    }

    ALWAYS_FALLBACK: dict[str, list[ToolPlan]] = {
        "recon": [
            ToolPlan("masscan", {"rate": 1000, "timeout": 60}),
            ToolPlan("nmap", {"timeout": 600}),
        ],
    }

    def route(self, phase_name: str, context: dict) -> PhasePlan:
        handler = getattr(self, f"_route_{phase_name}", None)
        if handler:
            return handler(context)
        return PhasePlan()

    # ── phase routers ───────────────────────────────────────────

    def _route_recon(self, ctx: dict) -> PhasePlan:
        return PhasePlan(
            tools=list(self.ALWAYS_RUN.get("recon", [])),
            fallback=list(self.ALWAYS_FALLBACK.get("recon", [])),
        )

    def _route_analyze(self, ctx: dict) -> PhasePlan:
        open_ports = ctx.get("open_ports", [])
        if not open_ports:
            return PhasePlan(skip=True, skip_reason="No open ports to analyze")

        tools: list[ToolPlan] = []

        for p in open_ports:
            svc = (p.get("service") or "").lower()
            port = p.get("port", 0)
            for tb in tools_for_service(svc) if svc else tools_for_port(port):
                if tb.tool_name == "gobuster":
                    url = f"http://{ctx.get('target_ip', '127.0.0.1')}:{port}"
                    tools.append(ToolPlan("gobuster", dict(tb.params, url=url)))
                else:
                    tools.append(ToolPlan(tb.tool_name, dict(tb.params)))

        open_port_nums = sorted({p.get("port", 0) for p in open_ports})
        tools.append(ToolPlan("nmap", {"ports": ",".join(str(n) for n in open_port_nums), "service_scan": True, "timeout": 90}))

        # Deduplicate by (tool_name, url) — gobuster runs per port, others run once
        seen: set[str] = set()
        deduped: list[ToolPlan] = []
        for t in tools:
            key = t.tool_name
            if t.tool_name == "gobuster":
                key = f"gobuster:{t.params.get('url', '')}"
            if key not in seen:
                seen.add(key)
                deduped.append(t)

        return PhasePlan(tools=deduped)

    def _route_exploit(self, ctx: dict) -> PhasePlan:
        findings = ctx.get("all_findings", ctx.get("findings", []))
        credentials = ctx.get("credentials", [])
        web_services = ctx.get("web_services", [])
        open_ports = ctx.get("open_ports", [])

        if not findings and not web_services:
            return PhasePlan(skip=True, skip_reason="No findings or web services to exploit")

        tools: list[ToolPlan] = []

        # Classify findings and look up strategies from YAML
        from skoll_agent.exploit.finding_classifier import classify_findings
        from skoll_agent.exploit.strategy_loader import load_strategies, get_strategies_for
        strategies = load_strategies()

        # Track which strategies we've already added to avoid duplicates
        seen_strategies: set[str] = set()

        classified = classify_findings(findings)
        for vuln_type, confidence, original_finding in classified:
            if confidence < 0.3:
                continue  # skip low-confidence classifications
            for strategy in get_strategies_for(vuln_type, strategies):
                sid = strategy["strategy_id"]
                if sid in seen_strategies:
                    continue
                seen_strategies.add(sid)

                # Check prerequisites
                prereqs = strategy.get("prerequisites", [])
                prereqs_met = True
                for p in prereqs:
                    if p == "ajp_port_open" and not any(o.get("port") == 8009 for o in open_ports):
                        prereqs_met = False

                if not prereqs_met:
                    continue

                # Resolve params — inject finding/target data
                params = dict(strategy["params"])
                for k, v in params.items():
                    if isinstance(v, str):
                        params[k] = v.replace("{target.ip}", ctx.get("target_ip", ""))
                    elif isinstance(v, list):
                        resolved = []
                        for item in v:
                            if isinstance(item, dict):
                                resolved.append({
                                    ik: iv.replace("{target.ip}", ctx.get("target_ip", ""))
                                    if isinstance(iv, str) else iv
                                    for ik, iv in item.items()
                                })
                            else:
                                resolved.append(item)
                        params[k] = resolved

                # Resolve SMB share from finding if applicable
                if strategy["executor"] == "smb" and params.get("action") == "download":
                    share = original_finding.get("share", "")
                    if share:
                        params["share"] = share

                tools.append(ToolPlan(strategy["executor"], params))

        # Legacy fallback: nuclei always
        tools.append(ToolPlan("nuclei", {"severity": "medium,high,critical", "timeout": 120}))

        # Legacy fallback: cve2msf if CVEs found
        cves_in_findings = self._extract_cves(findings)
        if cves_in_findings:
            tools.append(ToolPlan("cve2msf", {
                "findings": findings,
                "confirmed_cves": cves_in_findings[:10],
                "ports": open_ports,
            }))
            tools.append(ToolPlan("exploit_dispatcher", {
                "findings": findings,
                "confirmed_cves": cves_in_findings[:10],
                "ports": open_ports,
            }))

        return PhasePlan(tools=tools)

    @staticmethod
    def _extract_cves(findings: list[dict]) -> list[str]:
        import re
        pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        cves: set[str] = set()
        for f in findings:
            for text in (str(f.get("title", "")), str(f.get("description", "")), str(f.get("cve_id", ""))):
                for m in pattern.finditer(text):
                    cves.add(m.group(0).upper())
        return sorted(cves)

    def _route_report(self, ctx: dict) -> PhasePlan:
        return PhasePlan(tools=[ToolPlan("reporting", {})])

    # ── skip logic ──────────────────────────────────────────────

    def should_skip(self, phase_name: str, context: dict) -> tuple[bool, str]:
        plan = self.route(phase_name, context)
        return plan.skip, plan.skip_reason


import json  # noqa: E402 (needed for dedup above)
