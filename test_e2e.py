#!/usr/bin/env python3
"""End-to-end test del pipeline Ragnarök contra DVWA en localhost."""

import json
import os
import sys
import time
import traceback

# API keys are loaded from .env file or environment variables

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skoll_agent.pipeline import PipelineOrchestrator
from skoll_agent.pipeline.models import PhaseStatus, PhaseId
from skoll_agent.llm import LLMRouter

print("Importing LLMRouter...", flush=True)
client = LLMRouter()
print(f"  LLM router OK: {len(client._providers)} providers", flush=True)
for p in client._providers:
    print(f"    - {p.name}", flush=True)

events = []

def event_cb(etype, data):
    events.append((etype, data))
    if etype == "agent_log":
        msg = data.get("message", "")
        if msg:
            print(f"  {msg}", flush=True)
    elif etype == "agent_tool_start":
        print(f"  >>> {data.get('tool', '?')} -> {data.get('target', '?')}", flush=True)
    elif etype == "agent_tool_result":
        s = data.get("summary", "")
        if s:
            print(f"  <<< {data.get('tool', '?')}: {s[:200]}", flush=True)
    elif etype == "agent_finding":
        print(f"  FIND [{data.get('severity','?')}] {data.get('title','')[:120]}", flush=True)

print("=" * 70, flush=True)
print("RAGNAROK PIPELINE - END-TO-END TEST", flush=True)
print(f"Target: 127.0.0.1 (DVWA)", flush=True)
print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
print("=" * 70, flush=True)

orchestrator = PipelineOrchestrator(
    target="127.0.0.1",
    is_network=True,
    llm_client=client,
    event_callback=event_cb,
)

start = time.time()
try:
    orchestrator.run()
except KeyboardInterrupt:
    print("\nInterrupted by user", flush=True)
except Exception as e:
    print(f"\nERROR: {e}", flush=True)
    traceback.print_exc()

elapsed = time.time() - start

p = orchestrator.pipeline
phase_statuses = {}
for pid_name in ["RECON", "ENUM", "VALIDATE", "ANALYZE", "EXPLOIT", "CHAIN", "REPORT", "COMPLETE"]:
    try:
        pid = getattr(PhaseId, pid_name)
        pr = p.get_phase(pid)
        phase_statuses[pid_name] = {
            "status": pr.status.value,
            "summary": pr.summary[:200] if pr.summary else "",
        }
    except Exception as e:
        phase_statuses[pid_name] = {"status": "error", "summary": str(e)}

total = len(p.all_findings)
crit = sum(1 for f in p.all_findings if f.get("severity") == "critical")
high = sum(1 for f in p.all_findings if f.get("severity") == "high")

print(flush=True)
print("=" * 70, flush=True)
print("RESULTS", flush=True)
print("=" * 70, flush=True)
print(f"Time: {elapsed:.1f}s", flush=True)
print(f"Findings: {total} (critical: {crit}, high: {high})", flush=True)
print(flush=True)
for name, st in phase_statuses.items():
    icon = {"completed": "OK", "skipped": "SKIP", "failed": "FAIL", "pending": "WAIT"}.get(st["status"], "??")
    print(f"  [{icon}] {name}: {st['summary'][:120]}", flush=True)

result = {
    "target": "127.0.0.1",
    "elapsed": elapsed,
    "total_findings": total,
    "critical": crit,
    "high": high,
    "phases": phase_statuses,
    "events_count": len(events),
}
with open("/tmp/ragnarok_e2e_result.json", "w") as f:
    json.dump(result, f, indent=2, default=str)
print(f"\nResults saved to /tmp/ragnarok_e2e_result.json", flush=True)
