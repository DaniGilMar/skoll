#!/usr/bin/env python3
"""Skoll test — verifica todos los componentes nuevos del pipeline."""
import json
import os
import sys
import time

sys.path.insert(0, "/opt/skoll")
os.environ.setdefault("GROQ_API_KEY", open("/opt/skoll/.env").read().split("=", 1)[1].strip().split("\n")[0])
os.environ.setdefault("AI_PROVIDER", "groq")

PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  ✅ {name}")
    except Exception as e:
        FAIL += 1
        print(f"  ❌ {name}: {e}")

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ====================================================================
section("1. CONFIGURACIÓN")
# ====================================================================

def test_config():
    from skoll.config import (
        DEFAULT_PROVIDER, DEFAULT_GROQ_MODEL, GROQ_FAST_MODEL,
        GROQ_MODELS, get_fast_model,
    )
    assert DEFAULT_PROVIDER == "groq", f"Provider should be groq: {DEFAULT_PROVIDER}"
    assert DEFAULT_GROQ_MODEL == "llama-3.3-70b-versatile"
    assert GROQ_FAST_MODEL == "llama-3.1-8b-instant"
    fast = get_fast_model("groq")
    assert fast == "llama-3.1-8b-instant"

test("Config groq por defecto", test_config)

def test_groq_key():
    key = os.environ.get("GROQ_API_KEY") or open("/opt/skoll/.env").read()
    assert len(key) > 10 and "gsk_" in key

test("API Key Groq presente", test_groq_key)

# ====================================================================
section("2. CLIENTE GROQ (MULTI-MODEL)")
# ====================================================================

def test_groq_client():
    from skoll.client import GroqClient
    c = GroqClient()
    assert hasattr(c, "analyze"), "Need analyze()"
    assert hasattr(c, "analyze_fast"), "Need analyze_fast()"
    assert hasattr(c, "analyze_with_fallback"), "Need analyze_with_fallback()"
    assert hasattr(c, "analizar_codigo_stream"), "Need analizar_codigo_stream()"

test("GroqClient se instancia", test_groq_client)

def test_groq_real_simple():
    from skoll.client import GroqClient
    c = GroqClient()
    resp = c.analyze("Responde solo: OK", model="llama-3.1-8b-instant")
    assert "OK" in resp or "ok" in resp, f"Expected OK in response: {resp[:200]}"
    print(f"    8B response: {resp.strip()[:100]}")

test("Groq 8B real (simple)", test_groq_real_simple)

def test_groq_with_fallback():
    from skoll.client import GroqClient
    c = GroqClient()
    resp, model = c.analyze_with_fallback("Responde solo: FALLBACK_OK")
    assert resp and len(resp) > 0, f"Empty response from {model}"
    assert model != "none", f"Fallback failed: {model}"
    print(f"    Fallback response model={model}, text={resp.strip()[:80]}")

test("Groq analyze_with_fallback", test_groq_with_fallback)

# ====================================================================
section("3. TIERS / GUIDANCE")
# ====================================================================

def test_all_tiers():
    from skoll_agent.pipeline.orchestrator import _load_tier
    required = [
        "pentest-methodology.md",
        "exploit-guidance.md",
        "evidence-guide.md",
        "recovery.md",
        "ctf-playbook.md",
    ]
    for name in required:
        c = _load_tier(name)
        assert len(c) > 200, f"{name} too short: {len(c)}"
    # Check specific content
    m = _load_tier("pentest-methodology.md")
    assert "CVSS" in m, "pentest-methodology missing CVSS"
    assert "FTP" in m or "HTTP" in m, "pentest-methodology missing service guide"
    e = _load_tier("exploit-guidance.md")
    assert "WAF" in e, "exploit-guidance missing WAF"
    assert "Blocked" in e, "exploit-guidance missing Blocked"
    r = _load_tier("recovery.md")
    assert "Connection refused" in r, "recovery missing Connection refused"
    assert "RECON" in r, "recovery missing RECON"

test("Todos los tiers cargan y tienen contenido", test_all_tiers)

# ====================================================================
section("4. SAGE MEMORY")
# ====================================================================

def test_sage():
    from skoll_agent.memory.sage import (
        store_scan_result, recall_context_for_scan,
        format_sage_context, clear_target,
    )
    clear_target("test-sage-target")
    # Store
    store_scan_result(
        "test-sage-target", "recon",
        [{"title": "port 80 open", "severity": "high"}],
        [{"port": 80, "protocol": "tcp", "service": "http"}],
        "scan complete",
    )
    # Recall
    ctx = recall_context_for_scan("test-sage-target")
    assert len(ctx) == 1, f"Expected 1 session, got {len(ctx)}"
    assert ctx[0]["findings_count"] == 1
    # Format
    txt = format_sage_context("test-sage-target")
    assert "test-sage-target" in txt, f"Missing target in context: {txt}"
    assert "Session 1" in txt, f"Missing session in context"
    # Store second session
    store_scan_result(
        "test-sage-target", "enum",
        [{"title": "gobuster found /admin", "severity": "medium"}],
        [{"port": 80, "protocol": "tcp", "service": "http"}],
        "enum complete",
    )
    ctx2 = recall_context_for_scan("test-sage-target")
    assert len(ctx2) == 2, f"Expected 2 sessions, got {len(ctx2)}"
    clear_target("test-sage-target")
    ctx3 = recall_context_for_scan("test-sage-target")
    assert len(ctx3) == 0, "Should be empty after clear"

test("SAGE store/recall/clear", test_sage)

# ====================================================================
section("5. PIPELINE ORCHESTRATOR")
# ====================================================================

def test_orchestrator_init():
    from skoll_agent.pipeline import PipelineOrchestrator
    events = []
    o = PipelineOrchestrator(target="10.10.10.1", is_network=True, event_callback=lambda t, d: events.append((t, d)))
    assert o.target == "10.10.10.1"
    assert o.is_network
    assert o.llm is None
    assert o.pipeline is not None
    # SAGE recall is called at start of run (not init)
    # Phase list (lazy initialized)
    ph = o.pipeline.get_phase
    for pid_name in ["RECON", "ENUM", "VALIDATE", "ANALYZE", "EXPLOIT", "CHAIN", "REPORT", "COMPLETE"]:
        from skoll_agent.pipeline.models import PhaseId
        pid = getattr(PhaseId, pid_name)
        p = ph(pid)
        assert p is not None

test("PipelineOrchestrator init", test_orchestrator_init)

def test_orchestrator_llm_analyze():
    from skoll.client import GroqClient
    from skoll_agent.pipeline import PipelineOrchestrator
    c = GroqClient()
    o = PipelineOrchestrator(target="test", is_network=False, llm_client=c)
    resp, model = o._llm_analyze("Responde solo: LLM_WORKS")
    assert resp and len(resp) > 0, f"Empty response"
    assert model != "none", f"Both models failed: {model}"

test("_llm_analyze con Groq real", test_orchestrator_llm_analyze)

def test_orchestrator_json_parse():
    from skoll_agent.pipeline import PipelineOrchestrator
    o = PipelineOrchestrator(target="test")
    r = o._parse_json('```json\n{"test": true}\n```')
    assert r and r.get("test") is True, f"Failed to parse json block: {r}"
    r2 = o._parse_json('{"test2": 42}')
    assert r2 and r2["test2"] == 42, f"Failed to parse bare json: {r2}"
    r3 = o._parse_json("no json here")
    assert r3 is None, f"Should return None for non-json: {r3}"

test("_parse_json", test_orchestrator_json_parse)

def test_flag_detection():
    from skoll_agent.engines.flag_engine import FlagEngine
    e = FlagEngine()
    result = e.scan("test", text="found flag{test123} and CTF{example} and THM{tryhackme}")
    assert len(result.findings) >= 3, f"Expected 3+ flags, got {len(result.findings)}: {result.findings}"
    values = [f.get("flag_value", "") for f in result.findings]
    assert "flag{test123}" in values, f"flag not found in {values}"
    assert "CTF{example}" in values, f"CTF not found in {values}"
    assert "THM{tryhackme}" in values, f"THM not found in {values}"

test("Flag detection (flag_engine)", test_flag_detection)

# ====================================================================
section("6. ENGINES")
# ====================================================================

EXPECTED_ENGINES = [
    "nmap", "gobuster", "nikto", "ftp", "smb", "flag", "hydra",
    "sqlmap", "whatweb", "nuclei", "bandit", "semgrep", "cve",
    "ffuf", "masscan", "smbmap", "redis", "mysql", "postgres", "davtest",
    "enum4linux", "cadaver", "msfconsole", "exploit_dispatcher",
]

def test_all_engines_import():
    from skoll_agent.engines.registry import get_engine, list_engines
    engines = list_engines()
    assert len(engines) >= len(EXPECTED_ENGINES), (
        f"Expected {len(EXPECTED_ENGINES)}+ engines, got {len(engines)}: {list(engines.keys())}"
    )
    for name in EXPECTED_ENGINES:
        cls = get_engine(name)
        e = cls()
        assert e.name == name

test(f"{len(EXPECTED_ENGINES)} engines importan e instancian", test_all_engines_import)

def test_flag_engine():
    from skoll_agent.engines.flag_engine import FlagEngine
    e = FlagEngine()
    r = e.scan("test", text="this contains flag{test123} and HTB{example}")
    assert r.success
    assert len(r.findings) >= 2, f"Expected 2+ findings, got {len(r.findings)}"
    assert "flag{test123}" in r.raw_output
    assert "HTB{example}" in r.raw_output

test("FlagEngine detecta flags en texto", test_flag_engine)

# ====================================================================
section("7. REASONING LOOP (COMPAT)")
# ====================================================================

def test_reasoning_loop():
    from skoll_agent.brain.reasoning_loop import ReasoningLoop
    events = []
    rl = ReasoningLoop(
        None, "10.10.10.1",
        event_callback=lambda t, d: events.append((t, d)),
        is_network_target=True,
    )
    assert rl.is_network
    assert rl.project_path == "10.10.10.1"
    assert rl.orchestrator is not None
    assert rl.orchestrator.target == "10.10.10.1"
    # session_id setter propagation
    rl.session_id = "compat-test"
    assert rl.orchestrator.session_id == "compat-test"

test("ReasoningLoop backwards compat", test_reasoning_loop)

# ====================================================================
section("8. WEB SERVER (IMPORT)")
# ====================================================================

def test_web_server():
    import skoll.web_server as ws
    assert ws._AGENT_MODULE_OK

test("Web server importa correctamente", test_web_server)

# ====================================================================
section(f"\nRESULTADOS: {PASS} pasaron, {FAIL} fallaron")
# ====================================================================

sys.exit(0 if FAIL == 0 else 1)
