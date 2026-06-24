# PROMPT DE VALIDACIÓN

## Contexto

Eres un arquitecto de software senior especializado en herramientas de pentesting automatizadas. Necesito que analices un programa llamado **Skoll** (también llamado Yggdrasil/Ragnarök), identifiques sus problemas raíz, y valides o corrijas mi plan de soluciones.

## ¿Qué es Skoll?

Skoll es un pipeline autónomo de pentesting de 8 fases con 58+ engines especializados, 7 workers ProjectDiscovery, sistema de skills, base de conocimiento, web UI con temática nórdica, e integración pymetasploit3 RPC.

Arquitectura actual:
- **8 fases**: RECON → ENUM → VALIDATE → ANALYZE → EXPLOIT → CHAIN → REPORT → COMPLETE
- **58 engines** en `skoll_agent/engines/` (ej: nmap_engine.py, nuclei_engine.py, httpx_engine.py, etc.)
- **7 workers** en `skoll_agent/workers/` (subfinder, amass, naabu, httpx, katana, ffuf, nuclei) + 2 fallback (nmap, gobuster)
- **PipelineOrchestrator** (1847 líneas, `pipeline/orchestrator.py`) — llama engines vía `_run_tool("nombre", target, phase)`
- **WorkflowManager** (250 líneas, `workers/manager.py`) — llama workers vía `_run_worker("nombre", WorkerClass(), target, kwargs)`
- **RagnarokEngine** (`engines/ragnarok_engine.py`) — wrapper que usa WorkflowManager para la web UI
- **Web server**: dos endpoints — `/api/ragnarok/scan` (vía RagnarokEngine) y `/api/v2/start` (vía PipelineOrchestrator)
- **Motor LLM**: 11 agentes especializados con modelos diferentes, más un cerebro 70b para consenso

Tecnologías: Python 3.10+, ProjectDiscovery suite (naabu, httpx, katana, nuclei), nmap, masscan, ffuf, gobuster, nikto, sqlmap, hydra, whatweb, pymetasploit3, OpenRouter API, PostgreSQL (Docker pgvector).

## Problemas Identificados

### 1. ARQUITECTURA DUPLICADA (causa raíz principal)

Existen **dos implementaciones paralelas** para 9 herramientas. Cada una con flags distintos, parsing distinto, timeouts distintos:

| Tool | Worker (usa Ragnarök) | Engine (usa PipelineOrch.) |
|------|----------------------|---------------------------|
| naabu | `naabu -host TARGET -json -silent` | Delegaba al worker (mismos args) |
| nmap | `nmap -sV -T4 --open -oG -` | `nmap -sV -sC --min-rate 5000 -T5 -oX -` |
| katana | `katana -j -silent -jc -d 3` | Delegaba al worker (mismos args) |
| nuclei | `nuclei -j -rl 150 -severity medium,high,critical` | `nuclei -json -rl 50` ← flags distintos |
| gobuster | `gobuster dir -q -t 20` | `gobuster dir -t 30 -o gusbuster.txt --retry` |
| ffuf | `ffuf -json -ac -t 50` | `ffuf -of json -o /tmp/ffuf_output.json` |
| httpx | `httpx -j -sc -title -td` | **NO EXISTE** ← crash |

**Consecuencia**: Arreglas un bug en workers → engines siguen rotos y viceversa. El doble de bugs por herramienta.

### 2. HTTPX NO TIENE ENGINE

`httpx_engine.py` no existía. `engines/__init__.py` no registraba httpx. Cuando `PipelineOrchestrator._run_tool("httpx", ...)` se ejecuta (desde web_v2.py), explota con `KeyError: Engine 'httpx' not found`. Esto significa que el pipeline v2 **nunca ha podido ejecutar httpx**.

### 3. TIMEOUTS ABSURDOS

| Herramienta | Timeout | Tiempo real necesario | Consecuencia |
|------------|---------|----------------------|--------------|
| nikto | 60s (pero internamente `-maxtime 15m`) | 2-10 min | **Siempre matado antes de terminar** |
| hydra | **60s** | 5-30 min | Mata el brute-force antes de probar 10 contraseñas |
| sqlmap | **120s** | 5-30 min por parámetro | Nunca completa ni un test |
| katana (worker) | **60s** | 2-5 min para crawling completo | Timeout antes de encontrar rutas profundas |

**Nikto es el caso más grave**: timeout de 60s para una herramienta diseñada para escaneos de 15 minutos.

### 4. DNS TOOLS CONTRA IPS

`subfinder` y `amass` se ejecutan contra `127.0.0.1` (una IP). Son herramientas DNS que esperan un dominio. Se cuelgan 300s hasta timeout. Y el WorkflowManager corre todo secuencial, así que el pipeline entero espera 5+ minutos antes siquiera de empezar el escaneo de puertos.

### 5. TEMP FILES COMPARTIDOS = CORRUPCIÓN

- `ffuf_engine.py`: `/tmp/ffuf_output.json`
- `masscan_engine.py`: `/tmp/masscan_output.json`
- `gobuster_engine.py`: `gusbuster.txt` en CWD
- `nikto_engine.py`: `nikto_thm.txt` en CWD

Dos escaneos en paralelo → se pisan los ficheros → resultados mezclados.

### 6. MSFRPCD ES INSERVIBLE

- `msfrpcd` con flag `-S` (SSL) pero cliente Python conecta con `ssl=False` → mismatch
- Consume 80% CPU al iniciar
- Puerto 55554 nunca abre realmente
- `console.read()` devuelve "Error in input stream"
- Timeout de startup: 30 segundos de espera
- El proceso nunca funciona de forma fiable

### 7. NAABU CAMPO ADDRESS VS IP

naabu JSON output usa campo `ip`, no `address`. El worker usaba `obj.get("address", "")` que siempre devolvía string vacío.

### 8. 11 AGENTES LLM DONDE 8 SON REDUNDANTES

De los 11 agentes especializados, 8 caen siempre al mismo fallback (`llama-3.3-70b-versatile`). Esto significa:
- Pagas 11 llamadas a API
- 8 son idénticas (mismo modelo con prompts diferentes)
- El "cerebro 70b" hace el mismo trabajo que los 8 agentes fallback

Los agentes con modelos distintos que SÍ aportan valor:
1. **web_security** (qwen3-32b) — análisis web OWASP
2. **network_infra** (deepseek-r1-70b) — infraestructura de red
3. **cve_researcher** (qwen3.6-27b) — correlación CVE-versión
4. **extractor** (llama-3.1-8b) — parseo de output

Los 7 restantes (credential_auditor, exploit_planner, config_auditor, fp_validator, webapp_scanner, lateral_movement, quick_scanner) siempre caen a fallback 70b, haciéndolos redundantes.

### 9. FALTA AIRecon: ADAPTIVE LEARNING

AIRecon (pikpikcu/airecon) tiene características que Skoll no tiene:
- **Adaptive learning**: registra qué tools funcionan y prioriza las que encuentran resultados
- **WAF bypass/detection**: detecta y evade firewalls
- **Chain planner**: encadena hallazgos low en rutas de ataque high
- **Correlation engine**: correlaciona findings entre fases
- **Skills KB**: ficheros markdown con prompts por tecnología (WordPress, Django, Laravel...)
- **100% offline**: LLM local con Ollama, sin API keys

---

## Mi Propuesta de Solución

### Inmediatas (SEMANA 1 — YA IMPLEMENTADAS)

**1.1. Crear httpx_engine.py** ✅
Portar `httpx_worker.py` a `BaseEngine` pattern con `shutil.which()` + `TOOL_ALIASES` (httpx-toolkit primero, httpx después). Registrar en `engines/__init__.py`.

**1.2. Unificar naabu_engine.py y katana_engine.py** ✅
Eliminar dependencia de workers. Inline directo con `shutil.which()` + `subprocess.run()`. Campo `address`→`ip` en naabu.

**1.3. Timeouts realistas** ✅
- nikto: 60s → 600s, eliminar `-maxtime 15m` redundante
- hydra: 60s → 600s
- sqlmap: 120s → 600s
- nuclei engine: 300s → 120s, flags `-json`→`-j`, `-rl 50`→`-rl 150`

**1.4. DNS detection** ✅
subfinder/amass detectan target IP (regex `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`) → skip con log.

**1.5. Temp files** ✅
ffuf, masscan, gobuster, msf_manager: reemplazar rutas fijas por `tempfile.mkstemp()` con cleanup en `finally`.

**1.6. MSFRPCD fail fast** ✅
- Eliminar flag `-S` (SSL mismatch con `ssl=False`)
- Timeout startup 30s → 8s
- Si falla, matar proceso y usar subprocess `msfconsole -r` directamente

### Siguientes (SEMANA 2 — PENDIENTES)

**2.1. Eliminar workers/** y migrar WorkflowManager a engines
Actualmente `workers/manager.py` y `engines/ragnarok_engine.py` dependen de workers. Hay que:
1. Mover la lógica de `WorkflowManager.run_all()` a usar engines vía `get_engine()` + `engine.scan()`
2. Convertir `WorkerResult` a `EngineResult` en el manager
3. Eliminar workers/ y workers/__init__.py
4. Dejar RagnarokEngine como wrapper que llama engines directamente

**2.2. Reducir 11 agentes LLM a 4**
Mantener solo: web_security, network_infra, cve_researcher, extractor. Los 7 restantes no aportan valor porque siempre caen al mismo fallback 70b.

**2.3. Añadir test de integración contra DVWA**
Test que ejecuta pipeline completo contra DVWA Docker y verifica >0 puertos, endpoints, findings.

**2.4. Añadir adaptive learning (AIRecon style)**
Registrar en base de datos qué tools encuentran resultados vs cuáles fallan. Priorizar tools efectivas. Similar a cómo AIRecon adapta su pipeline según resultados previos.

### Futuras (SEMANA 3)

**3.1. API Auditing**: módulo OpenAPI spec parser + OWASP API Top 10 checks
**3.2. Nuclei KEV**: priorizar templates CISA Known Exploited Vulnerabilities
**3.3. Skills KB**: sistema de prompts markdown por tecnología detectada (WordPress, Django, Laravel...)
**3.4. Offline AI**: soporte Ollama para ejecución 100% offline sin API keys

---

## Lo que Necesito de Ti

1. **Valida mi análisis de causas raíz.** ¿Hay algo que se me escape? ¿Estoy diagnosticando correctamente?
2. **Critica mis soluciones.** ¿Hay soluciones mejores? ¿Algo que vaya a romper algo?
3. **Compara con AIRecon (pikpikcu/airecon).** AIRecon tiene pipeline RECON→ANALYSIS→EXPLOIT→REPORT (4 fases), adaptive learning, skills KB, 100% offline. ¿Debería Skoll converger a esa arquitectura más simple?
4. **Evalúa la priorización.** ¿Estoy atacando los problemas correctos primero?
5. **Detecta lo que falta.** ¿Hay problemas arquitectónicos que no he identificado?

Responde en español, estructurado en secciones. Sé crítico y directo — necesito detectar puntos ciegos, no aprobación.
