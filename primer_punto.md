# Skoll Agent — Informe de Arquitectura (Punto 1)

## Resumen Ejecutivo

Se ha transformado Skoll de una herramienta CLI de auditoría estática en un **Agente de Seguridad Autónomo** con capacidad de razonamiento (ReAct Loop), orquestación de herramientas, memoria persistente y ejecución aislada. El código existente (`auditor_ai/`) se mantiene intacto y convive con la nueva arquitectura modular (`skoll_agent/`).

---

## 1. Filosofía del Diseño

### Principios rectores

| Principio | Implementación |
|---|---|
| **Modularidad** | Separación en 7 capzas: brain/engines/actions/skills/memory/sandbox/reporting |
| **Agnosticismo de herramientas** | `BaseEngine` define interfaz abstracta; cualquier escáner se añade con un conector |
| **Seguridad por defecto** | `HumanInLoop` gate antes de acciones destructivas; `DockerSandbox` para aislamiento |
| **Persistencia** | `FindingsDB` guarda hallazgos en JSON; `AgentState` mantiene el ciclo de vida |
| **Extensibilidad** | `SkillRegistry` permite registrar nuevas habilidades sin tocar el núcleo |

### ¿Qué problema resuelve?

Antes: Skoll ejecutaba escaneos de forma lineal (el usuario elige archivo → herramienta → reporte).

Ahora: Skoll **razona** sobre el proyecto, **decide** qué archivos son prioritarios, **ejecuta** escaneos, **interpreta** resultados, y **decide** el siguiente paso — todo en un bucle autónomo.

---

## 2. Estructura de Directorios

```
skoll_agent/                         ← Núcleo del agente autónomo
├── __init__.py                      ← Auto-registra skills al importar
├── agent.py                         ← Entry point público (run_agent, run_sandboxed_agent)
│
├── brain/                           ← 🧠 CAPA DE RAZONAMIENTO
│   ├── reasoning_loop.py            ← Bucle ReAct (Think → Act → Observe)
│   ├── context.py                   ← Indexación del proyecto con risk scoring
│   └── planner.py                   ← Planificador estratégico de tareas vía LLM
│
├── engines/                         🔧 ORQUESTADOR DE HERRAMIENTAS
│   ├── base_engine.py               ← Interfaz abstracta (EngineResult, scan, parse_output)
│   ├── bandit_engine.py             ← Conector Bandit
│   └── semgrep_engine.py            ← Conector Semgrep
│
├── actions/                         → ACCIONES DEL AGENTE
│   ├── base_action.py               ← Interfaz abstracta (ActionResult)
│   ├── scan_action.py               ← Ejecuta escaneos multi-engine
│   └── report_action.py             ← Genera reportes SARIF/JSON/Markdown
│
├── skills/                          🎯 HABILIDADES DEL AGENTE
│   ├── base_skill.py                ← Interfaz abstracta
│   └── code_analysis_skill.py       ← Skill #1: análisis autónomo de código
│
├── memory/                          💾 MEMORIA Y ESTADO
│   ├── state.py                     ← AgentState, Finding, Severity, ActionLog
│   ├── findings_db.py               ← Persistencia JSON de hallazgos
│   └── task_queue.py                ← Cola priorizada con dependencias
│
├── sandbox/                         🛡 AISLAMIENTO
│   ├── docker_sandbox.py            ← Sandbox Docker (construye imagen + ejecuta comandos)
│   └── human_in_loop.py             ← Gate de aprobación humana (interactivo)
│
├── reporting/                       📊 REPORTES UNIFICADOS
│   ├── sarif.py                     ← Builder SARIF 2.1.0 (estándar OASIS)
│   └── severity.py                  ← Clasificador automático de severidad por regex
│
└── config/                          ⚙ CONFIGURACIÓN
    ├── agent_config.py              ← Config vía variables de entorno
    └── skill_registry.py            ← Registro central de skills
```

### Integración con el código existente

```
auditor_ai/main.py                   ← [+1 comando] "skoll agent [--sandbox]"
                              Llama a → skoll_agent/agent.py:run_agent()
                                            ↓
                               Usa → auditor_ai/client.py (GeminiClient/GroqClient)
                                     auditor_ai/utils.py (file reading)
```

El código antiguo sigue funcionando exactamente igual:
- `skoll chat` → igual que antes
- `skoll analyze ./ruta` → igual que antes
- `skoll scan ./ruta --tool bandit` → igual que antes
- `skoll web` → igual que antes

**Nuevo comando:**
- `skoll agent ./ruta --provider groq` → lanza el agente autónomo

---

## 3. El Bucle de Razonamiento (ReAct Loop)

Este es el corazón del agente. Está en `brain/reasoning_loop.py`.

### Diagrama de flujo

```
┌──────────────────────────────────────────────────────────────────┐
│                        INICIO                                     │
│  1. Indexar proyecto (context.py)                                 │
│     └→ Escanea archivos, asigna risk scores                       │
│     └→ Construye estructura del proyecto                          │
└──────────────────────────┬───────────────────────────────────────┘
                           ↓
┌──────────────────────────┴───────────────────────────────────────┐
│  ┌─────────── 2. THINK  ───────────┐                             │
│  │  LLM recibe:                    │                             │
│  │  - Estado actual del agente     │                             │
│  │  - Proyecto indexado (top 20    │                             │
│  │    archivos por riesgo)         │                             │
│  │  - Skills disponibles           │                             │
│  │  - Acciones disponibles         │                             │
│  │                                 │                             │
│  │  LLM responde con JSON:         │                             │
│  │  { "reasoning": "...",          │                             │
│  │    "action": "scan_file",       │                             │
│  │    "skill": "code_analysis",    │                             │
│  │    "params": { "target": "...", │                             │
│  │                "tool": "bandit"},│                            │
│  │    "priority": "high" }         │                             │
│  └─────────────────────────────────┘                             │
└──────────────────────────┬───────────────────────────────────────┘
                           ↓
┌──────────────────────────┴───────────────────────────────────────┐
│  ┌─────────── 3. ACT   ───────────┐                             │
│  │  Se ejecuta la acción:         │                             │
│  │  - scan_file → ScanAction      │                             │
│  │  - report     → ReportAction   │                             │
│  │  - generate_patch → (esqueleto)│                             │
│  │                                 │                             │
│  │  Cada acción actualiza el      │                             │
│  │  estado del agente y añade     │                             │
│  │  hallazgos a la memoria        │                             │
│  └─────────────────────────────────┘                             │
└──────────────────────────┬───────────────────────────────────────┘
                           ↓
┌──────────────────────────┴───────────────────────────────────────┐
│  ┌────────── 4. OBSERVE ──────────┐                             │
│  │  Se registra el resultado:     │                             │
│  │  - Log de acción               │                             │
│  │  - Hallazgos agregados a       │                             │
│  │    AgentState.findings[]       │                             │
│  │  - Archivos marcados como      │                             │
│  │    escaneados                  │                             │
│  │                                 │                             │
│  │  Se verifica condición de      │                             │
│  │  terminación:                   │                             │
│  │  - ¿max_iterations alcanzado?  │                             │
│  │  - ¿acción "complete"?         │                             │
│  │  - ¿max_depth alcanzado?       │                             │
│  └─────────────────────────────────┘                             │
└──────────────────────────┬───────────────────────────────────────┘
                           ↓
              ¿Completado? ── Sí ──→ 5. RESUMEN Y REPORTE
                           │
                          No
                           ↓
                      Volver a 2. THINK
```

### Código del núcleo (simplificado)

```python
class ReasoningLoop:
    def run(self) -> AgentState:
        # Fase 1: Indexar proyecto
        self.context = index_project(self.project_path)

        # Fase 2: Bucle ReAct
        while not self.state.is_complete():
            self.state.iteration += 1

            # THINK: preguntar al LLM qué hacer
            decision = self._think()

            # ACT: ejecutar la decisión
            self._act(decision)

            # OBSERVE: el resultado queda en self.state

        return self.state

    def _think(self):
        prompt = f"""
        Estado actual: {self.state.summary_text()}
        Proyecto: {context_to_prompt(self.context)}
        ¿Cuál es el siguiente paso?
        """
        respuesta_llm = self.llm.analizar_codigo_stream(prompt)
        return self._parse_decision(respuesta_llm)
```

---

## 4. El Indexador de Contexto (Project Context)

En `brain/context.py`. Es el "mapa" que el agente usa para orientarse.

### Risk Scoring automático

Cada archivo recibe un score basado en patrones regex:

| Categoría | Patrones | Peso |
|---|---|---|
| `exec` | eval, exec, os.system, subprocess, popen | 1.5× match |
| `injection` | f-strings con variables, SQL concatenado | 1.5× |
| `secrets` | api_key, secret, password, token, PEM keys | 1.5× |
| `network` | requests, urllib, socket, http, fetch | 0.5× |
| `database` | sqlite, mysql, execute, query, cursor | 0.5× |
| `file_ops` | open, write, chmod, chown, remove | 0.5× |
| `auth` | login, jwt, oauth, session, cookie | 0.5× |

El resultado es un ranking como este (probado contra el propio proyecto):

```
Risk distribution:
  [72.0] auditor_ai/web_server.py      ⚠️ CRITICAL  (network, exec, secrets)
  [51.0] auditor_ai/verifier.py        ⚠️ CRITICAL  (exec, file_ops)
  [41.0] auditor_ai/main.py            ⚠️ CRITICAL
  [36.0] auditor_ai/static/app.js      ⚠️ CRITICAL
  ...
```

### Output para el LLM

```python
def context_to_prompt(ctx, max_files=20) -> str:
    """Genera el texto que recibe el LLM para decidir"""
```

El prompt incluye:
- Estadísticas del proyecto (archivos, líneas, lenguajes)
- Top N archivos por risk score con indicadores
- Esto permite al LLM priorizar inteligentemente

---

## 5. Motor de Herramientas (Engines)

Cada herramienta de escaneo se encapsula en un conector que implementa `BaseEngine`:

```python
class BaseEngine(ABC):
    name: str
    description: str

    @abstractmethod
    def scan(self, target: str) -> EngineResult:
        """Ejecuta el escáner y devuelve raw_output"""

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[dict]:
        """Convierte la salida raw a JSON normalizado"""

    def normalize_finding(self, raw: dict) -> dict:
        """Estandariza campos: file_path, line_start, severity, title, etc."""
```

### Engines implementados

**BanditEngine** — `python -m bandit -r target -f json -q`
- Parseo de JSON de Bandit a formato normalizado
- Timeout configurable

**SemgrepEngine** — `semgrep scan --config auto target --json --quiet`
- Parseo de JSON de Semgrep (check_id, path, start/end line, severity)
- Timeout 120s por defecto

### Para añadir un nuevo engine (ej. CodeQL):

```python
class CodeqlEngine(BaseEngine):
    name = "codeql"
    description = "CodeQL semantic code analysis"

    def scan(self, target, **kwargs):
        # Lógica específica de CodeQL
        pass

    def parse_output(self, raw_output):
        # Parsear JSON de CodeQL a formato normalizado
        pass
```

Y se usa automáticamente desde `ScanAction`.

---

## 6. Sistema de Acciones

Cada acción implementa `BaseAction`:

| Acción | Archivo | Qué hace |
|---|---|---|
| `scan_file` | `scan_action.py` | Orquesta uno o varios engines sobre un target |
| `report` | `report_action.py` | Genera reportes en SARIF/JSON/Markdown |
| `generate_patch` | (esqueleto) | Pendiente de implementar (Punto 2) |
| `validate_fix` | (esqueleto) | Pendiente de implementar (Punto 2) |

### ScanAction — El más importante

```python
class ScanAction(BaseAction):
    def execute(self, params, state, context):
        target = params.get("target")  # archivo o "all"
        tool = params.get("tool")      # bandit, semgrep, o "all"

        # Resuelve la ruta absoluta
        # Selecciona engines a ejecutar
        # Ejecuta cada engine
        # Normaliza findings al modelo Finding
        # Retorna ActionResult con findings[]
```

---

## 7. Habilidades (Skills)

Las skills agrupan acciones relacionadas que el agente puede ejecutar.

### Skill #1: CodeAnalysisSkill

```python
class CodeAnalysisSkill(BaseSkill):
    name = "code_analysis"
    description = "Static code analysis using SAST tools"

    def execute(self, action, params, state, context):
        handle_scan()       # Escanea archivos priorizados por risk score
        handle_analyze()    # Analiza hallazgos abiertos
        handle_patch()      # (esqueleto)
        handle_validate()   # (esqueleto)
        handle_report()     # Genera reporte
```

**Decisión autónoma**: cuando el agente pide `scan_file`, el skill decide:
- Si `target="all"` → escanea los top 5 archivos por risk score
- Si `target="high_risk"` → escanea todos con risk_score > 5
- Si `target="ruta/especifica.py"` → escanea ese archivo

### Cómo registrar una nueva skill

```python
from skoll_agent.config.skill_registry import register_skill
from skoll_agent.skills.base_skill import BaseSkill

class MiNuevaSkill(BaseSkill):
    name = "network_scan"
    description = "Network port scanning with Nmap"

    def execute(self, action, params, state, context):
        # implementar
        pass

register_skill("network_scan", MiNuevaSkill)
```

El agente descubrirá automáticamente la nueva skill y podrá usarla.

---

## 8. Memoria y Estado

### AgentState

```python
@dataclass
class AgentState:
    project_path: str
    iteration: int               # Iteración actual del ReAct loop
    max_iterations: int          # Default: 15
    findings: list[Finding]      # Todos los hallazgos
    action_log: list[ActionLog]  # Historial de acciones
    scanned_files: set[str]      # Archivos ya escaneados
    current_depth: int           # Profundidad de anidamiento
    completed: bool              # ¿Terminó?
```

### Finding

```python
@dataclass
class Finding:
    id: str                     # UUID único
    file_path: str              # Archivo donde se encontró
    line_start: int             # Línea inicial
    line_end: int               # Línea final
    severity: Severity          # critical/high/medium/low/info
    title: str                  # Título del hallazgo
    description: str            # Descripción detallada
    tool: str                   # Qué herramienta lo detectó (bandit, semgrep)
    rule_id: str                # ID de la regla
    status: FindingStatus       # open/verified/patched/false_positive
    remediation: str            # Código de remediación sugerido
```

### TaskQueue

Cola priorizada de tareas. El LLM puede encolar múltiples tareas y el agente las ejecuta en orden de prioridad, respetando dependencias entre tareas.

---

## 9. Seguridad: Human-in-the-Loop y Sandbox

### HumanInLoop

```python
class HumanInLoop:
    def approve(self, message: str, context: dict) -> bool:
        """Muestra panel interactivo y pide confirmación"""

    def review_findings(self, findings: list) -> list[str]:
        """Pide aprobación hallazgo por hallazgo"""
```

**Activado por defecto.** Muestra un panel en la terminal:

```
┌─────────────────────────────────────┐
│ ⚠ Human Review Required            │
│                                     │
| Action: generate_patch              │
│ Reasoning: SQL injection found in   │
│   db.py:15, generating patch        │
│                                     │
│ ¿Aprobar esta acción? [y/N]:        │
└─────────────────────────────────────┘
```

Se desactiva con `AGENT_HUMAN_IN_LOOP=false`.

### DockerSandbox

```python
class DockerSandbox:
    def ensure_image(self) -> bool
        """Construye imagen skoll-sandbox si no existe"""

    def run_in_sandbox(self, project_path, command) -> dict
        """Monta el proyecto en /workspace y ejecuta comando"""

    def scan_in_sandbox(self, project_path, tool) -> dict
        """Ejecuta escaneo dentro del contenedor"""
```

La imagen sandbox incluye Python 3.11 + Bandit + Semgrep. El proyecto se monta como bind mount en `/workspace`.

---

## 10. Reportes SARIF

El módulo `reporting/sarif.py` genera reportes en formato **SARIF 2.1.0** (estándar OASIS), compatible con GitHub Advanced Security, VS Code, y otras herramientas.

```python
builder = SARIFBuilder()
builder.add_tool("skoll-agent", "0.1.0")
for finding in state.findings:
    builder.add_result(finding)
sarif_doc = builder.build()
# Guardar como report.sarif
```

### SeverityValidator

Clasificador automático que aplica regex sobre el título y descripción de cada hallazgo para **re-clasificar la severidad**:

```python
validator = SeverityValidator()
new_sev, label = validator.auto_classify("SQL Injection", "User input in query")
# → Severity.CRITICAL, "sql_injection"
```

---

## 11. Integración CLI

```bash
# Modo autónomo completo
skoll agent ./mi-proyecto --provider groq

# Modo autónomo con sandbox Docker
skoll agent ./mi-proyecto --sandbox

# Especificar modelo
skoll agent . --provider groq --model llama-3.3-70b-versatile
```

### Ejemplo de ejecución

```
$ skoll agent /opt/skoll/ejemplo_vulnerable.py --provider groq

🛡 Skoll Autonomous Security Agent
   Provider: groq | Model: llama-3.3-70b-versatile
   Project: /opt/skoll/ejemplo_vulnerable.py
   Max iterations: 15 | Human-in-loop: True
   Skills: code_analysis

✓ Proyecto indexado: 1 archivos, 17 líneas
⚠ Archivos alto riesgo: 1

─── Iteración 1/15 ───
Razonamiento: The file shows SQL injection via string concatenation
  and hardcoded API key. Starting with Bandit scan.
✅ scan_file → Scanned 1 file, found 2 vulnerabilities

─── Iteración 2/15 ───
Razonamiento: Found SQL injection in buscar_usuario() and hardcoded
  secret. Analyzing findings for prioritization.
✅ analyze_findings → Analysis: 2 critical/high, 0 medium, 0 low
...
```

---

## 12. Variables de Entorno

| Variable | Default | Descripción |
|---|---|---|
| `AI_PROVIDER` | `gemini` | Proveedor IA (gemini/groq) |
| `AGENT_MODEL` | (default del provider) | Modelo específico |
| `AGENT_MAX_ITERATIONS` | `15` | Iteraciones máximas del ReAct loop |
| `AGENT_MAX_DEPTH` | `3` | Profundidad máxima de anidamiento |
| `AGENT_HUMAN_IN_LOOP` | `true` | Activar gate de aprobación humana |
| `AGENT_SANDBOX` | `true` | Activar sandbox Docker |
| `AGENT_AUTO_PATCH` | `false` | Permitir parches automáticos |
| `AGENT_ENGINES` | `bandit,semgrep` | Engines activos |
| `AGENT_OUTPUT_DIR` | `./reports` | Directorio de reportes |
| `AGENT_PROJECT_MAX_CHARS` | `200000` | Máximo de caracteres a indexar |

---

## 13. Resumen de Archivos Creados (30)

| Archivo | Líneas | Propósito |
|---|---|---|
| `skoll_agent/__init__.py` | 4 | Auto-registro de skills |
| `skoll_agent/agent.py` | 98 | Entry point agente |
| `skoll_agent/brain/reasoning_loop.py` | 220 | ♻ ReAct Loop central |
| `skoll_agent/brain/context.py` | 143 | Indexador + risk scoring |
| `skoll_agent/brain/planner.py` | 97 | Planificador de tareas |
| `skoll_agent/engines/base_engine.py` | 27 | Interfaz abstracta |
| `skoll_agent/engines/bandit_engine.py` | 57 | Conector Bandit |
| `skoll_agent/engines/semgrep_engine.py` | 59 | Conector Semgrep |
| `skoll_agent/actions/base_action.py` | 22 | Interfaz abstracta |
| `skoll_agent/actions/scan_action.py` | 78 | Action: escanear |
| `skoll_agent/actions/report_action.py` | 88 | Action: reportar |
| `skoll_agent/skills/base_skill.py` | 16 | Interfaz abstracta |
| `skoll_agent/skills/code_analysis_skill.py` | 110 | 🎯 Primer skill |
| `skoll_agent/memory/state.py` | 113 | Modelos de datos |
| `skoll_agent/memory/findings_db.py` | 105 | Persistencia JSON |
| `skoll_agent/memory/task_queue.py` | 87 | Cola priorizada |
| `skoll_agent/sandbox/docker_sandbox.py` | 93 | Sandbox Docker |
| `skoll_agent/sandbox/human_in_loop.py` | 55 | Gate humano |
| `skoll_agent/reporting/sarif.py` | 89 | SARIF builder |
| `skoll_agent/reporting/severity.py` | 81 | Clasificador severidad |
| `skoll_agent/config/agent_config.py` | 37 | Config por env |
| `skoll_agent/config/skill_registry.py` | 24 | Registro de skills |

**Total: ~1700 líneas de código nuevo. Cero líneas modificadas en el código existente** (excepto `auditor_ai/main.py` para añadir el comando `agent` y arreglar un test).

---

## 14. Próximos Pasos (Punto 2)

El siguiente punto es implementar el **Patching Engine**:

- `actions/patch_action.py` → lógica real de diff/patch
- `actions/validate_action.py` → re-scan post-parche
- Integración con `git diff` para cambios seguros
- Modo dry-run vs apply
- Integración con `HumanInLoop` para aprobación antes de escribir en disco
