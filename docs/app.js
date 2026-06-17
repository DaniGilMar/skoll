"use strict";

const RAPTOR_SYSTEM_PROMPT = [
  "Eres Skoll (inspirado en el framework RAPTOR), un Ingeniero DevSecOps experto y Consultor de Ciberseguridad de élite.",
  "Tu objetivo es realizar análisis de seguridad estáticos (SAST) y auditorías de código exhaustivas.",
  "",
  "IMPORTANTE: Opera estrictamente bajo principios defensivos y éticos:",
  "1. No proporciones código de exploits funcionales ni payloads listos para atacar.",
  "2. Enfócate exclusivamente en identificar vulnerabilidades, evaluar su impacto y sugerir parches seguros.",
  "3. Tus reportes y respuestas deben estar siempre en ESPAÑOL, estructurados, claros y listos para ser leídos por desarrolladores.",
  "",
  "Cuando audites un hallazgo, estructura tu análisis bajo las siguientes ETAPAS RAPTOR:",
  "- ETAPA A: Ruido vs Realidad",
  "- ETAPA B: Requisitos de Explotación e Impacto",
  "- ETAPA C: Alcanzabilidad del Flujo (Reachability)",
  "- ETAPA D: Veredicto de Severidad y Solución Propuesta"
].join("\n");

const ANALYSIS_TEMPLATE = [
  "Analiza el siguiente código fuente.",
  "Genera un reporte de seguridad extremadamente exhaustivo detallando todos los hallazgos en formato Markdown en ESPAÑOL.",
  "",
  "Estructura el reporte para cada vulnerabilidad encontrada de la siguiente manera:",
  "",
  "# [Severidad] - [Nombre de la Vulnerabilidad]",
  "- **Archivo/Línea**: `código proporcionado` (líneas correspondientes)",
  "- **Descripción**: Breve descripción del fallo.",
  "",
  "### Metodología de Auditoría RAPTOR:",
  "1. **Etapa A (Ruido vs Realidad)**: [Tu análisis de si es real o falso positivo]",
  "2. **Etapa B (Requisitos de Explotación)**: [Qué requiere un atacante para detonarla]",
  "3. **Etapa C (Alcanzabilidad)**: [Análisis de flujo de datos del usuario al sink]",
  "",
  "### Solución y Mitigación Propuesta:",
  "- **Explicación Técnica**: Por qué la solución propuesta es segura.",
  "- **Código Corregido**:",
  "```[lenguaje]",
  "[Código seguro corregido]",
  "```",
  "",
  "---",
  "Código a analizar:",
  "{code_content}"
].join("\n");

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1/models";
const GROQ_BASE = "https://api.groq.com/openai/v1/chat/completions";

const FALLBACK_CHAIN = ["gemini-2.5-flash", "gemini-1.5-flash", "llama-3.3-70b-versatile"];

const PROVIDER_MAP = {
  "gemini-2.5-flash": "gemini",
  "gemini-2.5-pro": "gemini",
  "gemini-1.5-flash": "gemini",
  "gemini-1.5-pro": "gemini",
  "llama-3.3-70b-versatile": "groq",
  "llama-3.1-8b-instant": "groq",
  "qwen/qwen3-32b": "groq",
  "meta-llama/llama-4-scout-17b-16e-instruct": "groq"
};

let chatHistory = [];
let isStreaming = false;
let selectedFile = null;
let chatInitialized = false;
let currentModelUsed = null;

document.addEventListener("DOMContentLoaded", () => {
  registerSW();
  checkApiKeys();
  setupFileInput();
  setupDropZone();
  setupChatTextarea();
});

function registerSW() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("service-worker.js").catch(() => {});
  }
}

function getGeminiKey() { return localStorage.getItem("gemini_api_key") || ""; }
function getGroqKey() { return localStorage.getItem("groq_api_key") || ""; }
function getModel() { return document.getElementById("global-model").value; }
function providerOf(model) { return PROVIDER_MAP[model] || "gemini"; }

// ── Gemini fetch ──────────────────────────────────────────────────────
function geminiUrl(model, streaming) {
  const m = streaming ? "streamGenerateContent?alt=sse" : "generateContent";
  const base = `${GEMINI_BASE}/${model}:${m}`;
  const sep = base.includes("?") ? "&" : "?";
  return base + sep + "key=" + encodeURIComponent(getGeminiKey());
}

function prependSystemPrompt(contents, prompt) {
  return prompt ? [
    { role: "user", parts: [{ text: "[INSTRUCCIÓN DEL SISTEMA - Siguelas estrictamente]:\n" + prompt }] },
    { role: "model", parts: [{ text: "Entendido. Cumpliré las instrucciones del sistema en toda la conversación." }] },
    ...contents
  ] : contents;
}

async function geminiFetch(contents, systemPrompt, streaming, model) {
  const key = getGeminiKey();
  if (!key) throw new Error("API Key de Gemini no configurada");
  model = model || getModel();
  currentModelUsed = model;
  const res = await fetch(geminiUrl(model, streaming), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: prependSystemPrompt(contents, systemPrompt) })
  });
  if (res.status === 429) throw new Error("QUOTA_EXCEEDED");
  return res;
}

async function geminiStream(contents, systemPrompt, onChunk, onDone, onError) {
  let done = false;
  const sd = (t) => { if (!done) { done = true; onDone(t); } };
  const sc = (t) => { if (!done) onChunk(t); };
  try {
    const res = await geminiFetch(contents, systemPrompt, true);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "", full = "";
    while (true) {
      const { done: d, value } = await reader.read();
      if (d) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const json = line.slice(6).trim();
        if (!json || json === "[DONE]") continue;
        try {
          const evt = JSON.parse(json);
          const text = evt.candidates?.[0]?.content?.parts?.[0]?.text || "";
          const finish = evt.candidates?.[0]?.finishReason;
          if (text) { full += text; sc(full); }
          if (finish && finish !== "FINISH_REASON_UNSPECIFIED") { sd(full); return; }
        } catch {}
      }
    }
    sd(full);
  } catch (e) { onError(e.message); }
}

async function geminiNonStream(contents, systemPrompt) {
  const res = await geminiFetch(contents, systemPrompt, false);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Error ${res.status}`);
  }
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || "";
}

// ── Groq fetch ────────────────────────────────────────────────────────
function groqMessages(contents, systemPrompt) {
  let msgs = [];
  if (systemPrompt) msgs.push({ role: "system", content: systemPrompt });
  for (const c of contents) {
    const text = c.parts?.map(p => p.text).join("") || "";
    if (text) msgs.push({ role: c.role === "model" ? "assistant" : "user", content: text });
  }
  return msgs;
}

async function groqFetch(contents, systemPrompt, streaming, model) {
  const key = getGroqKey();
  if (!key) throw new Error("API Key de Groq no configurada");
  model = model || getModel();
  currentModelUsed = model;
  const res = await fetch(GROQ_BASE, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + key
    },
    body: JSON.stringify({
      model,
      messages: groqMessages(contents, systemPrompt),
      stream: streaming,
      temperature: 0.3,
      max_tokens: 8192
    })
  });
  if (res.status === 429) throw new Error("QUOTA_EXCEEDED");
  return res;
}

async function groqStream(contents, systemPrompt, onChunk, onDone, onError) {
  let done = false;
  const sd = (t) => { if (!done) { done = true; onDone(t); } };
  const sc = (t) => { if (!done) onChunk(t); };
  try {
    const res = await groqFetch(contents, systemPrompt, true);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error?.message || `Error ${res.status}`);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "", full = "";
    while (true) {
      const { done: d, value } = await reader.read();
      if (d) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const json = line.slice(6).trim();
        if (!json || json === "[DONE]") continue;
        try {
          const evt = JSON.parse(json);
          const text = evt.choices?.[0]?.delta?.content || "";
          const finish = evt.choices?.[0]?.finish_reason;
          if (text) { full += text; sc(full); }
          if (finish && finish !== "null" && finish !== null) { sd(full); return; }
        } catch {}
      }
    }
    sd(full);
  } catch (e) { onError(e.message); }
}

async function groqNonStream(contents, systemPrompt) {
  const res = await groqFetch(contents, systemPrompt, false);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Error ${res.status}`);
  }
  const data = await res.json();
  return data.choices?.[0]?.message?.content || "";
}

// ── Unified AI call with fallback chain ───────────────────────────────
const AI_FALLBACK_LOCK = {};

async function callAI(streaming, contents, systemPrompt, onChunk, onDone, onError) {
  const model = getModel();
  const startIdx = FALLBACK_CHAIN.indexOf(model);
  const chain = startIdx >= 0 ? FALLBACK_CHAIN.slice(startIdx) : [model];
  const lockKey = JSON.stringify(contents?.slice(-1)?.[0]);

  for (let i = 0; i < chain.length; i++) {
    const m = chain[i];
    const prov = providerOf(m);
    if (prov === "groq" && !getGroqKey()) continue;

    document.getElementById("status-text").textContent = `Usando ${m}`;
    const modelLabel = m;

    if (streaming) {
      const streamFn = prov === "groq" ? groqStream : geminiStream;
      const innerContents = prov === "groq" ? contents : contents;
      const innerSystem = prov === "groq" ? systemPrompt : systemPrompt;

      if (i === chain.length - 1) {
        return streamFn(innerContents, innerSystem, onChunk, onDone, onError);
      }

      let retry = false;
      await streamFn(innerContents, innerSystem,
        onChunk,
        (t) => { if (!retry) onDone(t); },
        (err) => {
          if (err === "QUOTA_EXCEEDED" || err.includes("429") || err.includes("quota") || err.includes("rate")) {
            retry = true;
            showToast(`Cuota agotada en ${modelLabel}, probando siguiente...`, "info");
          } else {
            onError(err);
          }
        }
      );
      if (!retry) return;
    } else {
      const fn = prov === "groq" ? groqNonStream : geminiNonStream;
      try {
        return await fn(contents, systemPrompt);
      } catch (e) {
        const msg = e.message || "";
        if ((msg.includes("QUOTA_EXCEEDED") || msg.includes("429") || msg.includes("quota") || msg.includes("rate")) && i < chain.length - 1) {
          showToast(`Cuota agotada en ${modelLabel}, probando siguiente...`, "info");
          continue;
        }
        throw e;
      }
    }
  }
  throw new Error("Todos los modelos agotados. Configura una API Key de Groq en Ajustes.");
}

// ── API Keys ──────────────────────────────────────────────────────────
function checkApiKeys() {
  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  const overlay = document.getElementById("api-key-overlay");
  if (getGeminiKey() || getGroqKey()) {
    dot.className = "status-dot ok";
    text.textContent = getGeminiKey() ? "Gemini lista" : "Groq lista";
    overlay.classList.add("hidden");
  } else {
    dot.className = "status-dot error";
    text.textContent = "Configurar API Key";
    overlay.classList.remove("hidden");
  }
}

function saveApiKeys() {
  const overlay = document.getElementById("api-key-overlay");
  const geminiInput = document.getElementById("gemini-key-input");
  const groqInput = document.getElementById("groq-key-input");
  const error = document.getElementById("api-key-error");
  const geminiKey = geminiInput.value.trim();
  const groqKey = groqInput.value.trim();
  if (!geminiKey && !groqKey) { error.classList.remove("hidden"); return; }
  error.classList.add("hidden");
  if (geminiKey) localStorage.setItem("gemini_api_key", geminiKey);
  if (groqKey) localStorage.setItem("groq_api_key", groqKey);
  overlay.classList.add("hidden");
  showToast("API Keys guardadas", "success");
  checkApiKeys();
}

// ── Tab switching ────────────────────────────────────────────────────
function switchTab(tab) {
  const titles = { analyze: "Análisis de Código", web: "Auditoría Web (URL)", chat: "Chat de Seguridad" };
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  document.getElementById(`tab-${tab}`).classList.add("active");
  document.getElementById(`nav-${tab}`).classList.add("active");
  document.getElementById("topbar-title").textContent = titles[tab];
  const h = document.getElementById("analyze-output-header");
  if (h) h.style.display = "none";
}

function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("collapsed");
  document.getElementById("sidebar-overlay").classList.toggle("hidden");
}

(function() {
  if (window.innerWidth < 768) {
    document.getElementById("sidebar").classList.add("collapsed");
    document.getElementById("sidebar-overlay").classList.add("hidden");
  }
  document.querySelectorAll(".nav-item").forEach(b => {
    b.addEventListener("click", () => {
      if (window.innerWidth < 768) {
        document.getElementById("sidebar").classList.add("collapsed");
        document.getElementById("sidebar-overlay").classList.add("hidden");
      }
    });
  });
})();

// ── File Input ────────────────────────────────────────────────────────
function setupFileInput() {
  document.getElementById("file-input").addEventListener("change", () => {
    const f = document.getElementById("file-input").files;
    if (f.length > 0) setSelectedFile(f[0]);
  });
}

function setupDropZone() {
  const zone = document.getElementById("drop-zone");
  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("dragover"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) setSelectedFile(e.dataTransfer.files[0]);
  });
}

function setSelectedFile(file) {
  selectedFile = file;
  const bar = document.getElementById("file-info-bar");
  document.getElementById("file-info-name").textContent = `${file.name}  (${formatBytes(file.size)})`;
  bar.classList.remove("hidden");
}

function clearFile() {
  selectedFile = null;
  document.getElementById("file-info-bar").classList.add("hidden");
  document.getElementById("file-input").value = "";
}

function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(1)} MB`;
}

// ── Analyzer helper ───────────────────────────────────────────────────
async function runAnalysis(code, label, btn, outputBox, meta, startTime) {
  isStreaming = true;
  btn.disabled = true;
  btn.textContent = label;
  outputBox.innerHTML = "";
  const header = document.getElementById("analyze-output-header");
  if (header) header.style.display = "flex";
  meta.textContent = "Conectando...";
  let cursorEl = document.createElement("span");
  cursorEl.className = "streaming-cursor";
  outputBox.appendChild(cursorEl);
  const prompt = ANALYSIS_TEMPLATE.replace("{code_content}", code);
  await callAI(
    true,
    [{ role: "user", parts: [{ text: prompt }] }],
    RAPTOR_SYSTEM_PROMPT,
    (full) => {
      outputBox.innerHTML = renderMarkdown(full);
      outputBox.appendChild(cursorEl);
      outputBox.scrollTop = outputBox.scrollHeight;
      meta.textContent = `${full.length.toLocaleString()} chars · ${((Date.now()-startTime)/1000).toFixed(1)}s`;
    },
    (full) => {
      cursorEl.remove();
      outputBox.innerHTML = renderMarkdown(full);
      applySeverityColors(outputBox);
      outputBox.scrollTop = outputBox.scrollHeight;
      meta.textContent = `Completado · ${full.length.toLocaleString()} chars · ${((Date.now()-startTime)/1000).toFixed(1)}s`;
      showToast("Análisis completado", "success");
    },
    (err) => {
      cursorEl.remove();
      outputBox.innerHTML = `<div class="output-placeholder"><span>⚠️</span><p style="color:var(--red)">Error: ${err}</p></div>`;
      meta.textContent = "Error";
    }
  );
  btn.disabled = false;
  btn.textContent = "Auditar con RAPTOR";
  isStreaming = false;
}

// ── ANALYZE — Code paste ──────────────────────────────────────────────
async function analyzeCode() {
  const code = document.getElementById("code-textarea").value.trim();
  if (!code || isStreaming) return;
  if (!getGeminiKey() && !getGroqKey()) { showToast("Configura una API Key primero", "error"); return; }
  await runAnalysis(code, "Analizando...", document.getElementById("analyze-code-btn"),
    document.getElementById("analyze-output"), document.getElementById("analyze-meta"), Date.now());
}

// ── ANALYZE — File upload ─────────────────────────────────────────────
async function analyzeFile() {
  if (!selectedFile || isStreaming) return;
  if (!getGeminiKey() && !getGroqKey()) { showToast("Configura una API Key primero", "error"); return; }
  const btn = document.getElementById("analyze-file-btn");
  const outputBox = document.getElementById("analyze-output");
  const meta = document.getElementById("analyze-meta");
  const startTime = Date.now();
  isStreaming = true;
  btn.disabled = true;
  btn.textContent = "Leyendo archivo...";
  outputBox.innerHTML = "";
  document.getElementById("analyze-output-header").style.display = "flex";
  meta.textContent = "Leyendo...";
  try {
    const text = await readFileAsText(selectedFile);
    await runAnalysis(text, "Auditando...", btn, outputBox, meta, startTime);
  } catch (e) {
    outputBox.innerHTML = `<div class="output-placeholder"><span>⚠️</span><p style="color:var(--red)">Error: ${e.message}</p></div>`;
    btn.disabled = false;
    btn.textContent = "Auditar";
    isStreaming = false;
  }
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error("No se pudo leer el archivo"));
    r.readAsText(file);
  });
}

// ── ANALYZE — URL ─────────────────────────────────────────────────────
const CORS_PROXIES = [
  (url) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
  (url) => `https://corsproxy.io/?${encodeURIComponent(url)}`
];

async function analyzeURL() {
  const url = document.getElementById("url-input").value.trim();
  if (!url || isStreaming) return;
  if (!getGeminiKey() && !getGroqKey()) { showToast("Configura una API Key primero", "error"); return; }
  const btn = document.getElementById("analyze-url-btn");
  const outputBox = document.getElementById("web-output");
  const startTime = Date.now();
  isStreaming = true;
  btn.disabled = true;
  btn.textContent = "Descargando...";
  outputBox.innerHTML = `<div class="output-placeholder"><span>⏳</span><p>Descargando contenido...</p></div>`;
  try {
    let content = null;
    for (const proxy of CORS_PROXIES) {
      try { const r = await fetch(proxy(url), { signal: AbortSignal.timeout(10000) }); if (r.ok) { content = await r.text(); break; } } catch {}
    }
    if (!content) throw new Error("No se pudo descargar la URL. Pega el contenido manualmente.");
    btn.textContent = "Analizando...";
    let cursorEl = document.createElement("span");
    cursorEl.className = "streaming-cursor";
    outputBox.innerHTML = "";
    outputBox.appendChild(cursorEl);
    const prompt = ANALYSIS_TEMPLATE.replace("{code_content}", content.slice(0, 50000));
    await callAI(true, [{ role: "user", parts: [{ text: prompt }] }], RAPTOR_SYSTEM_PROMPT,
      (full) => { outputBox.innerHTML = renderMarkdown(full); outputBox.appendChild(cursorEl); outputBox.scrollTop = outputBox.scrollHeight; },
      (full) => { cursorEl.remove(); outputBox.innerHTML = renderMarkdown(full); applySeverityColors(outputBox); outputBox.scrollTop = outputBox.scrollHeight; showToast("Completado", "success"); },
      (err) => { cursorEl.remove(); showError("web-output", err); }
    );
  } catch (e) { showError("web-output", e.message); }
  btn.disabled = false;
  btn.textContent = "Auditar Web";
  isStreaming = false;
}

// ── CHAT ──────────────────────────────────────────────────────────────
async function startChat() {
  if (!getGeminiKey() && !getGroqKey()) { showToast("Configura una API Key primero", "error"); return; }
  const btn = document.getElementById("start-chat-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Iniciando..."; }
  try {
    chatHistory = [
      { role: "user", parts: [{ text: "[INSTRUCCIÓN DEL SISTEMA - Siguelas estrictamente]:\n" + RAPTOR_SYSTEM_PROMPT }] },
      { role: "model", parts: [{ text: "Entendido. Cumpliré las instrucciones del sistema en toda la conversación." }] },
      { role: "user", parts: [{ text: "Hola, soy un desarrollador haciendo auditoría de seguridad." }] }
    ];
    const welcome = await callAI(false, chatHistory, null);
    chatHistory.push({ role: "model", parts: [{ text: welcome }] });
    chatInitialized = true;
    document.getElementById("chat-messages").innerHTML = "";
    document.getElementById("chat-input").disabled = false;
    document.getElementById("chat-send-btn").disabled = false;
    document.getElementById("chat-input").focus();
    document.getElementById("chat-hint").textContent = "Enter para enviar · Shift+Enter para nueva línea";
    appendChatMsg("ai", welcome);
    showToast("Chat iniciado", "success");
  } catch (e) {
    showToast("Error: " + e.message, "error");
    if (btn) { btn.disabled = false; btn.textContent = "Iniciar sesión de chat"; }
  }
}

async function sendChatMessage() {
  if (!chatInitialized || isStreaming) return;
  const textarea = document.getElementById("chat-input");
  const message = textarea.value.trim();
  if (!message) return;
  textarea.value = "";
  textarea.style.height = "auto";
  appendChatMsg("user", message);
  chatHistory.push({ role: "user", parts: [{ text: message }] });
  const aiMsgId = "ai-msg-" + Date.now();
  appendChatMsg("ai", "", aiMsgId);
  isStreaming = true;
  document.getElementById("chat-send-btn").disabled = true;
  const bubbleEl = document.getElementById(aiMsgId);
  let cursorEl = document.createElement("span");
  cursorEl.className = "streaming-cursor";
  bubbleEl.innerHTML = "";
  bubbleEl.appendChild(cursorEl);
  await callAI(true, chatHistory, null,
    (full) => { bubbleEl.innerHTML = renderMarkdown(full); bubbleEl.appendChild(cursorEl); scrollChatToBottom(); },
    (full) => { cursorEl.remove(); bubbleEl.innerHTML = renderMarkdown(full); scrollChatToBottom(); chatHistory.push({ role: "model", parts: [{ text: full }] }); },
    (err) => { cursorEl.remove(); bubbleEl.innerHTML = `<span style="color:var(--red)">⚠️ Error: ${err}</span>`; }
  );
  isStreaming = false;
  document.getElementById("chat-send-btn").disabled = false;
  document.getElementById("chat-input").focus();
}

function resetChat() {
  chatInitialized = false;
  chatHistory = [];
  document.getElementById("chat-messages").innerHTML = `
    <div class="chat-welcome">
      <div class="chat-welcome-icon">🤖</div>
      <h2>Chat de Seguridad Skoll</h2>
      <p>Asistente DevSecOps con metodología RAPTOR activada.<br/>Haz cualquier pregunta sobre vulnerabilidades, código o buenas prácticas de seguridad.</p>
      <button class="btn btn-primary" id="start-chat-btn" onclick="startChat()">💬 Iniciar sesión de chat</button>
    </div>`;
  document.getElementById("chat-input").disabled = true;
  document.getElementById("chat-send-btn").disabled = true;
  document.getElementById("chat-hint").textContent = "Inicia la sesión para comenzar a chatear";
}

function appendChatMsg(role, text, id) {
  const messages = document.getElementById("chat-messages");
  const div = document.createElement("div");
  div.className = `chat-msg ${role}`;
  const avatar = role === "user" ? "👤" : "🛡️";
  const bubbleContent = text ? renderMarkdown(text) : "";
  div.innerHTML = `<div class="chat-avatar">${avatar}</div><div class="chat-bubble" ${id ? `id="${id}"` : ""}>${bubbleContent}</div>`;
  messages.appendChild(div);
  scrollChatToBottom();
}

function scrollChatToBottom() {
  document.getElementById("chat-messages").scrollTop = document.getElementById("chat-messages").scrollHeight;
}

function setupChatTextarea() {
  const ta = document.getElementById("chat-input");
  ta.addEventListener("input", () => { ta.style.height = "auto"; ta.style.height = Math.min(ta.scrollHeight, 160) + "px"; });
  ta.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChatMessage(); } });
}

// ── Markdown renderer ─────────────────────────────────────────────────
function renderMarkdown(text) {
  const esc = s => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, l, c) => `<pre><code class="lang-${l}">${esc(c.trim())}</code></pre>`);
  text = text.replace(/`([^`\n]+)`/g, (_, c) => `<code>${esc(c)}</code>`);
  text = text.replace(/^#{4}\s(.+)$/gm, "<h4>$1</h4>");
  text = text.replace(/^#{3}\s(.+)$/gm, "<h3>$1</h3>");
  text = text.replace(/^#{2}\s(.+)$/gm, "<h2>$1</h2>");
  text = text.replace(/^#{1}\s(.+)$/gm, "<h1>$1</h1>");
  text = text.replace(/\*\*\*(.+?)\*\*\*/g, "<strong><em>$1</em></strong>");
  text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/\*(.+?)\*/g, "<em>$1</em>");
  text = text.replace(/^---+$/gm, "<hr/>");
  text = text.replace(/((?:^[\s]*[-*+]\s.+\n?)+)/gm, m => `<ul>${m.trim().split("\n").map(l => `<li>${l.replace(/^[\s]*[-*+]\s/, "")}</li>`).join("")}</ul>`);
  text = text.replace(/((?:^\d+\.\s.+\n?)+)/gm, m => `<ol>${m.trim().split("\n").map(l => `<li>${l.replace(/^\d+\.\s/, "")}</li>`).join("")}</ol>`);
  text = text.replace(/^>\s(.+)$/gm, "<blockquote>$1</blockquote>");
  const bt = /^<(h[1-6]|ul|ol|li|pre|blockquote|hr)/;
  text = text.split("\n").map(l => { if (!l.trim()) return ""; return bt.test(l.trim()) ? l : `<p>${l}</p>`; }).join("\n");
  return text;
}

function applySeverityColors(c) {
  c.querySelectorAll("h1").forEach(h => {
    const t = h.textContent.toUpperCase();
    if (t.includes("CRÍT")) h.style.color = "var(--sev-critical)";
    else if (t.includes("ALTA")) h.style.color = "var(--sev-high)";
    else if (t.includes("MEDIA")) h.style.color = "var(--sev-medium)";
    else if (t.includes("BAJA")) h.style.color = "var(--sev-low)";
    else if (t.includes("INFO")) h.style.color = "var(--sev-info)";
  });
}

// ── Toast ─────────────────────────────────────────────────────────────
let _toastTimer = null;
function showToast(msg, type) {
  const toast = document.getElementById("toast");
  toast.textContent = msg;
  toast.className = `toast ${type}`;
  toast.classList.remove("hidden");
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => toast.classList.add("hidden"), 4000);
}

function showError(id, msg) {
  isStreaming = false;
  document.getElementById(id).innerHTML =
    `<div style="color:var(--red);padding:20px;text-align:center;"><div style="font-size:32px;margin-bottom:12px">⚠️</div><strong>Error</strong><br/><span style="color:var(--text-secondary)">${msg}</span></div>`;
  showToast("❌ " + msg, "error");
}
