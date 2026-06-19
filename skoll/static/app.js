/* ═══════════════════════════════════════════════════════════════════
   Skoll Web — app.js
   Client-side logic: SSE streaming, Markdown rendering, Chat, Upload
   ═══════════════════════════════════════════════════════════════════ */

"use strict";

// ── State ─────────────────────────────────────────────────────────────
let selectedFile    = null;
let chatSessionId   = null;
let isStreaming     = false;
let currentProvider = "openrouter";
let _toolResultId   = 0;

const MODELS = {
  gemini: [
    { value: "gemini-2.5-flash", label: "gemini-2.5-flash ⚡" },
    { value: "gemini-2.5-pro",   label: "gemini-2.5-pro 🧠" },
  ],
  groq: [
    { value: "llama-3.3-70b-versatile", label: "Llama 3.3 70B" },
    { value: "llama-3.1-8b-instant",    label: "Llama 3.1 8B" },
    { value: "mixtral-8x7b-32768",      label: "Mixtral 8x7B" },
    { value: "llama3-70b-8192",         label: "Llama3 70B" },
    { value: "llama3-8b-8192",          label: "Llama3 8B" },
  ],
  openrouter: [
    { value: "deepseek/deepseek-chat",          label: "DeepSeek Chat" },
    { value: "mistral/mistral-nemo",            label: "Mistral Nemo" },
    { value: "microsoft/phi-4",                 label: "Phi-4" },
    { value: "google/gemini-2.0-flash-exp:free",label: "Gemini 2.0 Flash (free)" },
    { value: "qwen/qwen-2.5-72b-instruct",      label: "Qwen 2.5 72B" },
  ],
};

// ── Init ──────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  console.log("Skoll: app.js v2 loaded");
  checkStatus();
  setupFileInput();
  setupDropZone();
  setupChatTextarea();
  setupModelWatcher();
  setProvider(currentProvider);
  setTimeout(autoStartChat, 1000);
});

async function autoStartChat() {
  if (chatSessionId) return;
  try {
    const res = await fetch("/api/chat/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: getModel(), provider: getProvider() })
    });
    if (!res.ok) return;
    const data = await res.json();
    chatSessionId = data.session_id;
    console.log("Chat auto-started:", chatSessionId);
    document.getElementById("chat-input").disabled = false;
    document.getElementById("chat-send-btn").disabled = false;
    updateStatusLabel();
  } catch (e) {
    console.log("Chat auto-start deferred:", e.message);
  }
}

// ── Status check ──────────────────────────────────────────────────────
async function checkStatus() {
  const dot  = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  try {
    const res  = await fetch("/api/status");
    const data = await res.json();
    if (data.api_key_configured) {
      dot.className  = "status-dot ok";
      text.textContent = "API conectada";
      document.getElementById("api-key-overlay").classList.add("hidden");
      setTimeout(updateStatusLabel, 1500);
    } else {
      dot.className  = "status-dot error";
      text.textContent = "Configurar API Key";
      document.getElementById("api-key-overlay").classList.remove("hidden");
      const provLabels = { gemini: "Google Gemini", groq: "Groq", openrouter: "OpenRouter" };
      const provHints = {
        gemini: "Consíguela gratis en https://aistudio.google.com/",
        groq: "Consíguela en https://console.groq.com/keys",
        openrouter: "Consíguela en https://openrouter.ai/keys",
      };
      document.getElementById("api-key-prompt").textContent =
        `Introduce tu API Key de ${provLabels[currentProvider] || currentProvider} para usar Skoll.`;
      document.getElementById("api-key-hint").textContent = provHints[currentProvider] || "";
    }
  } catch {
    dot.className  = "status-dot error";
    text.textContent = "Servidor no disponible";
  }
}

async function saveApiKey() {
  const input = document.getElementById("api-key-input");
  const btn = document.getElementById("api-key-btn");
  const error = document.getElementById("api-key-error");
  const key = input.value.trim();
  if (!key) return;
  btn.disabled = true;
  btn.textContent = "Conectando...";
  error.classList.add("hidden");
  const provLabels = { gemini: "Google Gemini", groq: "Groq", openrouter: "OpenRouter" };
  document.getElementById("api-key-prompt").textContent =
    `Introduce tu API Key de ${provLabels[currentProvider] || currentProvider} para usar Skoll.`;
  try {
    const res = await fetch("/api/configure-key", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: key, provider: getProvider() })
    });
    if (!res.ok) throw new Error();
    document.getElementById("api-key-overlay").classList.add("hidden");
    showToast("✅ API Key configurada correctamente", "success");
    checkStatus();
  } catch {
    error.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.textContent = "Guardar y conectar";
  }
}

// ── Tab switching ──────────────────────────────────────────────────────
function switchTab(tab) {
  const titles = { analyze: "Mímir", scan: "Heimdall", web: "Huginn", chat: "Runas", renacer: "Ragnarök" };

  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  document.getElementById(`tab-${tab}`).classList.add("active");
  document.getElementById(`nav-${tab}`).classList.add("active");
  document.getElementById("topbar-title").textContent = titles[tab] || tab;

  if (tab === "chat" && !chatSessionId) {
    showChatWelcome();
  }
}

// ── Sidebar toggle ────────────────────────────────────────────────────
function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("collapsed");
}

// ── Provider / Model helpers ──────────────────────────────────────────
function setProvider(provider) {
  currentProvider = provider;
  document.querySelectorAll(".toggle-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`prov-${provider}`).classList.add("active");

  const sel = document.getElementById("global-model");
  sel.innerHTML = "";
  MODELS[provider].forEach(m => {
    const opt = document.createElement("option");
    opt.value = m.value;
    opt.textContent = m.label;
    sel.appendChild(opt);
  });
  // Re-start chat on provider switch
  if (chatSessionId) {
    chatSessionId = null;
    document.getElementById("chat-input").disabled = true;
    document.getElementById("chat-send-btn").disabled = true;
    setTimeout(autoStartChat, 500);
  }
  // Update overlay hint
  const provLabels = { gemini: "Google Gemini", groq: "Groq", openrouter: "OpenRouter" };
  const provHints = {
    gemini: "Consíguela gratis en https://aistudio.google.com/",
    groq: "Consíguela en https://console.groq.com/keys",
    openrouter: "Consíguela en https://openrouter.ai/keys",
  };
  document.getElementById("api-key-prompt").textContent =
    `Introduce tu API Key de ${provLabels[provider] || provider} para usar Skoll.`;
  document.getElementById("api-key-hint").textContent = provHints[provider] || "";
}

function getModel() {
  return document.getElementById("global-model").value;
}

function getProvider() {
  return currentProvider;
}

function setupModelWatcher() {
  document.getElementById("global-model").addEventListener("change", () => {
    if (chatSessionId) restartChat();
  });
}

function restartChat() {
  chatSessionId = null;
  document.getElementById("chat-input").disabled = true;
  document.getElementById("chat-send-btn").disabled = true;
  const chatMsgs = document.getElementById("chat-messages");
  if (!chatMsgs.querySelector(".chat-welcome")) {
    chatMsgs.innerHTML = `<div class="chat-welcome">
      <div class="chat-welcome-icon">🤖</div>
      <h2>Runas — Chat de Seguridad</h2>
      <p>El oráculo de conocimiento nórdico; consulta la sabiduría sobre vulnerabilidades y defensas.</p>
      <button class="btn btn-primary" id="start-chat-btn" onclick="startChat()">💬 Iniciar sesión de chat</button>
    </div>`;
  }
  setTimeout(() => {
    autoStartChat();
    updateStatusLabel();
  }, 500);
}

function updateStatusLabel() {
  const el = document.getElementById("status-text");
  const badge = document.getElementById("model-badge");
  const prov = { gemini: "Gemini", groq: "Groq", openrouter: "OpenRouter" }[currentProvider] || currentProvider;
  const label = `${prov} · ${getModel()}`;
  if (el) {
    el.textContent = chatSessionId ? label : "API conectada";
  }
  if (badge) {
    badge.textContent = chatSessionId ? label : "Esperando conexión...";
  }
}

// ── Clear output ──────────────────────────────────────────────────────
function clearOutput() {
  const activeTab = document.querySelector(".tab-panel.active").id;
  if (activeTab === "tab-analyze") {
    setOutputPlaceholder("analyze-output", "🛡️", "El informe de seguridad aparecerá aquí...");
    document.getElementById("analyze-meta").textContent = "";
  } else if (activeTab === "tab-scan") {
    setOutputPlaceholder("scan-output", "⚡", "Los resultados del escaneo SAST aparecerán aquí...");
    document.getElementById("scan-meta").textContent = "";
  } else if (activeTab === "tab-chat") {
    resetChat();
  }
}

function setOutputPlaceholder(boxId, icon, text) {
  document.getElementById(boxId).innerHTML =
    `<div class="output-placeholder"><span>${icon}</span><p>${text}</p></div>`;
}

// ── File Input & Drop Zone ────────────────────────────────────────────
function setupFileInput() {
  const input = document.getElementById("file-input");
  input.addEventListener("change", () => {
    if (input.files.length > 0) setSelectedFile(input.files[0]);
  });
}

function setupDropZone() {
  const zone = document.getElementById("drop-zone");
  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("dragover"); });
  zone.addEventListener("dragleave", ()  => zone.classList.remove("dragover"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) setSelectedFile(e.dataTransfer.files[0]);
  });
  zone.addEventListener("click", () => document.getElementById("file-input").click());
}

function setSelectedFile(file) {
  selectedFile = file;
  const bar  = document.getElementById("file-info-bar");
  const name = document.getElementById("file-info-name");
  name.textContent = `${file.name}  (${formatBytes(file.size)})`;
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

// ── ANALYZE — File upload ─────────────────────────────────────────────
async function analyzeFile() {
  if (!selectedFile || isStreaming) return;

  const btn = document.getElementById("analyze-file-btn");
  const formData = new FormData();
  formData.append("file", selectedFile);
  formData.append("model", getModel());
  formData.append("provider", getProvider());

  const startTime = Date.now();
  startStreamingUI("analyze-output", btn, "Auditando...");

  try {
    const res = await fetch("/api/analyze/file", { method: "POST", body: formData });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || res.statusText);
    }
    await consumeSSE(res, "analyze-output", "analyze-meta", startTime);
  } catch (e) {
    showError("analyze-output", e.message);
  } finally {
    endStreamingUI(btn, "🚀 Auditar con RAPTOR");
  }
}

// ── ANALYZE — By path ─────────────────────────────────────────────────
async function analyzeByPath() {
  const path = document.getElementById("path-input").value.trim();
  if (!path || isStreaming) return;

  const btn = document.getElementById("analyze-path-btn");
  const startTime = Date.now();
  startStreamingUI("analyze-output", btn, "Analizando...");

  try {
    const res = await fetch("/api/analyze/path", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, model: getModel(), provider: getProvider() })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || res.statusText);
    }
    await consumeSSE(res, "analyze-output", "analyze-meta", startTime);
  } catch (e) {
    showError("analyze-output", e.message);
  } finally {
    endStreamingUI(btn, "Analizar ruta");
  }
}

// ── SCAN ──────────────────────────────────────────────────────────────
async function runScan() {
  const path = document.getElementById("scan-path-input").value.trim();
  if (!path || isStreaming) return;

  const toolEl = document.querySelector('input[name="sast-tool"]:checked');
  const tool = toolEl ? toolEl.value : "bandit";
  const btn  = document.getElementById("scan-btn");
  const outputBox = document.getElementById("scan-output");
  const startTime = Date.now();

  isStreaming = true;
  btn.disabled = true;
  btn.textContent = "Ejecutando SAST...";
  outputBox.innerHTML = `<div class="output-placeholder"><span>⏳</span><p>Ejecutando ${tool === "all" ? "Bandit + Semgrep" : tool}...</p></div>`;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, tool, model: getModel(), provider: getProvider() })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || res.statusText);
    }
    btn.textContent = "Analizando con IA...";
    outputBox.innerHTML = `<div class="output-placeholder"><span>🧠</span><p>Interpretando resultados con IA...</p></div>`;
    await consumeSSE(res, "scan-output", null, startTime);
  } catch (e) {
    showError("scan-output", e.message);
  } finally {
    isStreaming = false;
    btn.disabled = false;
    btn.textContent = "⚡ Lanzar Escaneo";
  }
}

// ── ANALYZE — URL ──────────────────────────────────────────────────────
async function analyzeURL() {
  console.log("analyzeURL() called");
  const url = document.getElementById("url-input").value.trim();
  console.log("URL:", url);
  if (!url || isStreaming) return;

  const btn = document.getElementById("analyze-url-btn");
  const outputBox = document.getElementById("web-output");
  const startTime = Date.now();

  isStreaming = true;
  btn.disabled = true;
  btn.textContent = "Conectando...";

  outputBox.innerHTML = `<div class="output-placeholder"><span>⏳</span><p>Descargando contenido de la URL...</p></div>`;

  try {
    console.log("Fetching /api/analyze/url...");
    const res = await fetch("/api/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, model: getModel(), provider: getProvider() })
    });
    console.log("Response status:", res.status);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || res.statusText);
    }
    btn.textContent = "Analizando con IA...";
    outputBox.innerHTML = `<div class="output-placeholder"><span>🧠</span><p>Analizando con IA (metodología RAPTOR)...</p></div>`;
    await consumeSSE(res, "web-output", null, startTime);
  } catch (e) {
    console.error("analyzeURL error:", e.message);
    showError("web-output", e.message);
  } finally {
    isStreaming = false;
    btn.disabled = false;
    btn.textContent = "Auditar Web";
  }
}

// ── CHAT ──────────────────────────────────────────────────────────────
async function startChat() {
  const btn = document.getElementById("start-chat-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Iniciando sesión..."; }

  try {
    const res = await fetch("/api/chat/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: getModel(), provider: getProvider() })
    });
    if (!res.ok) throw new Error((await res.json()).detail);
    const data = await res.json();
    chatSessionId = data.session_id;

    // Clear welcome screen, enable input
    document.getElementById("chat-messages").innerHTML = "";
    document.getElementById("chat-input").disabled = false;
    document.getElementById("chat-send-btn").disabled = false;
    document.getElementById("chat-input").focus();
    document.getElementById("chat-hint").textContent = "Enter para enviar · Shift+Enter para nueva línea";

    updateStatusLabel();
    showToast("💬 Sesión de chat iniciada con " + data.model, "success");
    const provLabel = { gemini: "Gemini", groq: "Groq", openrouter: "OpenRouter" }[data.provider] || data.provider;
    appendSystemMsg(`🛡️ Sesión iniciada con ${provLabel} (${data.model}). Soy Skoll con metodología RAPTOR activada. ¿En qué puedo ayudarte hoy?`);
  } catch (e) {
    showToast("Error al iniciar chat: " + e.message, "error");
    btn.disabled = false;
    btn.textContent = "💬 Iniciar sesión de chat";
  }
}

function resetChat() {
  chatSessionId = null;
  document.getElementById("chat-messages").innerHTML = `
    <div class="chat-welcome">
      <div class="chat-welcome-icon">🤖</div>
      <h2>Runas — Chat de Seguridad</h2>
      <p>Asistente conversacional de ciberseguridad; consulta sobre vulnerabilidades, código, configuraciones y mejores prácticas.</p>
      <button class="btn btn-primary" id="start-chat-btn" onclick="startChat()">💬 Iniciar sesión de chat</button>
    </div>`;
  document.getElementById("chat-input").disabled = true;
  document.getElementById("chat-send-btn").disabled = true;
  document.getElementById("chat-hint").textContent = "Inicia la sesión para comenzar a chatear";
}

function showChatWelcome() {
  resetChat();
}

async function sendChatMessage() {
  if (!chatSessionId || isStreaming) return;
  const textarea = document.getElementById("chat-input");
  const message  = textarea.value.trim();
  if (!message) return;

  textarea.value = "";
  textarea.style.height = "auto";

  // Append user bubble
  appendChatMsg("user", message);

  // Append AI bubble (empty, will stream into it)
  const aiMsgId = "ai-msg-" + Date.now();
  appendChatMsg("ai", "", aiMsgId);

  isStreaming = true;
  document.getElementById("chat-send-btn").disabled = true;

  const bubbleEl = document.getElementById(aiMsgId);
  let fullText = "";
  let cursorEl = document.createElement("span");
  cursorEl.className = "streaming-cursor";

  try {
    const res = await fetch("/api/chat/message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: chatSessionId, message })
    });
    if (!res.ok) throw new Error((await res.json()).detail);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();

    bubbleEl.innerHTML = "";
    bubbleEl.appendChild(cursorEl);

    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        try {
          const evt = JSON.parse(line.slice(6));
          if (evt.type === "chunk") {
            fullText += evt.content;
            bubbleEl.innerHTML = renderMarkdown(fullText);
            bubbleEl.appendChild(cursorEl);
            scrollChatToBottom();
          } else if (evt.type === "done" || evt.type === "error") {
            cursorEl.remove();
            bubbleEl.innerHTML = evt.type === "error"
              ? `<span style="color:var(--red)">⚠️ ${evt.content}</span>`
              : renderMarkdown(fullText);
            scrollChatToBottom();
          }
        } catch {}
      }
    }
  } catch (e) {
    bubbleEl.innerHTML = `<span style="color:var(--red)">⚠️ Error: ${e.message}</span>`;
  } finally {
    isStreaming = false;
    document.getElementById("chat-send-btn").disabled = false;
    document.getElementById("chat-input").focus();
    cursorEl.remove();
  }
}

function appendChatMsg(role, text, id = "") {
  const messages = document.getElementById("chat-messages");
  const div = document.createElement("div");
  div.className = `chat-msg ${role}`;

  const avatar = role === "user" ? "👤" : "🛡️";
  const bubbleContent = text ? renderMarkdown(text) : "";

  div.innerHTML = `
    <div class="chat-avatar">${avatar}</div>
    <div class="chat-bubble" ${id ? `id="${id}"` : ""}>${bubbleContent}</div>
  `;

  messages.appendChild(div);
  scrollChatToBottom();
}

function appendSystemMsg(text) {
  appendChatMsg("ai", text);
}

function scrollChatToBottom() {
  const messages = document.getElementById("chat-messages");
  messages.scrollTop = messages.scrollHeight;
}

function setupChatTextarea() {
  const ta = document.getElementById("chat-input");
  ta.addEventListener("input", () => {
    ta.style.height = "auto";
    ta.style.height = Math.min(ta.scrollHeight, 160) + "px";
  });
  ta.addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  });
}

// ── SSE consumer ──────────────────────────────────────────────────────
async function consumeSSE(response, outputBoxId, metaId, startTime) {
  const outputBox = document.getElementById(outputBoxId);
  const metaEl    = document.getElementById(metaId);

  outputBox.innerHTML = "";
  let cursorEl = document.createElement("span");
  cursorEl.className = "streaming-cursor";
  outputBox.appendChild(cursorEl);

  const reader  = response.body.getReader();
  const decoder = new TextDecoder();
  let fullText  = "";
  let buffer    = "";
  let charCount = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop();

    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      try {
        const evt = JSON.parse(line.slice(6));

        if (evt.type === "chunk") {
          fullText += evt.content;
          charCount += evt.content.length;
          outputBox.innerHTML = renderMarkdown(fullText);
          outputBox.appendChild(cursorEl);
          outputBox.scrollTop = outputBox.scrollHeight;
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
          if (metaEl) metaEl.textContent = `${charCount.toLocaleString()} chars · ${elapsed}s`;

        } else if (evt.type === "done") {
          cursorEl.remove();
          outputBox.innerHTML = renderMarkdown(fullText);
          applySeverityColors(outputBox);
          outputBox.scrollTop = outputBox.scrollHeight;
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
          if (metaEl) metaEl.textContent = `✅ ${charCount.toLocaleString()} chars · ${elapsed}s`;
          showToast("✅ Análisis completado", "success");

        } else if (evt.type === "error") {
          cursorEl.remove();
          showError(outputBoxId, evt.content);
        }
      } catch {}
    }
  }
}

// ── Markdown renderer (lightweight, no dependencies) ──────────────────
function renderMarkdown(text) {
  // Escape HTML to prevent XSS in code blocks
  const escapeHtml = s => s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Code blocks (``` ... ```)
  text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) =>
    `<pre><code class="lang-${lang}">${escapeHtml(code.trim())}</code></pre>`
  );

  // Inline code
  text = text.replace(/`([^`\n]+)`/g, (_, c) => `<code>${escapeHtml(c)}</code>`);

  // Headings
  text = text.replace(/^#{4}\s(.+)$/gm, "<h4>$1</h4>");
  text = text.replace(/^#{3}\s(.+)$/gm, "<h3>$1</h3>");
  text = text.replace(/^#{2}\s(.+)$/gm, "<h2>$1</h2>");
  text = text.replace(/^#{1}\s(.+)$/gm, "<h1>$1</h1>");

  // Bold & italic
  text = text.replace(/\*\*\*(.+?)\*\*\*/g, "<strong><em>$1</em></strong>");
  text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/\*(.+?)\*/g, "<em>$1</em>");

  // HR
  text = text.replace(/^---+$/gm, "<hr/>");

  // Unordered lists
  text = text.replace(/((?:^[\s]*[-*+]\s.+\n?)+)/gm, match => {
    const items = match.trim().split("\n").map(l => `<li>${l.replace(/^[\s]*[-*+]\s/, "")}</li>`).join("");
    return `<ul>${items}</ul>`;
  });

  // Ordered lists
  text = text.replace(/((?:^\d+\.\s.+\n?)+)/gm, match => {
    const items = match.trim().split("\n").map(l => `<li>${l.replace(/^\d+\.\s/, "")}</li>`).join("");
    return `<ol>${items}</ol>`;
  });

  // Blockquotes
  text = text.replace(/^>\s(.+)$/gm, "<blockquote>$1</blockquote>");

  // Paragraphs — wrap lines that aren't already block elements
  const blockTags = /^<(h[1-6]|ul|ol|li|pre|blockquote|hr)/;
  text = text.split("\n").map(line => {
    if (!line.trim()) return "";
    if (blockTags.test(line.trim())) return line;
    return `<p>${line}</p>`;
  }).join("\n");

  return text;
}

// Color h1 headings by severity keyword
function applySeverityColors(container) {
  container.querySelectorAll("h1").forEach(h => {
    const t = h.textContent.toUpperCase();
    if (t.includes("CRÍT"))   h.style.color = "var(--sev-critical)";
    else if (t.includes("ALTA"))   h.style.color = "var(--sev-high)";
    else if (t.includes("MEDIA"))  h.style.color = "var(--sev-medium)";
    else if (t.includes("BAJA"))   h.style.color = "var(--sev-low)";
    else if (t.includes("INFO"))   h.style.color = "var(--sev-info)";
  });
}

// ── UI helpers ────────────────────────────────────────────────────────
function startStreamingUI(outputBoxId, btn, label) {
  isStreaming = true;
  if (btn) { btn.disabled = true; btn.textContent = label; }
  setOutputPlaceholder(outputBoxId, "⏳", "Conectando con IA...");
}

function endStreamingUI(btn, label) {
  isStreaming = false;
  if (btn) { btn.disabled = false; btn.textContent = label; }
}

function showError(outputBoxId, msg) {
  isStreaming = false;
  const box = document.getElementById(outputBoxId);
  if (box) {
    box.innerHTML = `
      <div style="color:var(--red);padding:20px;text-align:center;">
        <div style="font-size:32px;margin-bottom:12px">⚠️</div>
        <strong>Error</strong><br/><span style="color:var(--text-secondary)">${msg}</span>
      </div>`;
  }
  showToast("❌ " + msg, "error");
}

// ── Running tool indicator (shared) ────────────────────────────────────
let _runningToolInterval = null;
let _progressBarEl = null;

function showRunningTool(tool, target, params) {
  const el = document.getElementById("renacer-running-tool");
  if (!el) return;
  el.classList.remove("hidden");
  if (_runningToolInterval) clearInterval(_runningToolInterval);

  let paramStr = "";
  if (params && Object.keys(params).length > 0) {
    paramStr = " [" + Object.entries(params).map(([k,v]) => `${k}=${v}`).join(", ") + "]";
  }

  const startTime = Date.now();

  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
      <span>⏳ <strong>${tool}</strong> → ${target}${paramStr}</span>
      <span class="running-time" id="tool-progress-pct">0:00</span>
    </div>
    <div class="tool-progress-track"><div class="tool-progress-fill" id="tool-progress-fill" style="width:0%"></div></div>
  `;
  _progressBarEl = document.getElementById("tool-progress-fill");

  _runningToolInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(elapsed / 60);
    const s = elapsed % 60;
    const pctEl = document.getElementById("tool-progress-pct");
    if (pctEl) {
      if (!pctEl.textContent.includes("%")) {
        pctEl.textContent = `${m}:${s.toString().padStart(2,"0")}`;
      }
    }
  }, 1000);
}

function updateToolProgress(pct) {
  if (_progressBarEl) {
    _progressBarEl.style.width = Math.min(pct, 100) + "%";
  }
  const pctEl = document.getElementById("tool-progress-pct");
  if (pctEl) {
    pctEl.textContent = pct + "%";
    _lastProgressTime = Date.now();
  }
}

function hideRunningTool() {
  if (_runningToolInterval) {
    clearInterval(_runningToolInterval);
    _runningToolInterval = null;
  }
  if (_progressBarEl) {
    _progressBarEl.style.width = "0%";
    _progressBarEl = null;
  }
  const el = document.getElementById("renacer-running-tool");
  if (el) el.classList.add("hidden");
}

// ── RENACER (v2) ─────────────────────────────────────────────────────
async function startRenacer() {
  const target = document.getElementById("renacer-target").value.trim();
  if (!target) { showToast("❌ Introduce un target", "error"); return; }

  const tier = "agent";
  const btn = document.getElementById("renacer-btn");
  const log = document.getElementById("renacer-log");

  btn.disabled = true;
  btn.textContent = "🔄 Ejecutando...";
  log.innerHTML = '<div class="agent-entry log">🛡️ Iniciando pipeline Renacer...</div>';

  try {
    const res = await fetch("/api/v2/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, tier })
    });
    if (!res.ok) throw new Error((await res.json()).detail);
    const data = await res.json();
    log.innerHTML += `<div class="agent-entry log">✅ Sesión: ${data.session_id.slice(0, 8)}... | Tier: ${tier}</div>`;

    const stream = await fetch(`/api/v2/stream/${data.session_id}`);
    const reader = stream.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        try {
          const evt = JSON.parse(line.slice(6));
          handleRenacerEvent(evt, log);
        } catch {}
      }
    }

    showToast("✅ Pipeline completado", "success");
  } catch (e) {
    log.innerHTML += `<div class="agent-entry error">❌ Error: ${e.message}</div>`;
    showToast("❌ " + e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "▶ Ejecutar";
  }
}

function handleRenacerEvent(evt, log) {
  const type = evt.type;
  const data = evt.data || {};

  let html = "";
  switch (type) {
    case "heartbeat":
      if (data.tool) {
        showRunningTool(data.tool, data.target, data.params);
        if (data.percent !== undefined) updateToolProgress(data.percent);
      }
      return;

    case "agent_log":
      html = `<div class="agent-entry log">${data.message || ""}</div>`;
      break;
    case "agent_tool_start":
      showRunningTool(data.tool, data.target, data.params);
      const flags = data.params && data.params.flags ? ` (${data.params.flags})` : "";
      html = `<div class="agent-entry action">🔧 ${data.tool || ""} ${data.target || ""}${flags}</div>`;
      break;
    case "agent_tool_result":
      hideRunningTool();
      html = `<div class="agent-entry action">✅ ${data.tool || ""}: ${data.summary || "ok"}</div>`;
      break;
    case "agent_tool_progress":
      updateToolProgress(data.percent);
      return;
    case "agent_complete":
      hideRunningTool();
      html = `<div class="agent-entry complete">✅ Pipeline completado</div>`;
      break;
    case "agent_summary":
      html = `<div class="agent-entry complete">📊 ${data.message || "Resumen"}</div>`;
      break;
    case "agent_complete":
      html = `<div class="agent-entry complete">✅ Pipeline completado</div>`;
      break;
    case "agent_error":
      html = `<div class="agent-entry error">❌ ${data.message || "Error"}</div>`;
      break;
    default:
      html = data.message ? `<div class="agent-entry log">${data.message}</div>` : "";
  }
  if (html) {
    log.innerHTML += html;
    log.scrollTop = log.scrollHeight;
  }
}

function toggleToolOutput(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const header = el.previousElementSibling;
  const isHidden = el.classList.toggle("hidden");
  const arrow = header && header.querySelector(".tool-arrow");
  if (arrow) arrow.textContent = isHidden ? "▶" : "▼";
}

function escapeHtml(s) {
  if (!s) return "";
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── Toast ─────────────────────────────────────────────────────────────
let _toastTimer = null;
function showToast(msg, type = "info") {
  const toast = document.getElementById("toast");
  toast.textContent = msg;
  toast.className = `toast ${type}`;
  toast.classList.remove("hidden");
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => toast.classList.add("hidden"), 4000);
}
