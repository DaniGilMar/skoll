const GROQ_MODELS = [
    "gemma2-9b-it",
    "llama-3.3-70b-versatile",
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
    "llama3-8b-8192",
];

const GEMINI_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
];

let geminiConfigured = false;
let groqConfigured = false;

// ── Page Load ─────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', async () => {
    await refreshStatus();
});

async function refreshStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        geminiConfigured = data.gemini_configured;
        groqConfigured = data.groq_configured;
    } catch (_) {
        geminiConfigured = false;
        groqConfigured = false;
    }

    // Setup overlay badges
    document.getElementById('gemini-status').textContent = geminiConfigured ? '✅' : '⬜';
    document.getElementById('groq-status').textContent = groqConfigured ? '✅' : '⬜';

    // Config bar dots
    document.getElementById('bar-gemini-status').className = `status-dot ${geminiConfigured ? 'on' : 'off'}`;
    document.getElementById('bar-groq-status').className = `status-dot ${groqConfigured ? 'on' : 'off'}`;

    // Enable/disable continue button
    const canContinue = geminiConfigured || groqConfigured;
    document.getElementById('btn-continue').disabled = !canContinue;
}

// ── Save API Key ──────────────────────────────────────────────

async function saveKey(provider) {
    const inputId = provider === 'groq' ? 'groq-key' : 'gemini-key';
    const btnId = provider === 'groq' ? 'groq-btn' : 'gemini-btn';
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    const apiKey = input.value.trim();

    if (!apiKey) {
        setKeyStatus('error', `Introduce la API Key de ${provider === 'groq' ? 'Groq' : 'Gemini'}.`);
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Guardando...';

    try {
        const res = await fetch('/api/configure-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider, api_key: apiKey }),
        });
        const data = await res.json();
        if (res.ok) {
            setKeyStatus('success', `✅ API Key de ${provider === 'groq' ? 'Groq' : 'Gemini'} configurada.`);
            input.value = '';
        } else {
            setKeyStatus('error', `❌ ${data.detail || 'Error'}`);
        }
    } catch (err) {
        setKeyStatus('error', `❌ Error de conexión: ${err.message}`);
    }

    btn.disabled = false;
    btn.textContent = 'Guardar';
    await refreshStatus();
}

function setKeyStatus(type, msg) {
    const el = document.getElementById('key-status');
    el.className = `key-status ${type}`;
    el.textContent = msg;
}

// ── Setup / Continue ─────────────────────────────────────────

function checkSetupAndContinue() {
    if (!geminiConfigured && !groqConfigured) {
        setKeyStatus('error', '⚠️ Configura al menos una API Key antes de continuar.');
        return;
    }
    document.getElementById('setup-overlay').style.display = 'none';
    document.getElementById('app-content').style.display = 'block';
}

function showSetup() {
    document.getElementById('app-content').style.display = 'none';
    document.getElementById('setup-overlay').style.display = 'flex';
    refreshStatus();
}

// ── Provider / Model ─────────────────────────────────────────

const providerSelect = document.createElement('select');
providerSelect.id = 'provider-select';

const modelSelect = document.createElement('select');
modelSelect.id = 'model-select';

function populateModels(provider) {
    const models = provider === 'groq' ? GROQ_MODELS : GEMINI_MODELS;
    modelSelect.innerHTML = models.map(m => `<option value="${m}">${m}</option>`).join('');
}

providerSelect.addEventListener('change', () => {
    populateModels(providerSelect.value);
    updateBar();
});

modelSelect.addEventListener('change', updateBar);

function updateBar() {
    document.getElementById('bar-provider').textContent =
        providerSelect.value === 'groq' ? 'GroqCloud' : 'Gemini';
    document.getElementById('bar-model').textContent = modelSelect.value;
}

// Insert provider/model selects into the config bar
(function initBar() {
    const bar = document.querySelector('.config-bar');
    const setupBtn = bar.querySelector('.btn-setup');

    providerSelect.innerHTML = `
        <option value="gemini">Gemini</option>
        <option value="groq">GroqCloud</option>
    `;
    populateModels('gemini');

    const sep1 = document.createElement('span'); sep1.textContent = '|';
    const sep2 = document.createElement('span'); sep2.textContent = '|';

    bar.insertBefore(sep1, setupBtn);
    bar.insertBefore(providerSelect, setupBtn);
    bar.insertBefore(sep2, setupBtn);
    bar.insertBefore(modelSelect, setupBtn);

    updateBar();
})();

// ── Send Message ─────────────────────────────────────────────

async function handleSend() {
    const inputField = document.getElementById('chat-input');
    const chatOutput = document.getElementById('chat-output');
    const input = inputField.value.trim();
    if (!input) return;

    const provider = providerSelect.value;
    const model = modelSelect.value;

    // Verify the selected provider has its key configured
    if (provider === 'groq' && !groqConfigured) {
        chatOutput.innerHTML += `<p class="error-msg">⚠️ Groq no está configurado. Ve a ⚙️ APIs y añade tu API Key de Groq.</p>`;
        inputField.value = '';
        return;
    }
    if (provider === 'gemini' && !geminiConfigured) {
        chatOutput.innerHTML += `<p class="error-msg">⚠️ Gemini no está configurado. Ve a ⚙️ APIs y añade tu API Key de Gemini.</p>`;
        inputField.value = '';
        return;
    }

    chatOutput.innerHTML += `<p class="user-msg"><b>Tú (${provider}):</b> ${escapeHtml(input)}</p>`;
    inputField.value = '';

    const isUrl = input.startsWith('http');
    const endpoint = isUrl ? '/api/analyze/url' : '/api/analyze/path';
    const payload = isUrl ? { url: input, provider, model } : { path: input, provider, model };

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || response.statusText);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        chatOutput.innerHTML += `<p class="ai-msg"><b>Skoll (${provider}):</b> <span class="streaming-text"></span></p>`;
        const streamDisplay = chatOutput.lastElementChild.querySelector('.streaming-text');

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const chunk = decoder.decode(value);
            const lines = chunk.split('\n\n');
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    try {
                        const data = JSON.parse(line.replace('data: ', ''));
                        if (data.type === 'chunk') {
                            streamDisplay.innerText += data.content;
                        }
                        if (data.type === 'error') {
                            streamDisplay.innerHTML += `<br><b style="color:#f85149">Error: ${data.content}</b>`;
                        }
                    } catch (_) { /* ignore partial parse errors */ }
                }
            }
        }
        streamDisplay.style.borderRight = 'none';
        chatOutput.scrollTop = chatOutput.scrollHeight;
    } catch (err) {
        chatOutput.innerHTML += `<p class="error-msg">Error: ${err.message}</p>`;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
