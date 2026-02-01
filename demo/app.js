// =============================================================================
// Vijil Travel Agent Demo - Side-by-side comparison UI
// =============================================================================

// =============================================================================
// State Management
// =============================================================================

const state = {
    unprotected: {
        url: 'http://localhost:9000',
        messages: [],
        trust: null,
        loading: false
    },
    protected: {
        url: 'http://localhost:9001',
        messages: [],
        trust: null,
        loading: false
    }
};

// Load settings from URL params or localStorage
function loadSettings() {
    const params = new URLSearchParams(window.location.search);

    if (params.has('unprotected')) {
        state.unprotected.url = params.get('unprotected');
    } else if (localStorage.getItem('unprotected-url')) {
        state.unprotected.url = localStorage.getItem('unprotected-url');
    }

    if (params.has('protected')) {
        state.protected.url = params.get('protected');
    } else if (localStorage.getItem('protected-url')) {
        state.protected.url = localStorage.getItem('protected-url');
    }

    // Update input fields
    document.getElementById('unprotected-url').value = state.unprotected.url;
    document.getElementById('protected-url').value = state.protected.url;
}

// Save settings to localStorage
function saveSettings() {
    localStorage.setItem('unprotected-url', state.unprotected.url);
    localStorage.setItem('protected-url', state.protected.url);
}

// =============================================================================
// Detection Logic
// =============================================================================

function isBlockedResponse(text) {
    const blockPatterns = [
        "I can't assist",
        "I'm sorry, but I can't",
        "I cannot help with",
        "I'm not able to",
        "I won't be able to",
        "I'm unable to",
        "I cannot assist"
    ];
    return blockPatterns.some(pattern => text.includes(pattern));
}

// =============================================================================
// Rendering
// =============================================================================

function renderMessage(panelId, message) {
    const container = document.getElementById(`${panelId}-messages`);
    const div = document.createElement('div');
    div.className = `message ${message.role}`;

    if (message.error) {
        div.className += ' error';
    }

    if (message.blocked) {
        div.className += ' blocked';
        div.innerHTML = `
            ${escapeHtml(message.text)}
            <span class="detection-badge">Blocked by Dome</span>
        `;
    } else {
        div.textContent = message.text;
    }

    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function renderLoadingMessage(panelId) {
    const container = document.getElementById(`${panelId}-messages`);
    const div = document.createElement('div');
    div.className = 'message agent loading';
    div.id = `${panelId}-loading`;
    div.textContent = 'Thinking';
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function removeLoadingMessage(panelId) {
    const loading = document.getElementById(`${panelId}-loading`);
    if (loading) loading.remove();
}

function updateTrustBadge(panelId, score) {
    const badge = document.getElementById(`${panelId}-trust`);
    if (score !== null) {
        badge.textContent = score.toFixed(2);
        badge.style.background = score > 0.7 ? '#c8e6c9' : score > 0.4 ? '#fff9c4' : '#ffcdd2';
        badge.style.color = score > 0.7 ? '#2e7d32' : score > 0.4 ? '#f57f17' : '#c62828';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// =============================================================================
// Preload Demo Conversation
// =============================================================================

function preloadConversation() {
    // Add a sample exchange to show the UI isn't empty
    const sampleExchange = [
        { role: 'user', text: 'Find flights from SFO to JFK tomorrow' },
        { role: 'agent', text: 'I found 3 flights from SFO to JFK for tomorrow:\n\n1. UA 123 - Departs 7:00 AM, Arrives 3:30 PM - $299\n2. AA 456 - Departs 10:15 AM, Arrives 6:45 PM - $325\n3. DL 789 - Departs 2:00 PM, Arrives 10:30 PM - $275\n\nWould you like me to book any of these?' }
    ];

    ['unprotected', 'protected'].forEach(panelId => {
        sampleExchange.forEach(msg => {
            state[panelId].messages.push(msg);
            renderMessage(panelId, msg);
        });
    });

    // Set placeholder trust scores
    updateTrustBadge('unprotected', 0.42);
    updateTrustBadge('protected', 0.87);
}

// =============================================================================
// A2A Protocol Integration
// =============================================================================

async function sendA2AMessage(panelId, text) {
    const panel = state[panelId];

    const messageId = crypto.randomUUID();
    const payload = {
        jsonrpc: '2.0',
        method: 'message/send',
        params: {
            message: {
                messageId: messageId,
                role: 'user',
                parts: [{ type: 'text', text }]
            }
        },
        id: Date.now().toString()
    };

    try {
        const response = await fetch(panel.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        return extractResponseText(data);
    } catch (error) {
        console.error(`Error sending to ${panelId}:`, error);
        return { text: `Error: ${error.message}`, error: true };
    }
}

function extractResponseText(data) {
    // Handle A2A response format
    try {
        // New A2A format: artifacts array with parts
        const artifacts = data.result?.artifacts;
        if (artifacts?.length > 0) {
            const textParts = artifacts
                .flatMap(a => a.parts || [])
                .filter(p => p.kind === 'text' || p.type === 'text')
                .map(p => p.text);
            if (textParts.length > 0) {
                return { text: textParts.join('\n') };
            }
        }

        // Legacy A2A format: status.message.parts
        const message = data.result?.status?.message;
        if (message?.parts) {
            const textParts = message.parts
                .filter(p => p.type === 'text' || p.kind === 'text')
                .map(p => p.text);
            return { text: textParts.join('\n') };
        }

        // Fallback for other formats
        if (data.result?.message) {
            return { text: data.result.message };
        }

        // Handle error responses
        if (data.error) {
            return { text: `Error: ${data.error.message || JSON.stringify(data.error)}`, error: true };
        }

        return { text: JSON.stringify(data, null, 2), error: true };
    } catch (e) {
        return { text: 'Failed to parse response', error: true };
    }
}

// =============================================================================
// Send Handlers
// =============================================================================

async function handleSend(panelId, text) {
    if (!text.trim()) return;

    const panel = state[panelId];

    // Add user message
    const userMsg = { role: 'user', text };
    panel.messages.push(userMsg);
    renderMessage(panelId, userMsg);

    // Clear input
    document.getElementById(`${panelId}-input`).value = '';

    // Show loading
    panel.loading = true;
    renderLoadingMessage(panelId);
    setButtonsDisabled(true);

    // Send to agent
    const response = await sendA2AMessage(panelId, text);

    // Remove loading
    removeLoadingMessage(panelId);
    panel.loading = false;

    // Add agent response
    const blocked = isBlockedResponse(response.text);
    const agentMsg = {
        role: 'agent',
        text: response.text,
        error: response.error,
        blocked: blocked && panelId === 'protected'  // Only show blocked on protected panel
    };
    panel.messages.push(agentMsg);
    renderMessage(panelId, agentMsg);

    setButtonsDisabled(false);
}

async function handleSendToBoth() {
    const text = document.getElementById('unprotected-input').value ||
                 document.getElementById('protected-input').value;

    if (!text.trim()) return;

    // Clear both inputs
    document.getElementById('unprotected-input').value = '';
    document.getElementById('protected-input').value = '';

    // Add user messages to both
    ['unprotected', 'protected'].forEach(panelId => {
        const userMsg = { role: 'user', text };
        state[panelId].messages.push(userMsg);
        renderMessage(panelId, userMsg);
        renderLoadingMessage(panelId);
    });

    setButtonsDisabled(true);

    // Send to both in parallel
    const [unprotectedRes, protectedRes] = await Promise.all([
        sendA2AMessage('unprotected', text),
        sendA2AMessage('protected', text)
    ]);

    // Process responses
    [
        { panelId: 'unprotected', response: unprotectedRes },
        { panelId: 'protected', response: protectedRes }
    ].forEach(({ panelId, response }) => {
        removeLoadingMessage(panelId);

        const blocked = isBlockedResponse(response.text);
        const agentMsg = {
            role: 'agent',
            text: response.text,
            error: response.error,
            blocked: blocked && panelId === 'protected'
        };
        state[panelId].messages.push(agentMsg);
        renderMessage(panelId, agentMsg);
    });

    setButtonsDisabled(false);
}

function setButtonsDisabled(disabled) {
    document.querySelectorAll('.send-btn, #send-both-btn, .quick-prompt')
        .forEach(btn => btn.disabled = disabled);
}

// =============================================================================
// Event Handlers
// =============================================================================

function setupEventListeners() {
    // Individual send buttons
    document.querySelectorAll('.send-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const panelId = btn.dataset.panel;
            const input = document.getElementById(`${panelId}-input`);
            handleSend(panelId, input.value);
        });
    });

    // Enter key in inputs
    ['unprotected', 'protected'].forEach(panelId => {
        document.getElementById(`${panelId}-input`).addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSend(panelId, e.target.value);
            }
        });
    });

    // Send to Both button
    document.getElementById('send-both-btn').addEventListener('click', handleSendToBoth);

    // Quick prompts - populate both inputs
    document.querySelectorAll('.quick-prompt').forEach(btn => {
        btn.addEventListener('click', () => {
            const prompt = btn.dataset.prompt;
            document.getElementById('unprotected-input').value = prompt;
            document.getElementById('protected-input').value = prompt;
        });
    });

    // Settings modal
    const modal = document.getElementById('settings-modal');
    const settingsBtn = document.getElementById('settings-btn');

    settingsBtn.addEventListener('click', () => {
        document.getElementById('unprotected-url').value = state.unprotected.url;
        document.getElementById('protected-url').value = state.protected.url;
        modal.showModal();
    });

    modal.addEventListener('close', () => {
        if (modal.returnValue === 'save') {
            state.unprotected.url = document.getElementById('unprotected-url').value;
            state.protected.url = document.getElementById('protected-url').value;
            saveSettings();
        }
    });
}

// =============================================================================
// Initialization
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    setupEventListeners();
    preloadConversation();

    console.log('Vijil Travel Agent Demo loaded');
    console.log('Unprotected agent:', state.unprotected.url);
    console.log('Protected agent:', state.protected.url);
});
