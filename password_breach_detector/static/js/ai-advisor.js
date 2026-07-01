/**
 * AI Security Assistant Client Controller
 */

document.addEventListener('DOMContentLoaded', function() {
    initAIChatWidget();
});

function initAIChatWidget() {
    const chatForm = document.getElementById('ai-chat-form');
    const chatInput = document.getElementById('ai-chat-input');
    const messagesBox = document.getElementById('ai-messages-box');
    const clearBtn = document.getElementById('ai-clear-btn');
    const suggestions = document.querySelectorAll('.ai-suggest-chip');

    // 1. Submit query
    if (chatForm && chatInput && messagesBox) {
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const message = chatInput.value.trim();
            if (!message) return;

            chatInput.value = '';
            sendMessageToAssistant(message);
        });
    }

    // 2. Click suggestion chips
    suggestions.forEach(chip => {
        chip.addEventListener('click', function() {
            const promptText = this.getAttribute('data-prompt');
            if (promptText) {
                sendMessageToAssistant(promptText);
            }
        });
    });

    // 3. Clear chat history
    if (clearBtn && messagesBox) {
        clearBtn.addEventListener('click', function() {
            if (confirm("Are you sure you want to clear this conversation history?")) {
                messagesBox.innerHTML = `
                    <div class="flex items-start space-x-2.5">
                        <div class="h-7 w-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center flex-shrink-0 font-bold text-xs">AI</div>
                        <div class="bg-blue-50 border border-blue-100 rounded-2xl rounded-tl-none p-3.5 shadow-sm text-sm text-gray-800 leading-relaxed max-w-[85%]">
                            Conversation cleared. How can I assist you with your credential audits or settings today?
                        </div>
                    </div>
                `;
                const statusLabel = document.getElementById('ai-status-label');
                if (statusLabel) statusLabel.textContent = "Your Cybersecurity Assistant";
            }
        });
    }
}

/**
 * Sends a prompt message to the AI Security Assistant backend API
 */
function sendMessageToAssistant(promptText) {
    const messagesBox = document.getElementById('ai-messages-box');
    if (!messagesBox) return;

    // Append User message bubble
    appendChatMessage('user', promptText);

    // Append Typing loading indicator
    const typingId = appendTypingIndicator();

    fetch('/api/ai-advisor/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ message: promptText })
    })
    .then(res => {
        if (!res.ok) throw new Error('API response error');
        return res.json();
    })
    .then(data => {
        removeTypingIndicator(typingId);
        
        // Update Status label if fallback/offline mode is active
        const statusLabel = document.getElementById('ai-status-label');
        if (statusLabel) {
            statusLabel.textContent = data.is_fallback ? "Running in Offline Security Advisor mode." : "Your Cybersecurity Assistant";
        }
        
        // Clean response from Sentinel references
        let cleanResponse = data.response.replace(/Sentinel AI/g, "AI Security Assistant").replace(/Sentinel/g, "AI Security Assistant");
        
        // Append AI response bubble
        appendChatMessage('ai', cleanResponse);
    })
    .catch(err => {
        console.error(err);
        removeTypingIndicator(typingId);
        appendChatMessage('ai', "I apologize, but I am having trouble connecting. Let me know if you would like me to outline standard security recommendations offline.");
    });
}

/**
 * Appends a message bubble to the messages list with timestamps
 */
function appendChatMessage(sender, text) {
    const messagesBox = document.getElementById('ai-messages-box');
    if (!messagesBox) return;

    const wrapper = document.createElement('div');
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    if (sender === 'user') {
        wrapper.className = 'flex flex-col items-end space-y-1';
        wrapper.innerHTML = `
            <div class="flex items-start justify-end space-x-2.5">
                <div class="bg-blue-600 text-white rounded-2xl rounded-tr-none p-3 shadow-sm text-sm leading-relaxed max-w-[85%] break-words">
                    ${escapeHtml(text)}
                </div>
                <div class="h-7 w-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center flex-shrink-0 font-bold text-xs">U</div>
            </div>
            <span class="text-[10px] text-gray-400 mr-9">${timeStr}</span>
        `;
    } else {
        wrapper.className = 'flex flex-col items-start space-y-1 group';
        const formattedText = parseMarkdown(text);
        const uuid = 'copy-' + Math.random().toString(36).substr(2, 9);
        
        wrapper.innerHTML = `
            <div class="flex items-start space-x-2.5">
                <div class="h-7 w-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center flex-shrink-0 font-bold text-xs">AI</div>
                <div class="relative bg-blue-50 border border-blue-100 rounded-2xl rounded-tl-none p-3.5 shadow-sm text-sm text-gray-800 leading-relaxed max-w-[85%] break-words">
                    <div class="pr-6 font-normal space-y-1" id="${uuid}">${formattedText}</div>
                    <button onclick="copyToClipboardText('${uuid}')" 
                            class="absolute top-2 right-2 p-1 text-gray-400 hover:text-gray-700 opacity-0 group-hover:opacity-100 transition-opacity focus:outline-none" 
                            title="Copy Response">
                        <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2" />
                        </svg>
                    </button>
                </div>
            </div>
            <span class="text-[10px] text-gray-400 ml-9">${timeStr}</span>
        `;
    }

    messagesBox.appendChild(wrapper);
    messagesBox.scrollTop = messagesBox.scrollHeight;
}

/**
 * Appends the three-dot pulsing typing loader with "Thinking..." text
 */
function appendTypingIndicator() {
    const messagesBox = document.getElementById('ai-messages-box');
    if (!messagesBox) return null;

    const id = 'typing-' + Math.random().toString(36).substr(2, 9);
    const wrapper = document.createElement('div');
    wrapper.id = id;
    wrapper.className = 'flex items-start space-x-2.5';
    wrapper.innerHTML = `
        <div class="h-7 w-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center flex-shrink-0 font-bold text-xs">AI</div>
        <div class="bg-blue-50 border border-blue-100 rounded-2xl rounded-tl-none p-3.5 shadow-sm flex items-center space-x-1.5 py-3 px-5">
            <span class="text-xs text-gray-500 font-semibold mr-1">Thinking...</span>
            <div class="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0s"></div>
            <div class="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0.2s"></div>
            <div class="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0.4s"></div>
        </div>
    `;

    messagesBox.appendChild(wrapper);
    messagesBox.scrollTop = messagesBox.scrollHeight;
    return id;
}

/**
 * Removes the typing indicator once data resolves
 */
function removeTypingIndicator(id) {
    if (!id) return;
    const el = document.getElementById(id);
    if (el) el.remove();
}

/**
 * Helper to copy response text
 */
function copyToClipboardText(id) {
    const el = document.getElementById(id);
    if (el) {
        navigator.clipboard.writeText(el.innerText)
        .then(() => {
            showToastNotification('Response copied to clipboard!');
        })
        .catch(err => {
            console.error('Clipboard write failed:', err);
        });
    }
}

/**
 * Visual Toast notification
 */
function showToastNotification(message) {
    const toast = document.createElement('div');
    toast.className = 'fixed bottom-5 right-5 z-50 py-3 px-6 bg-green-950 border border-green-800 text-green-300 font-semibold rounded-xl shadow-lg transition duration-300 transform translate-y-2 opacity-0 toast-slide';
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
    }, 10);
    
    setTimeout(() => {
        toast.classList.add('translate-y-2', 'opacity-0');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 3000);
}

/**
 * Safe HTML escape
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

/**
 * Lightweight, client-side Markdown formatter with tables and code support
 */
function parseMarkdown(text) {
    let escaped = escapeHtml(text);
    
    // Code blocks: ```language ... ```
    escaped = escaped.replace(/```(?:[a-zA-Z0-9]+)?\n([\s\S]*?)\n```/g, '<pre class="bg-gray-800 text-gray-100 p-3 rounded-xl font-mono text-xs overflow-x-auto my-2">$1</pre>');
    
    // Split into lines for line-by-line parsing
    let lines = escaped.split('\n');
    let result = [];
    let inTable = false;
    let tableHTML = '';
    
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        
        // Handle Table lines: starts and ends with "|"
        if (line.startsWith('|') && line.endsWith('|')) {
            if (!inTable) {
                inTable = true;
                tableHTML = '<div class="overflow-x-auto my-2 rounded-xl border border-gray-200"><table class="min-w-full divide-y divide-gray-200 text-xs text-left">';
            }
            
            const cells = line.split('|').map(c => c.trim()).filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
            
            // Check if it is a separator line (e.g. |---|---|)
            if (cells.every(c => /^:-*-*:?$/.test(c) || /^-+$/.test(c))) {
                continue;
            }
            
            // Determine if it's header
            if (tableHTML.endsWith('text-left">')) {
                tableHTML += '<thead class="bg-gray-50 text-gray-500 font-semibold uppercase tracking-wider"><tr>';
                cells.forEach(c => {
                    tableHTML += `<th class="px-3 py-2 border-b border-gray-200">${c}</th>`;
                });
                tableHTML += '</tr></thead><tbody class="divide-y divide-gray-100 bg-white">';
            } else {
                tableHTML += '<tr class="hover:bg-gray-50">';
                cells.forEach(c => {
                    tableHTML += `<td class="px-3 py-2 text-gray-600">${c}</td>`;
                });
                tableHTML += '</tr>';
            }
            continue;
        } else {
            if (inTable) {
                inTable = false;
                tableHTML += '</tbody></table></div>';
                result.push(tableHTML);
                tableHTML = '';
            }
        }
        
        // Headings
        if (line.startsWith('### ')) {
            result.push(`<h5 class="text-xs font-bold text-gray-950 mt-3 mb-1 uppercase tracking-wider">${line.substring(4)}</h5>`);
        } else if (line.startsWith('## ')) {
            result.push(`<h4 class="text-sm font-bold text-gray-950 mt-4 mb-1">${line.substring(3)}</h4>`);
        } else if (line.startsWith('# ')) {
            result.push(`<h3 class="text-base font-extrabold text-gray-950 mt-4 mb-2">${line.substring(2)}</h3>`);
        }
        // Bullet lists
        else if (line.startsWith('- ')) {
            result.push(`<li class="list-disc pl-1 ml-4 my-1 text-gray-700">${line.substring(2)}</li>`);
        }
        // Empty lines
        else if (line === '') {
            result.push('<div class="h-2"></div>');
        }
        // Normal paragraph line
        else {
            result.push(line);
        }
    }
    
    if (inTable) {
        tableHTML += '</tbody></table></div>';
        result.push(tableHTML);
    }
    
    // Join lines back
    let finalHtml = result.join('\n');
    
    // Format inline elements: bold (**text**)
    finalHtml = finalHtml.replace(/\*\*(.*?)\*\*/g, '<strong class="font-bold text-gray-950">$1</strong>');
    
    // Format inline elements: italic (*text*)
    finalHtml = finalHtml.replace(/\*(.*?)\*/g, '<em class="italic text-gray-800">$1</em>');
    
    // Format linebreaks except for tag boundaries
    finalHtml = finalHtml.replace(/\n/g, '<br>');
    
    return finalHtml;
}

/**
 * Helper to get CSRF token
 */
function getCsrfToken() {
    const name = 'csrftoken';
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Global trigger to open AI chat window and send a message from dashboard prompts
 */
window.triggerSentinelChat = function(promptText) {
    const chatWidget = document.getElementById('ai-chat-widget');
    if (chatWidget) {
        try {
            const alpineData = Alpine.$data(chatWidget);
            if (alpineData) {
                alpineData.open = true;
                alpineData.minimized = false;
            }
        } catch (e) {
            console.error('Alpine integration failed:', e);
            chatWidget.querySelector('button').style.display = 'none';
            chatWidget.querySelector('div').classList.remove('hidden');
        }
    }
    sendMessageToAssistant(promptText);
};

/**
 * Global trigger to open AI chat window silently without sending a message
 */
window.openSentinelChat = function() {
    const chatWidget = document.getElementById('ai-chat-widget');
    if (chatWidget) {
        try {
            const alpineData = Alpine.$data(chatWidget);
            if (alpineData) {
                alpineData.open = true;
                alpineData.minimized = false;
            }
        } catch (e) {
            console.error('Alpine integration failed:', e);
            chatWidget.querySelector('button').style.display = 'none';
            chatWidget.querySelector('div').classList.remove('hidden');
        }
    }
};
