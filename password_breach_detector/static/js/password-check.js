/**
 * Password Security Platform
 * Client-side script handling inline password checking, live metrics, and generation.
 */

let compositionChartInstance = null;

document.addEventListener('DOMContentLoaded', function() {
    // 1. Initialize Password Fields Visibility Toggles
    initPasswordVisibilityToggles();

    // 2. Initialize Live Password strength listeners
    const landingInput = document.getElementById('landing-password-input');
    const liveContainer = document.getElementById('live-strength-container');
    if (landingInput) {
        landingInput.addEventListener('input', function() {
            const val = this.value;
            if (val.length > 0) {
                liveContainer.classList.remove('hidden');
                const strength = evaluateLiveStrength(val);
                const bar = document.getElementById('live-strength-bar');
                const label = document.getElementById('live-strength-label');
                
                label.textContent = strength.label;
                label.className = "text-sm font-bold " + strength.textColor;
                
                bar.style.width = strength.width;
                bar.className = "h-2 rounded-full strength-progress-bar " + strength.color;
            } else {
                liveContainer.classList.add('hidden');
            }
        });
    }

    // 3. Landing Auditor form handler
    const auditorForm = document.getElementById('landing-auditor-form');
    if (auditorForm) {
        auditorForm.addEventListener('submit', function(e) {
            e.preventDefault();
            runPasswordAudit();
        });
    }

    // 4. Password Checker Page form handlers
    const checkForm = document.getElementById('password-check-form');
    if (checkForm) {
        checkForm.addEventListener('submit', function(e) {
            e.preventDefault();
            runPasswordCheckPageAudit();
        });
    }

    const strengthForm = document.getElementById('password-strength-form');
    if (strengthForm) {
        strengthForm.addEventListener('submit', function(e) {
            e.preventDefault();
            runPasswordCheckPageStrength();
        });
    }

    // 5. Password Generator Handler
    initPasswordGenerator();
});

/**
 * Password inputs visibility toggle helper
 */
function initPasswordVisibilityToggles() {
    const containers = document.querySelectorAll('.password-field-container');
    containers.forEach(container => {
        const input = container.querySelector('input');
        const toggle = container.querySelector('.password-toggle');
        if (input && toggle) {
            toggle.addEventListener('click', function() {
                if (input.type === 'password') {
                    input.type = 'text';
                    this.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" /></svg>';
                } else {
                    input.type = 'password';
                    this.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>';
                }
            });
        }
    });
}

/**
 * Local real-time strength evaluator
 */
function evaluateLiveStrength(password) {
    if (!password) {
        return { score: 0, label: 'Weak', color: 'bg-red-500', textColor: 'text-red-500', width: '0%' };
    }
    let score = 0;
    
    // Length points
    if (password.length >= 16) score += 1.5;
    else if (password.length >= 12) score += 1.25;
    else if (password.length >= 8) score += 0.75;
    
    // Charset checks
    if (/[a-z]/.test(password)) score += 0.5;
    if (/[A-Z]/.test(password)) score += 0.75;
    if (/[0-9]/.test(password)) score += 0.75;
    if (/[^A-Za-z0-9]/.test(password)) score += 0.75;
    
    let label = 'Weak';
    let color = 'bg-red-500';
    let textColor = 'text-red-500';
    let width = '25%';
    
    if (score >= 3.75) {
        label = 'Very Strong';
        color = 'bg-green-500';
        textColor = 'text-green-500';
        width = '100%';
    } else if (score >= 2.75) {
        label = 'Strong';
        color = 'bg-blue-500';
        textColor = 'text-blue-500';
        width = '75%';
    } else if (score >= 1.5) {
        label = 'Medium';
        color = 'bg-yellow-500';
        textColor = 'text-yellow-500';
        width = '50%';
    }
    
    return { score, label, color, textColor, width };
}

/**
 * Runs password audit by calling POST /api/check-password
 */
function runPasswordAudit() {
    const input = document.getElementById('landing-password-input');
    const loading = document.getElementById('landing-loading');
    const resultsArea = document.getElementById('landing-results-area');
    
    if (!input || !input.value) return;
    const password = input.value;
    
    // Show loading spinner
    if (loading) loading.classList.remove('hidden');
    if (resultsArea) resultsArea.classList.add('hidden');
    
    fetch('/api/check-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ password: password })
    })
    .then(res => {
        if (!res.ok) throw new Error('API request failed');
        return res.json();
    })
    .then(data => {
        if (loading) loading.classList.add('hidden');
        populateAuditResults(data, password);
        input.value = '';
        
        // Hide the live strength container since input is cleared
        const liveContainer = document.getElementById('live-strength-container');
        if (liveContainer) liveContainer.classList.add('hidden');
    })
    .catch(err => {
        console.error('Audit failed:', err);
        if (loading) loading.classList.add('hidden');
        showError('An error occurred during password auditing. Please try again.');
    });
}

/**
 * Populates API response into results card panels
 */
function populateAuditResults(data, password) {
    const area = document.getElementById('landing-results-area');
    if (!area) return;
    
    // Update Score
    const pct = Math.round(data.strength_score * 100);
    document.getElementById('res-score-pct').textContent = pct + "%";
    
    // Update Entropy
    document.getElementById('res-entropy-val').textContent = data.entropy + " bits";
    
    // Update Crack Time
    document.getElementById('res-crack-time').textContent = data.crack_time;
    
    // Update Breach status
    const statusText = document.getElementById('res-status-text');
    const statusBg = document.getElementById('res-status-icon-bg');
    const statusIcon = document.getElementById('res-status-icon');
    const statusDesc = document.getElementById('res-breach-desc');
    
    if (data.was_breached) {
        statusText.textContent = "Compromised (" + data.breach_count.toLocaleString() + " breaches)";
        statusBg.className = "p-1.5 rounded-full bg-red-100 text-red-600";
        statusIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />';
        statusDesc.textContent = "Warning! This password is exposed in leaked databases and is unsafe. Replace it immediately.";
    } else {
        statusText.textContent = "Secured / Clean";
        statusBg.className = "p-1.5 rounded-full bg-green-100 text-green-600";
        statusIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />';
        statusDesc.textContent = "Great news. We did not identify this password in public database dumps.";
    }
    
    // Populate recommendations list
    const recsList = document.getElementById('res-recs-list');
    if (data.recommendations && data.recommendations.length > 0) {
        let html = '<ul class="list-disc pl-5 space-y-1">';
        data.recommendations.forEach(rec => {
            html += `<li>${rec}</li>`;
        });
        html += '</ul>';
        recsList.innerHTML = html;
    } else {
        recsList.innerHTML = '<p class="text-green-600 font-semibold">Your password meets complexity and safety thresholds!</p>';
    }
    
    // Draw/Update Composition Pie Chart
    drawCompositionChart(password);
    
    // Show results area
    area.classList.remove('hidden');
}

/**
 * Calculates characters statistics locally and draws the Chart.js pie chart
 */
function drawCompositionChart(password) {
    let lower = 0, upper = 0, digits = 0, symbols = 0;
    const total = password.length;
    
    for (let i = 0; i < total; i++) {
        const c = password[i];
        if (/[a-z]/.test(c)) lower++;
        else if (/[A-Z]/.test(c)) upper++;
        else if (/[0-9]/.test(c)) digits++;
        else symbols++;
    }
    
    const lowerPct = Math.round((lower / total) * 100);
    const upperPct = Math.round((upper / total) * 100);
    const digitsPct = Math.round((digits / total) * 100);
    const symbolsPct = Math.round((symbols / total) * 100);
    
    const ctx = document.getElementById('compositionChart').getContext('2d');
    
    // Destroy previous instance
    if (compositionChartInstance) {
        compositionChartInstance.destroy();
    }
    
    compositionChartInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Lowercase %', 'Uppercase %', 'Numbers %', 'Symbols %'],
            datasets: [{
                data: [lowerPct, upperPct, digitsPct, symbolsPct],
                backgroundColor: ['#60a5fa', '#34d399', '#facc15', '#f87171'],
                borderWidth: 1,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { boxWidth: 12, padding: 15 }
                }
            }
        }
    });
}

/**
 * Initialize secure password generator
 */
function initPasswordGenerator() {
    const slider = document.getElementById('gen-length');
    const lengthVal = document.getElementById('gen-length-val');
    
    if (slider && lengthVal) {
        slider.addEventListener('input', function() {
            lengthVal.textContent = this.value;
        });
    }
    
    const generateBtn = document.getElementById('generate-pw-btn');
    if (generateBtn) {
        generateBtn.addEventListener('click', function() {
            const len = document.getElementById('gen-length').value;
            const upper = document.getElementById('gen-upper').checked;
            const lower = document.getElementById('gen-lower').checked;
            const numbers = document.getElementById('gen-numbers').checked;
            const symbols = document.getElementById('gen-symbols').checked;
            const similar = document.getElementById('gen-similar').checked;
            
            fetch(`/api/generate-password?length=${len}&uppercase=${upper}&lowercase=${lower}&numbers=${numbers}&symbols=${symbols}&exclude_similar=${similar}`)
            .then(res => res.json())
            .then(data => {
                const display = document.getElementById('generated-password-display');
                if (display) {
                    display.textContent = data.password;
                    display.className = "font-mono text-lg text-green-600 font-extrabold select-all tracking-wide break-all mr-10";
                }
            })
            .catch(err => {
                console.error("Generator failed:", err);
                showError("Could not connect to generator API.");
            });
        });
    }
    
    const copyBtn = document.getElementById('copy-generated-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', function() {
            const display = document.getElementById('generated-password-display');
            if (display && display.textContent && display.textContent !== 'Click Generate...') {
                navigator.clipboard.writeText(display.textContent)
                .then(() => {
                    showToast('Copied password to clipboard!');
                })
                .catch(err => {
                    console.error('Clipboard copy failed:', err);
                });
            }
        });
    }
}

/**
 * Helper to display temporary toast notifications
 */
function showToast(message) {
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
 * Error display helper
 */
function showError(message) {
    const alertBox = document.createElement('div');
    alertBox.className = 'bg-red-50 border border-red-200 text-red-800 px-4 py-3.5 rounded-xl relative mb-6 flex items-center justify-between shadow-sm';
    alertBox.role = 'alert';
    alertBox.innerHTML = `
        <span class="block sm:inline font-medium">${message}</span>
        <span class="cursor-pointer font-bold ml-4 text-red-400 hover:text-red-600">✕</span>
    `;
    
    document.querySelector('main').prepend(alertBox);
    
    alertBox.querySelector('span:last-child').addEventListener('click', function() {
        alertBox.remove();
    });
    
    setTimeout(() => {
        if (alertBox.parentNode) {
            alertBox.remove();
        }
    }, 5000);
}

/**
 * Get CSRF token helper
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
 * Run password check page audit (exposure check)
 */
function runPasswordCheckPageAudit() {
    const input = document.getElementById('password-input');
    const loading = document.getElementById('loading-indicator');
    const container = document.getElementById('result-container');
    
    if (!input || !input.value) return;
    const password = input.value;
    
    if (loading) loading.classList.remove('hidden');
    if (container) container.classList.add('hidden');
    
    fetch('/api/check-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ password: password })
    })
    .then(res => res.json())
    .then(data => {
        if (loading) loading.classList.add('hidden');
        if (container) {
            let html = '';
            if (data.was_breached) {
                html = `
                    <div class="bg-red-50 border border-red-200 rounded-xl p-4 text-red-800">
                        <h4 class="font-bold">Compromised!</h4>
                        <p class="text-sm mt-1">This password was found in <strong>${data.breach_count.toLocaleString()}</strong> data breaches. Do not use this password!</p>
                    </div>
                `;
            } else {
                html = `
                    <div class="bg-green-50 border border-green-200 rounded-xl p-4 text-green-800">
                        <h4 class="font-bold">Clean / Safe!</h4>
                        <p class="text-sm mt-1">This password was not found in known database breaches.</p>
                    </div>
                `;
            }
            container.innerHTML = html;
            container.classList.remove('hidden');
        }
        input.value = '';
    })
    .catch(err => {
        console.error(err);
        if (loading) loading.classList.add('hidden');
        showError('Audit check failed.');
    });
}

/**
 * Run password check page strength complexity analyzer
 */
function runPasswordCheckPageStrength() {
    const input = document.getElementById('strength-password-input');
    const loading = document.getElementById('strength-loading-indicator');
    const container = document.getElementById('strength-result-container');
    
    if (!input || !input.value) return;
    const password = input.value;
    
    if (loading) loading.classList.remove('hidden');
    if (container) container.classList.add('hidden');
    
    fetch('/api/check-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ password: password })
    })
    .then(res => res.json())
    .then(data => {
        if (loading) loading.classList.add('hidden');
        if (container) {
            let recsHtml = '';
            if (data.recommendations && data.recommendations.length > 0) {
                recsHtml = '<ul class="list-disc pl-5 mt-2 space-y-1 text-xs text-gray-600">';
                data.recommendations.forEach(r => {
                    recsHtml += `<li>${r}</li>`;
                });
                recsHtml += '</ul>';
            } else {
                recsHtml = '<p class="text-xs text-green-600 font-semibold mt-2">Meets complexity guidelines.</p>';
            }
            
            container.innerHTML = `
                <div class="space-y-3">
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 font-semibold">Strength Rating:</span>
                        <span class="font-bold text-blue-600">${Math.round(data.strength_score * 100)}%</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 font-semibold">Shannon Entropy:</span>
                        <span class="font-bold font-mono text-gray-700">${data.entropy} bits</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 font-semibold">Est. Crack Time:</span>
                        <span class="font-bold text-gray-700">${data.crack_time}</span>
                    </div>
                    <div class="pt-2 border-t border-gray-200">
                        <span class="text-xs text-gray-400 font-bold uppercase tracking-wider block">Recommendations</span>
                        ${recsHtml}
                    </div>
                </div>
            `;
            container.classList.remove('hidden');
        }
        input.value = '';
    })
    .catch(err => {
        console.error(err);
        if (loading) loading.classList.add('hidden');
        showError('Strength analysis failed.');
    });
}