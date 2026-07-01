/**
 * Password Breach Detector
 * Main JavaScript file
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize mobile menu
    initMobileMenu();
    
    // Initialize dark mode toggle
    initDarkMode();
    
    // Initialize tooltips
    initTooltips();
    
    // Initialize password toggles
    initPasswordToggles();
    
    // Initialize notification dismissal
    initNotificationDismissal();
    
    // Initialize dashboard charts if present
    if (document.getElementById('security-score-chart')) {
        initSecurityScoreChart();
    }
    
    if (document.getElementById('breach-history-chart')) {
        initBreachHistoryChart();
    }
});

/**
 * Initialize mobile menu functionality
 */
function initMobileMenu() {
    const mobileMenuButton = document.querySelector('[x-data="{ open: false }"]');
    const mobileMenu = document.querySelector('[x-data="{ mobileMenuOpen: false }"]');
    
    if (mobileMenuButton && mobileMenu) {
        mobileMenuButton.addEventListener('click', function() {
            const isOpen = mobileMenu.classList.contains('hidden');
            
            if (isOpen) {
                mobileMenu.classList.remove('hidden');
            } else {
                mobileMenu.classList.add('hidden');
            }
        });
    }
}

/**
 * Initialize dark mode toggle functionality
 */
function initDarkMode() {
    // Check if user has already set a preference
    const darkModePref = localStorage.getItem('darkMode');
    const html = document.documentElement;
    
    // Set initial state based on preference or system default
    if (darkModePref === 'true' || (darkModePref === null && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        html.classList.add('dark');
    } else {
        html.classList.remove('dark');
    }
    
    // Add event listener to toggle buttons
    const darkModeToggle = document.querySelector('[x-data="{ darkMode: true }"] button');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            html.classList.toggle('dark');
            localStorage.setItem('darkMode', html.classList.contains('dark'));
        });
    }
}

/**
 * Initialize tooltips
 */
function initTooltips() {
    const tooltipTriggers = document.querySelectorAll('[data-tooltip]');
    
    tooltipTriggers.forEach(trigger => {
        trigger.addEventListener('mouseenter', function() {
            const tooltipText = this.getAttribute('data-tooltip');
            
            const tooltip = document.createElement('div');
            tooltip.className = 'absolute z-10 px-3 py-2 text-sm font-medium text-white bg-gray-900 rounded-lg shadow-sm tooltip';
            tooltip.textContent = tooltipText;
            tooltip.style.bottom = '100%';
            tooltip.style.left = '50%';
            tooltip.style.transform = 'translateX(-50%) translateY(-8px)';
            tooltip.style.whiteSpace = 'nowrap';
            
            this.style.position = 'relative';
            this.appendChild(tooltip);
        });
        
        trigger.addEventListener('mouseleave', function() {
            const tooltip = this.querySelector('.tooltip');
            if (tooltip) {
                tooltip.remove();
            }
        });
    });
}

/**
 * Initialize password visibility toggles
 */
function initPasswordToggles() {
    const passwordFields = document.querySelectorAll('.password-field-container');
    
    passwordFields.forEach(container => {
        const input = container.querySelector('input[type="password"]');
        const toggleBtn = container.querySelector('.password-toggle');
        
        if (input && toggleBtn) {
            toggleBtn.addEventListener('click', function() {
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
 * Initialize notification dismissal functionality
 */
function initNotificationDismissal() {
    const closeButtons = document.querySelectorAll('.notification .close-btn');
    
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const notification = this.closest('.notification');
            if (notification) {
                notification.remove();
            }
        });
    });
}

/**
 * Initialize security score chart
 */
function initSecurityScoreChart() {
    const ctx = document.getElementById('security-score-chart').getContext('2d');
    
    // Get data from the element's data attributes
    const score = parseInt(document.getElementById('security-score-chart').getAttribute('data-score'));
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Secure', 'Room for Improvement'],
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [
                    score >= 80 ? '#10B981' : score >= 60 ? '#3B82F6' : score >= 40 ? '#F59E0B' : '#EF4444',
                    '#E5E7EB'
                ],
                borderWidth: 0
            }]
        },
        options: {
            cutout: '75%',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        }
    });
}

/**
 * Initialize breach history chart
 */
function initBreachHistoryChart() {
    const ctx = document.getElementById('breach-history-chart').getContext('2d');
    
    // Get data from the element's data attributes
    const dataElement = document.getElementById('breach-history-chart');
    const labels = JSON.parse(dataElement.getAttribute('data-labels'));
    const breachCounts = JSON.parse(dataElement.getAttribute('data-breach-counts'));
    const checkCounts = JSON.parse(dataElement.getAttribute('data-check-counts'));
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Password Checks',
                    data: checkCounts,
                    borderColor: '#3B82F6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Breached Passwords',
                    data: breachCounts,
                    borderColor: '#EF4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}