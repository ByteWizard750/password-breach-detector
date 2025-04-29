/**
 * Password Breach Detector
 * Client-side logic for secure password checking
 */

document.addEventListener('DOMContentLoaded', function() {
    // Password breach check form
    const passwordForm = document.getElementById('password-check-form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', function(e) {
            e.preventDefault();
            checkPasswordBreaches();
        });
    }
    
    // Password strength analyzer form
    const strengthForm = document.getElementById('password-strength-form');
    if (strengthForm) {
        strengthForm.addEventListener('submit', function(e) {
            e.preventDefault();
            analyzePasswordStrength();
        });
    }
});

/**
 * Check if a password has been exposed in data breaches
 * Uses k-anonymity model to protect the password
 */
function checkPasswordBreaches() {
    const passwordInput = document.getElementById('password-input');
    const resultContainer = document.getElementById('result-container');
    const loadingIndicator = document.getElementById('loading-indicator');
    
    if (!passwordInput || !passwordInput.value) {
        showError('Please enter a password to check');
        return;
    }
    
    // Show loading indicator
    if (loadingIndicator) {
        loadingIndicator.classList.remove('hidden');
    }
    
    // Clear previous results
    if (resultContainer) {
        resultContainer.innerHTML = '';
        resultContainer.classList.add('hidden');
    }
    
    try {
        // Get the password
        const password = passwordInput.value;
        
        // Create SHA-1 hash of the password
        const hashHex = CryptoJS.SHA1(password).toString().toUpperCase();
        
        // Split the hash into prefix and suffix
        const hashPrefix = hashHex.substring(0, 5);
        const hashSuffix = hashHex.substring(5);
        
        // Send the prefix to our backend
        fetch('/api/password/check/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken(),
            },
            body: JSON.stringify({
                hash_prefix: hashPrefix,
                hash_suffix: hashSuffix
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Hide loading indicator
            if (loadingIndicator) {
                loadingIndicator.classList.add('hidden');
            }
            
            // Display results
            displayBreachResults(data);
            
            // Clear the password input for security
            passwordInput.value = '';
        })
        .catch(error => {
            console.error('Error checking password:', error);
            // Hide loading indicator
            if (loadingIndicator) {
                loadingIndicator.classList.add('hidden');
            }
            showError('An error occurred while checking the password. Please try again.');
        });
    } catch (error) {
        console.error('Error processing password:', error);
        // Hide loading indicator
        if (loadingIndicator) {
            loadingIndicator.classList.add('hidden');
        }
        showError('An error occurred while processing the password. Please try again.');
    }
}

/**
 * Display the results of the breach check
 */
function displayBreachResults(data) {
    const resultContainer = document.getElementById('result-container');
    
    if (!resultContainer) return;
    
    resultContainer.classList.remove('hidden');
    
    if (data.was_breached) {
        // Password was found in breaches
        resultContainer.innerHTML = `
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <svg class="h-6 w-6 text-red-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                </div>
                <div class="ml-3">
                    <h3 class="text-lg font-medium text-red-800 dark:text-red-400">Password Compromised!</h3>
                    <div class="mt-2 text-sm text-gray-600 dark:text-gray-300">
                        <p>This password was found in <strong>${data.breach_count.toLocaleString()}</strong> data breaches.</p>
                        <p class="mt-2">This password is not safe to use. You should:</p>
                        <ul class="list-disc pl-5 mt-1">
                            <li>Change this password immediately on any site where you use it</li>
                            <li>Never use this password again</li>
                            <li>Use a unique password for each account</li>
                            <li>Consider using a password manager</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    } else {
        // Password not found in breaches
        resultContainer.innerHTML = `
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <svg class="h-6 w-6 text-green-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                    </svg>
                </div>
                <div class="ml-3">
                    <h3 class="text-lg font-medium text-green-800 dark:text-green-400">Good News!</h3>
                    <div class="mt-2 text-sm text-gray-600 dark:text-gray-300">
                        <p>This password was not found in any known data breaches.</p>
                        <p class="mt-2">Remember to:</p>
                        <ul class="list-disc pl-5 mt-1">
                            <li>Use a unique password for each account</li>
                            <li>Use long, complex passwords</li>
                            <li>Enable two-factor authentication when available</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    }
}

/**
 * Analyze password strength and provide recommendations
 */
function analyzePasswordStrength() {
    const passwordInput = document.getElementById('strength-password-input');
    const resultContainer = document.getElementById('strength-result-container');
    const loadingIndicator = document.getElementById('strength-loading-indicator');
    
    if (!passwordInput || !passwordInput.value) {
        showError('Please enter a password to analyze');
        return;
    }
    
    // Show loading indicator
    if (loadingIndicator) {
        loadingIndicator.classList.remove('hidden');
    }
    
    // Clear previous results
    if (resultContainer) {
        resultContainer.innerHTML = '';
        resultContainer.classList.add('hidden');
    }
    
    try {
        const password = passwordInput.value;
        
        // Create SHA-1 hash of the password
        const hashHex = CryptoJS.SHA1(password).toString().toUpperCase();
        
        // Only send the prefix to our backend
        const hashPrefix = hashHex.substring(0, 5);
        
        // Check password characteristics
        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasNumbers = /[0-9]/.test(password);
        const hasSymbols = /[^A-Za-z0-9]/.test(password);
        
        // Send data to our backend
        fetch('/api/password/analyze-strength/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken(),
            },
            body: JSON.stringify({
                hash_prefix: hashPrefix,
                length: password.length,
                has_uppercase: hasUppercase,
                has_lowercase: hasLowercase,
                has_numbers: hasNumbers,
                has_symbols: hasSymbols
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Hide loading indicator
            if (loadingIndicator) {
                loadingIndicator.classList.add('hidden');
            }
            
            // Display results
            displayStrengthResults(data);
            
            // Clear the password input for security
            passwordInput.value = '';
        })
        .catch(error => {
            console.error('Error analyzing password:', error);
            // Hide loading indicator
            if (loadingIndicator) {
                loadingIndicator.classList.add('hidden');
            }
            showError('An error occurred while analyzing the password. Please try again.');
        });
    } catch (error) {
        console.error('Error processing password:', error);
        // Hide loading indicator
        if (loadingIndicator) {
            loadingIndicator.classList.add('hidden');
        }
        showError('An error occurred while processing the password. Please try again.');
    }
}

/**
 * Display password strength results
 */
function displayStrengthResults(data) {
    const resultContainer = document.getElementById('strength-result-container');
    
    if (!resultContainer) return;
    
    resultContainer.classList.remove('hidden');
    
    // Determine strength category and color
    let strengthCategory = 'Very Weak';
    let strengthColor = 'red';
    let progressWidth = Math.round(data.strength_score * 100);
    
    if (data.strength_score >= 0.8) {
        strengthCategory = 'Very Strong';
        strengthColor = 'green';
    } else if (data.strength_score >= 0.6) {
        strengthCategory = 'Strong';
        strengthColor = 'blue';
    } else if (data.strength_score >= 0.4) {
        strengthCategory = 'Medium';
        strengthColor = 'yellow';
    } else if (data.strength_score >= 0.2) {
        strengthCategory = 'Weak';
        strengthColor = 'orange';
    }
    
    // Build recommendations HTML
    let recommendationsHtml = '';
    if (data.recommendations && data.recommendations.length > 0) {
        recommendationsHtml = '<ul class="list-disc pl-5 mt-2">';
        data.recommendations.forEach(rec => {
            recommendationsHtml += `<li>${rec}</li>`;
        });
        recommendationsHtml += '</ul>';
    } else {
        recommendationsHtml = '<p class="mt-2">No specific recommendations - your password looks good!</p>';
    }
    
    // Render result
    resultContainer.innerHTML = `
        <h3 class="text-lg font-medium mb-3">Password Strength: ${strengthCategory}</h3>
        
        <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700 mb-4">
            <div class="bg-${strengthColor}-600 h-2.5 rounded-full" style="width: ${progressWidth}%"></div>
        </div>
        
        <div class="mt-4">
            <h4 class="font-medium">Recommendations:</h4>
            ${recommendationsHtml}
        </div>
    `;
}

/**
 * Display an error message
 */
function showError(message) {
    const alertBox = document.createElement('div');
    alertBox.className = 'bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4';
    alertBox.role = 'alert';
    alertBox.innerHTML = `
        <span class="block sm:inline">${message}</span>
        <span class="absolute top-0 bottom-0 right-0 px-4 py-3">
            <svg class="fill-current h-6 w-6 text-red-500" role="button" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                <title>Close</title>
                <path d="M14.348 14.849a1.2 1.2 0 0 1-1.697 0L10 11.819l-2.651 3.029a1.2 1.2 0 1 1-1.697-1.697l2.758-3.15-2.759-3.152a1.2 1.2 0 1 1 1.697-1.697L10 8.183l2.651-3.031a1.2 1.2 0 1 1 1.697 1.697l-2.758 3.152 2.758 3.15a1.2 1.2 0 0 1 0 1.698z"/>
            </svg>
        </span>
    `;
    
    document.querySelector('main').prepend(alertBox);
    
    // Add click event to close button
    alertBox.querySelector('svg').addEventListener('click', function() {
        alertBox.remove();
    });
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertBox.parentNode) {
            alertBox.remove();
        }
    }, 5000);
}

/**
 * Get CSRF token from cookies
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