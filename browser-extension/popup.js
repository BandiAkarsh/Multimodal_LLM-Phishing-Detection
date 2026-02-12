/**
 * Phishing Guard - Popup Script
 * Handles user interactions in the browser extension popup
 */

(function() {
    'use strict';

    // Default API configuration
    const DEFAULT_API_URL = 'http://localhost:8000';
    let currentApiUrl = DEFAULT_API_URL;

    /**
     * Initialize popup when DOM is ready
     */
    document.addEventListener('DOMContentLoaded', function() {
        initializePopup();
    });

    /**
     * Initialize popup functionality
     */
    function initializePopup() {
        // Load saved settings
        loadSettings();

        // Set up event listeners
        setupEventListeners();

        // Get current tab info
        getCurrentTabInfo();

        // Check API status
        checkApiStatus();
    }

    /**
     * Load settings from Chrome storage
     */
    function loadSettings() {
        chrome.storage.sync.get(['enabled', 'notifications', 'apiUrl'], function(result) {
            // Set toggle states
            document.getElementById('toggleEnabled').checked = result.enabled !== false;
            document.getElementById('toggleNotifications').checked = result.notifications !== false;

            // Set API URL
            if (result.apiUrl) {
                currentApiUrl = result.apiUrl;
                document.getElementById('apiUrlInput').value = result.apiUrl;
            } else {
                document.getElementById('apiUrlInput').value = DEFAULT_API_URL;
            }
        });
    }

    /**
     * Set up event listeners
     */
    function setupEventListeners() {
        // Toggle protection
        document.getElementById('toggleEnabled').addEventListener('change', function(e) {
            const enabled = e.target.checked;
            chrome.storage.sync.set({ enabled: enabled }, function() {
                // Notify content script
                chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
                    if (tabs[0]) {
                        chrome.tabs.sendMessage(tabs[0].id, {
                            action: 'toggle',
                            enabled: enabled
                        });
                    }
                });
            });
        });

        // Toggle notifications
        document.getElementById('toggleNotifications').addEventListener('change', function(e) {
            const notifications = e.target.checked;
            chrome.storage.sync.set({ notifications: notifications });
        });

        // Save API URL
        document.getElementById('saveApiUrl').addEventListener('click', saveApiUrl);

        // Quick scan button
        document.getElementById('scanButton').addEventListener('click', performQuickScan);

        // Enter key on URL input
        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                performQuickScan();
            }
        });

        // Open settings button
        document.getElementById('openSettings').addEventListener('click', function() {
            chrome.tabs.create({ url: chrome.runtime.getURL('settings.html') });
        });

        // View history button
        document.getElementById('viewHistory').addEventListener('click', function() {
            chrome.tabs.create({ url: chrome.runtime.getURL('history.html') });
        });
    }

    /**
     * Save API URL configuration
     */
    function saveApiUrl() {
        const urlInput = document.getElementById('apiUrlInput');
        const statusEl = document.getElementById('apiUrlStatus');
        let url = urlInput.value.trim();

        // Validate URL
        if (!url) {
            url = DEFAULT_API_URL;
        }

        // Remove trailing slash
        url = url.replace(/\/$/, '');

        // Basic URL validation
        try {
            new URL(url);
        } catch (e) {
            showStatus(statusEl, 'Invalid URL format', 'error');
            return;
        }

        // Test connection
        showStatus(statusEl, 'Testing connection...', 'info');

        fetch(`${url}/health`)
            .then(response => {
                if (response.ok) {
                    return response.json();
                }
                throw new Error('Connection failed');
            })
            .then(data => {
                // Save the URL
                chrome.storage.sync.set({ apiUrl: url }, function() {
                    currentApiUrl = url;
                    showStatus(statusEl, '✓ Connected successfully!', 'success');

                    // Update API status indicator
                    updateApiStatus(true);
                });
            })
            .catch(error => {
                console.error('API connection test failed:', error);
                showStatus(statusEl, '✗ Cannot connect to API', 'error');
                updateApiStatus(false);
            });
    }

    /**
     * Show status message
     */
    function showStatus(element, message, type) {
        element.textContent = message;
        element.className = 'status-message ' + type;

        // Clear after 5 seconds
        setTimeout(() => {
            element.textContent = '';
            element.className = 'status-message';
        }, 5000);
    }

    /**
     * Check API status
     */
    function checkApiStatus() {
        fetch(`${currentApiUrl}/health`, { method: 'GET' })
            .then(response => {
                updateApiStatus(response.ok);
            })
            .catch(() => {
                updateApiStatus(false);
            });
    }

    /**
     * Update API status indicator
     */
    function updateApiStatus(isConnected) {
        const indicator = document.getElementById('statusIndicator');
        const dot = indicator.querySelector('.status-dot');
        const text = indicator.querySelector('.status-text');

        if (isConnected) {
            indicator.classList.remove('disconnected');
            indicator.classList.add('connected');
            dot.style.backgroundColor = '#22c55e';
            text.textContent = 'Connected';
        } else {
            indicator.classList.remove('connected');
            indicator.classList.add('disconnected');
            dot.style.backgroundColor = '#ef4444';
            text.textContent = 'Disconnected';
        }
    }

    /**
     * Get current tab information
     */
    function getCurrentTabInfo() {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs[0]) {
                const url = tabs[0].url;
                document.getElementById('currentUrl').textContent = url;

                // Request scan results from content script
                chrome.tabs.sendMessage(tabs[0].id, { action: 'getResults' }, function(response) {
                    if (response && response.results) {
                        updatePageStats(response.results);
                    }
                });
            }
        });
    }

    /**
     * Update page statistics display
     */
    function updatePageStats(results) {
        let scannedCount = 0;
        let threatCount = 0;

        for (const [url, result] of Object.entries(results)) {
            scannedCount++;
            if (result.classification && result.classification !== 'legitimate') {
                threatCount++;
            }
        }

        document.getElementById('statScanned').textContent = scannedCount;
        document.getElementById('statThreats').textContent = threatCount;

        const statsEl = document.getElementById('pageStats');
        if (threatCount > 0) {
            statsEl.innerHTML = `<span class="threat-badge">⚠️ ${threatCount} potential threats detected</span>`;
        } else {
            statsEl.innerHTML = '<span class="safe-badge">✓ No threats detected</span>';
        }
    }

    /**
     * Perform quick scan on user-entered URL
     */
    function performQuickScan() {
        const urlInput = document.getElementById('urlInput');
        const scanButton = document.getElementById('scanButton');
        const resultBox = document.getElementById('scanResult');
        const url = urlInput.value.trim();

        if (!url) {
            showResult(resultBox, 'Please enter a URL', 'error');
            return;
        }

        // Validate URL
        try {
            new URL(url);
        } catch (e) {
            showResult(resultBox, 'Invalid URL format', 'error');
            return;
        }

        // Show loading state
        scanButton.disabled = true;
        scanButton.querySelector('.btn-text').style.display = 'none';
        scanButton.querySelector('.btn-loading').style.display = 'inline';
        resultBox.style.display = 'none';

        // Get auth token and perform scan
        chrome.storage.local.get(['authToken'], function(result) {
            const token = result.authToken || '';

            fetch(`${currentApiUrl}/api/v1/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ url: url, force_scan: true })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                displayScanResult(resultBox, data);
            })
            .catch(error => {
                console.error('Scan error:', error);
                showResult(resultBox, `Scan failed: ${error.message}`, 'error');
            })
            .finally(() => {
                scanButton.disabled = false;
                scanButton.querySelector('.btn-text').style.display = 'inline';
                scanButton.querySelector('.btn-loading').style.display = 'none';
            });
        });
    }

    /**
     * Display scan result
     */
    function displayScanResult(element, result) {
        const classification = result.classification || 'unknown';
        const confidence = Math.round((result.confidence || 0) * 100);
        const riskScore = result.risk_score || 0;

        let className = 'result-' + classification;
        let title = classification.replace(/_/g, ' ').toUpperCase();
        let icon = '⚠️';

        if (classification === 'legitimate') {
            icon = '✓';
        } else if (classification === 'phishing' || classification === 'phishing_kit') {
            icon = '🚨';
        } else if (classification === 'ai_generated_phishing') {
            icon = '🤖';
        }

        element.innerHTML = `
            <div class="result-header ${className}">
                <span class="result-icon">${icon}</span>
                <span class="result-title">${title}</span>
            </div>
            <div class="result-details">
                <div class="result-metric">
                    <span class="metric-label">Confidence:</span>
                    <span class="metric-value">${confidence}%</span>
                </div>
                <div class="result-metric">
                    <span class="metric-label">Risk Score:</span>
                    <span class="metric-value">${riskScore}/100</span>
                </div>
                <div class="result-action">
                    <strong>Action:</strong> ${result.recommended_action || 'monitor'}
                </div>
            </div>
        `;

        element.className = 'result-box ' + className;
        element.style.display = 'block';
    }

    /**
     * Show simple result message
     */
    function showResult(element, message, type) {
        element.textContent = message;
        element.className = 'result-box result-' + type;
        element.style.display = 'block';
    }

})();
