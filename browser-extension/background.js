/**
 * Phishing Guard - Background Service Worker
 * Handles API communication, notifications, and state management
 */

const API_BASE = 'http://localhost:8000';

/**
 * Initialize extension on install
 */
chrome.runtime.onInstalled.addListener(function(details) {
    console.log('[Phishing Guard] Extension installed');
    
    // Set default settings
    chrome.storage.sync.set({
        enabled: true,
        autoScan: true,
        showNotifications: true,
        apiUrl: API_BASE
    });
    
    // Authenticate with API
    authenticateWithAPI();
});

/**
 * Authenticate with the API and store token
 */
async function authenticateWithAPI() {
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: 'browser-extension',
                password: 'extension-token-' + chrome.runtime.id
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            chrome.storage.local.set({authToken: data.access_token});
            console.log('[Phishing Guard] Authenticated with API');
        } else {
            console.error('[Phishing Guard] Authentication failed:', response.status);
        }
    } catch (error) {
        console.error('[Phishing Guard] Auth error:', error);
    }
}

/**
 * Listen for tab updates to scan new pages
 */
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Wait a moment for page to fully load
        setTimeout(() => {
            chrome.tabs.sendMessage(tabId, {action: 'scanPage'}, function(response) {
                if (chrome.runtime.lastError) {
                    // Content script not loaded yet, that's ok
                    console.log('[Phishing Guard] Content script not ready');
                }
            });
        }, 1000);
    }
});

/**
 * Handle messages from content scripts and popup
 */
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    switch(request.action) {
        case 'quickScan':
            // Quick scan from popup
            quickScanURL(request.url).then(sendResponse);
            return true; // Async response
            
        case 'getStats':
            // Get scanning statistics
            getScanStats().then(sendResponse);
            return true;
            
        case 'checkHealth':
            // Check API health
            checkAPIHealth().then(sendResponse);
            return true;
            
        case 'openSettings':
            chrome.runtime.openOptionsPage();
            break;
    }
});

/**
 * Quick scan a URL and return result
 */
async function quickScanURL(url) {
    try {
        const token = await getAuthToken();
        
        const response = await fetch(`${API_BASE}/api/v1/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({url: url, force_scan: false})
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        return await response.json();
        
    } catch (error) {
        console.error('[Phishing Guard] Quick scan error:', error);
        return {
            error: error.message,
            classification: 'error',
            url: url
        };
    }
}

/**
 * Get authentication token from storage
 */
async function getAuthToken() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['authToken'], function(result) {
            resolve(result.authToken || '');
        });
    });
}

/**
 * Get scanning statistics
 */
async function getScanStats() {
    // This would ideally track from storage
    return {
        totalScanned: 0,
        threatsBlocked: 0,
        lastScan: null
    };
}

/**
 * Check API health
 */
async function checkAPIHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`, {
            method: 'GET'
        });
        
        if (response.ok) {
            const data = await response.json();
            return {
                online: true,
                status: data.status,
                version: data.version
            };
        } else {
            return {
                online: false,
                error: `HTTP ${response.status}`
            };
        }
    } catch (error) {
        return {
            online: false,
            error: error.message
        };
    }
}

/**
 * Periodic health check
 */
setInterval(checkAPIHealth, 30000); // Check every 30 seconds

console.log('[Phishing Guard] Background service worker loaded');
