/**
 * Phishing Guard - Background Service Worker (Standalone Mode)
 * Works without external API - uses JavaScript-based detection
 */

// Configuration
const CONFIG = {
    useLocalAPI: false,  // Set to true if you want to use local API as well
    apiBase: 'http://localhost:8000',
    showNotifications: true
};

/**
 * Initialize extension on install
 */
chrome.runtime.onInstalled.addListener(function(details) {
    console.log('[Phishing Guard] Extension installed - Standalone Mode');
    
    // Set default settings
    chrome.storage.sync.set({
        enabled: true,
        autoScan: true,
        showNotifications: true,
        mode: 'standalone',  // Indicates standalone operation
        useLocalAPI: false
    });
    
    // Show welcome notification
    showNotification(
        'Phishing Guard Active',
        'Extension is running in standalone mode. All links will be scanned automatically.'
    );
});

/**
 * Listen for tab updates to scan new pages
 */
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Wait for page to load, then trigger scan
        setTimeout(() => {
            chrome.tabs.sendMessage(tabId, {action: 'scanPage'}, function(response) {
                if (chrome.runtime.lastError) {
                    // Content script might not be injected yet
                    console.log('[Phishing Guard] Content script not ready on', tab.url);
                } else {
                    console.log('[Phishing Guard] Scanned page:', tab.url, response);
                }
            });
        }, 1500);
    }
});

/**
 * Handle messages from content scripts and popup
 */
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'threatDetected') {
        // Handle high-risk threat detection
        console.log('[Phishing Guard] High-risk threat detected:', request.url);
        
        if (CONFIG.showNotifications) {
            showNotification(
                '🚨 Phishing Threat Detected!',
                `Risk Score: ${request.risk}% - ${request.url}`,
                'high'
            );
        }
        
        // Store threat for statistics
        storeThreat(request.url, request.risk);
        
        sendResponse({status: 'notified'});
        
    } else if (request.action === 'getStats') {
        // Return scanning statistics
        getStatistics().then(stats => {
            sendResponse(stats);
        });
        return true; // Async response
        
    } else if (request.action === 'clearStats') {
        chrome.storage.local.remove(['threats', 'scanCount']);
        sendResponse({status: 'cleared'});
    }
    
    return true;
});

/**
 * Show browser notification
 */
function showNotification(title, message, priority = 'normal') {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'images/icon128.png',
        title: title,
        message: message,
        priority: priority === 'high' ? 2 : 1,
        requireInteraction: priority === 'high'
    });
}

/**
 * Store detected threat for statistics
 */
function storeThreat(url, risk) {
    chrome.storage.local.get(['threats', 'scanCount'], function(result) {
        const threats = result.threats || [];
        threats.push({
            url: url,
            risk: risk,
            timestamp: Date.now()
        });
        
        // Keep only last 100 threats
        if (threats.length > 100) {
            threats.shift();
        }
        
        chrome.storage.local.set({
            threats: threats,
            scanCount: (result.scanCount || 0) + 1
        });
    });
}

/**
 * Get scanning statistics
 */
async function getStatistics() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['threats', 'scanCount'], function(result) {
            const threats = result.threats || [];
            const now = Date.now();
            const dayAgo = now - (24 * 60 * 60 * 1000);
            
            resolve({
                totalThreats: threats.length,
                recentThreats: threats.filter(t => t.timestamp > dayAgo).length,
                totalScans: result.scanCount || 0,
                mode: 'standalone',
                lastThreat: threats.length > 0 ? threats[threats.length - 1] : null
            });
        });
    });
}

/**
 * Handle extension icon click
 */
chrome.action.onClicked.addListener(function(tab) {
    // Open popup is handled automatically by manifest
    console.log('[Phishing Guard] Extension icon clicked');
});

console.log('[Phishing Guard] Background service worker loaded - Standalone Mode');
