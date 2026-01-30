/**
 * Phishing Guard - Browser Extension
 * 
 * This extension provides real-time phishing detection in the browser.
 * It scans links on web pages and highlights potential threats.
 * 
 * Features:
 * - Automatic link scanning on page load
 * - Visual highlighting of suspicious links
 * - Real-time notifications for threats
 * - Quick scan via popup
 * - Statistics tracking
 * 
 * Author: Phishing Guard Team
 * Version: 2.0.0
 * License: MIT
 */

// Configuration
const CONFIG = {
    API_BASE: 'http://localhost:8000',
    SCAN_DELAY: 1000,
    MAX_LINKS_PER_PAGE: 100,
    TRUSTED_DOMAINS: [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
        'github.com', 'stackoverflow.com', 'wikipedia.org',
        'amazon.com', 'microsoft.com', 'apple.com', 'linkedin.com'
    ]
};

// State management
const state = {
    isEnabled: true,
    isScanning: false,
    scannedLinks: new Map(),
    threatsFound: 0,
    settings: {
        autoScan: true,
        highlightThreats: true,
        showNotifications: true
    }
};

/**
 * Initialize extension
 */
function init() {
    console.log('[Phishing Guard] Initializing...');
    
    // Load settings
    loadSettings();
    
    // Check if we should scan this page
    if (shouldScanPage()) {
        scanCurrentPage();
    }
    
    // Setup event listeners
    setupEventListeners();
    
    console.log('[Phishing Guard] Initialized successfully');
}

/**
 * Load extension settings from storage
 */
function loadSettings() {
    chrome.storage.sync.get(['settings'], function(result) {
        if (result.settings) {
            state.settings = { ...state.settings, ...result.settings };
        }
    });
}

/**
 * Check if current page should be scanned
 */
function shouldScanPage() {
    const url = window.location.href;
    
    // Don't scan internal browser pages
    if (url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('file://')) {
        return false;
    }
    
    // Check if extension is enabled
    return state.isEnabled;
}

/**
 * Scan current page for links
 */
function scanCurrentPage() {
    if (state.isScanning) return;
    
    state.isScanning = true;
    console.log('[Phishing Guard] Scanning page...');
    
    // Get all links
    const links = document.querySelectorAll('a[href^="http"]');
    console.log(`[Phishing Guard] Found ${links.length} links`);
    
    // Filter and scan links
    const linksToScan = Array.from(links)
        .slice(0, CONFIG.MAX_LINKS_PER_PAGE)
        .filter(link => !isTrustedDomain(link.href));
    
    console.log(`[Phishing Guard] Scanning ${linksToScan.length} links`);
    
    // Scan each link
    linksToScan.forEach((link, index) => {
        setTimeout(() => {
            scanLink(link);
        }, index * 100); // Stagger requests
    });
    
    state.isScanning = false;
}

/**
 * Check if domain is trusted
 */
function isTrustedDomain(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        return CONFIG.TRUSTED_DOMAINS.some(domain => hostname.includes(domain));
    } catch {
        return false;
    }
}

/**
 * Scan a single link
 */
async function scanLink(linkElement) {
    const url = linkElement.href;
    
    // Skip if already scanned
    if (state.scannedLinks.has(url)) {
        applyHighlight(linkElement, state.scannedLinks.get(url));
        return;
    }
    
    try {
        // Get auth token
        const token = await getAuthToken();
        
        // Call API
        const response = await fetch(`${CONFIG.API_BASE}/api/v1/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const result = await response.json();
        
        // Store result
        state.scannedLinks.set(url, result);
        
        // Apply visual feedback
        applyHighlight(linkElement, result);
        
        // Track threats
        if (result.classification !== 'legitimate') {
            state.threatsFound++;
            
            // Show notification
            if (state.settings.showNotifications && result.risk_score > 70) {
                showNotification(url, result);
            }
        }
        
    } catch (error) {
        console.error('[Phishing Guard] Scan error:', error);
    }
}

/**
 * Apply visual highlight to link
 */
function applyHighlight(linkElement, result) {
    if (!state.settings.highlightThreats) return;
    
    const classification = result.classification || 'legitimate';
    
    // Define styles
    const styles = {
        legitimate: {
            borderBottom: '2px solid #22c55e',
            backgroundColor: 'transparent'
        },
        phishing: {
            border: '2px solid #ef4444',
            backgroundColor: '#fef2f2'
        },
        ai_generated_phishing: {
            border: '2px dashed #f97316',
            backgroundColor: '#fff7ed'
        },
        phishing_kit: {
            border: '2px solid #991b1b',
            backgroundColor: '#fef2f2'
        }
    };
    
    // Apply style
    const style = styles[classification] || styles.legitimate;
    Object.assign(linkElement.style, style);
    
    // Add tooltip
    if (result.risk_score !== undefined) {
        linkElement.title = `Phishing Guard: ${classification.replace(/_/g, ' ')} (Risk: ${result.risk_score}/100)`;
    }
}

/**
 * Show browser notification
 */
function showNotification(url, result) {
    const title = `🚨 ${result.classification.replace(/_/g, ' ').toUpperCase()}!`;
    const message = `Risk: ${result.risk_score}/100 | ${url.substring(0, 50)}...`;
    
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'images/icon128.png',
        title,
        message,
        priority: 2
    });
}

/**
 * Get auth token from storage
 */
async function getAuthToken() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['authToken'], (result) => {
            resolve(result.authToken || '');
        });
    });
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Listen for messages from popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        switch(request.action) {
            case 'getStatus':
                sendResponse({
                    isEnabled: state.isEnabled,
                    linksScanned: state.scannedLinks.size,
                    threatsFound: state.threatsFound
                });
                break;
                
            case 'toggle':
                state.isEnabled = request.enabled;
                sendResponse({ isEnabled: state.isEnabled });
                break;
                
            case 'rescan':
                state.scannedLinks.clear();
                scanCurrentPage();
                sendResponse({ status: 'scanning' });
                break;
        }
        return true;
    });
    
    // Observe DOM changes
    observeDOMChanges();
}

/**
 * Observe DOM changes for dynamic content
 */
function observeDOMChanges() {
    const observer = new MutationObserver((mutations) => {
        let hasNewLinks = false;
        
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    if (node.querySelector && node.querySelector('a[href^="http"]')) {
                        hasNewLinks = true;
                    }
                }
            });
        });
        
        if (hasNewLinks) {
            setTimeout(scanCurrentPage, 500);
        }
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

// Initialize
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

console.log('[Phishing Guard] Content script loaded');
