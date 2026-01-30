/**
 * Phishing Guard - Content Script
 * Scans all links on web pages and highlights potential phishing attempts
 */

(function() {
    'use strict';

    // Configuration
    const API_BASE = 'http://localhost:8000';
    const SCAN_ON_HOVER = true;
    const HIGHLIGHT_SUSPICIOUS = true;
    
    // State
    let isEnabled = true;
    let scannedLinks = new Map();
    let isScanning = false;

    // Colors for different threat levels
    const THREAT_COLORS = {
        'legitimate': '#22c55e',      // Green
        'phishing': '#ef4444',        // Red
        'ai_generated_phishing': '#f97316', // Orange
        'phishing_kit': '#991b1b',    // Dark red
        'scanning': '#3b82f6',        // Blue
        'error': '#6b7280'            // Gray
    };

    /**
     * Initialize the content script
     */
    function init() {
        console.log('[Phishing Guard] Content script loaded');
        
        // Check if extension is enabled
        chrome.storage.sync.get(['enabled'], function(result) {
            isEnabled = result.enabled !== false; // Default to true
            if (isEnabled) {
                scanLinks();
                observeDOMChanges();
            }
        });

        // Listen for messages from popup/background
        chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
            if (request.action === 'scanPage') {
                scanLinks();
                sendResponse({status: 'scanning'});
            } else if (request.action === 'getResults') {
                sendResponse({results: Object.fromEntries(scannedLinks)});
            } else if (request.action === 'toggle') {
                isEnabled = request.enabled;
                if (isEnabled) {
                    scanLinks();
                } else {
                    clearHighlights();
                }
                sendResponse({status: 'toggled', enabled: isEnabled});
            }
            return true;
        });
    }

    /**
     * Scan all links on the page
     */
    function scanLinks() {
        if (!isEnabled || isScanning) return;
        
        const links = document.querySelectorAll('a[href^="http"]');
        console.log(`[Phishing Guard] Found ${links.length} links to scan`);
        
        links.forEach(link => {
            const url = link.href;
            
            // Skip if already scanned
            if (scannedLinks.has(url)) {
                applyHighlight(link, scannedLinks.get(url));
                return;
            }
            
            // Skip common safe domains
            if (isTrustedDomain(url)) {
                return;
            }
            
            // Scan the link
            scanLink(url, link);
        });
    }

    /**
     * Check if URL is from a trusted domain
     */
    function isTrustedDomain(url) {
        const trustedDomains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org',
            'amazon.com', 'microsoft.com', 'apple.com', 'linkedin.com'
        ];
        
        try {
            const domain = new URL(url).hostname.toLowerCase();
            return trustedDomains.some(trusted => domain.includes(trusted));
        } catch {
            return false;
        }
    }

    /**
     * Scan a single link via API
     */
    async function scanLink(url, linkElement) {
        if (scannedLinks.has(url)) return;
        
        // Mark as scanning
        scannedLinks.set(url, {status: 'scanning', timestamp: Date.now()});
        applyHighlight(linkElement, {classification: 'scanning'});
        
        try {
            // Get auth token from storage
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
            
            const result = await response.json();
            
            // Store result
            scannedLinks.set(url, {
                classification: result.classification,
                confidence: result.confidence,
                risk_score: result.risk_score,
                timestamp: Date.now()
            });
            
            // Apply visual feedback
            applyHighlight(linkElement, result);
            
            // Show notification for threats
            if (result.classification !== 'legitimate' && result.risk_score > 70) {
                showNotification(url, result);
            }
            
        } catch (error) {
            console.error('[Phishing Guard] Scan error:', error);
            scannedLinks.set(url, {status: 'error', error: error.message});
            applyHighlight(linkElement, {classification: 'error'});
        }
    }

    /**
     * Get auth token from storage
     */
    async function getAuthToken() {
        return new Promise((resolve) => {
            chrome.storage.local.get(['authToken'], function(result) {
                resolve(result.authToken || '');
            });
        });
    }

    /**
     * Apply visual highlight to link
     */
    function applyHighlight(linkElement, result) {
        if (!HIGHLIGHT_SUSPICIOUS) return;
        
        const classification = result.classification || 'legitimate';
        const color = THREAT_COLORS[classification] || THREAT_COLORS.legitimate;
        
        // Remove existing highlights
        linkElement.classList.remove('phishing-guard-safe', 'phishing-guard-warning', 
                                     'phishing-guard-danger', 'phishing-guard-scanning');
        
        // Apply new highlight based on classification
        switch(classification) {
            case 'legitimate':
                linkElement.classList.add('phishing-guard-safe');
                linkElement.style.borderBottom = `2px solid ${color}`;
                break;
            case 'phishing':
            case 'phishing_kit':
                linkElement.classList.add('phishing-guard-danger');
                linkElement.style.border = `2px solid ${color}`;
                linkElement.style.backgroundColor = '#fef2f2';
                break;
            case 'ai_generated_phishing':
                linkElement.classList.add('phishing-guard-warning');
                linkElement.style.border = `2px dashed ${color}`;
                linkElement.style.backgroundColor = '#fff7ed';
                break;
            case 'scanning':
                linkElement.classList.add('phishing-guard-scanning');
                linkElement.style.borderBottom = `2px dotted ${color}`;
                break;
            default:
                // No highlight for unknown/error
        }
        
        // Add tooltip with info
        if (result.risk_score !== undefined) {
            linkElement.title = `Phishing Guard: ${classification.replace(/_/g, ' ').toUpperCase()} (Risk: ${result.risk_score}/100)`;
        }
    }

    /**
     * Clear all highlights
     */
    function clearHighlights() {
        const links = document.querySelectorAll('a[href^="http"]');
        links.forEach(link => {
            link.classList.remove('phishing-guard-safe', 'phishing-guard-warning', 
                                 'phishing-guard-danger', 'phishing-guard-scanning');
            link.style.border = '';
            link.style.backgroundColor = '';
        });
    }

    /**
     * Show browser notification for threats
     */
    function showNotification(url, result) {
        const title = `🚨 ${result.classification.replace(/_/g, ' ').toUpperCase()} Detected!`;
        const message = `Risk Score: ${result.risk_score}/100\\nURL: ${url.substring(0, 50)}...`;
        
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'images/icon128.png',
            title: title,
            message: message,
            priority: 2
        });
    }

    /**
     * Observe DOM changes for dynamic content
     */
    function observeDOMChanges() {
        const observer = new MutationObserver((mutations) => {
            let shouldScan = false;
            
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check if added node contains links
                            if (node.querySelector && node.querySelector('a[href^="http"]')) {
                                shouldScan = true;
                            }
                            // Check if added node is a link
                            if (node.tagName === 'A' && node.href && node.href.startsWith('http')) {
                                shouldScan = true;
                            }
                        }
                    });
                }
            });
            
            if (shouldScan) {
                // Debounce scanning
                clearTimeout(window.phishingGuardScanTimeout);
                window.phishingGuardScanTimeout = setTimeout(scanLinks, 500);
            }
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
