/**
 * Phishing Guard - Content Script (Standalone Mode)
 * Scans all links on web pages using JavaScript-only detection (no API required)
 */

// Import the standalone detector
// Note: In Manifest V3, we need to load this differently
let detector = null;

// Initialize detector
function initDetector() {
    // Create detector instance inline for standalone operation
    detector = {
        whitelist: new Set([
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com'
        ]),
        
        brands: {
            'paypal': ['paypal.com'],
            'amazon': ['amazon.com'],
            'google': ['google.com'],
            'facebook': ['facebook.com'],
            'apple': ['apple.com'],
            'microsoft': ['microsoft.com'],
            'netflix': ['netflix.com'],
            'chase': ['chase.com'],
            'citi': ['citi.com']
        },
        
        suspiciousKeywords: ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'password'],
        suspiciousTLDs: ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'],
        
        analyze(url) {
            try {
                const urlObj = new URL(url);
                const domain = urlObj.hostname.toLowerCase();
                
                // Check whitelist
                if (this.isWhitelisted(domain)) {
                    return { classification: 'legitimate', confidence: 1.0, riskScore: 0 };
                }
                
                // Extract features
                const features = this.extractFeatures(url, urlObj);
                const typosquat = this.checkTyposquatting(domain);
                const riskScore = this.calculateRisk(features, typosquat);
                
                // Classification
                if (typosquat.isTyposquatting) {
                    return { classification: 'phishing', confidence: 0.95, riskScore: 85 };
                } else if (riskScore >= 70) {
                    return { classification: 'phishing', confidence: 0.85, riskScore };
                } else if (riskScore >= 40) {
                    return { classification: 'phishing', confidence: 0.70, riskScore };
                } else if (riskScore >= 20) {
                    return { classification: 'suspicious', confidence: 0.60, riskScore };
                } else {
                    return { classification: 'legitimate', confidence: 0.85, riskScore };
                }
            } catch (e) {
                return { classification: 'unknown', confidence: 0, riskScore: 50 };
            }
        },
        
        isWhitelisted(domain) {
            for (const trusted of this.whitelist) {
                if (domain === trusted || domain.endsWith('.' + trusted)) return true;
            }
            return false;
        },
        
        extractFeatures(url, urlObj) {
            return {
                hasHttps: url.startsWith('https://'),
                urlLength: url.length,
                hasIP: /^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname),
                hasAt: url.includes('@'),
                numHyphens: (urlObj.hostname.match(/-/g) || []).length,
                suspiciousTLD: this.suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld)),
                suspiciousKeyword: this.suspiciousKeywords.some(kw => urlObj.hostname.includes(kw))
            };
        },
        
        checkTyposquatting(domain) {
            const base = domain.split('.')[0];
            for (const [brand, legitDomains] of Object.entries(this.brands)) {
                if (base.includes(brand)) {
                    const isLegit = legitDomains.some(l => domain === l || domain.endsWith('.' + l));
                    if (!isLegit) return { isTyposquatting: true, brand };
                }
            }
            return { isTyposquatting: false };
        },
        
        calculateRisk(features, typosquat) {
            let score = 0;
            if (typosquat.isTyposquatting) score += 60;
            if (!features.hasHttps) score += 15;
            if (features.urlLength > 75) score += 10;
            if (features.hasIP) score += 25;
            if (features.hasAt) score += 20;
            if (features.suspiciousTLD) score += 20;
            if (features.suspiciousKeyword) score += 10;
            score += features.numHyphens * 5;
            return Math.min(100, score);
        }
    };
}

(function() {
    'use strict';
    
    // Initialize
    initDetector();
    
    // State
    let isEnabled = true;
    let scannedLinks = new Map();
    let isScanning = false;
    
    // Colors for threat levels
    const COLORS = {
        'legitimate': { border: '2px solid #22c55e', background: 'rgba(34, 197, 94, 0.1)' },
        'phishing': { border: '3px solid #ef4444', background: 'rgba(239, 68, 68, 0.15)' },
        'suspicious': { border: '2px dashed #f97316', background: 'rgba(249, 115, 22, 0.1)' },
        'unknown': { border: '1px dotted #6b7280', background: 'transparent' },
        'scanning': { border: '2px dotted #3b82f6', background: 'rgba(59, 130, 246, 0.05)' }
    };
    
    /**
     * Initialize content script
     */
    function init() {
        console.log('[Phishing Guard] Standalone content script loaded');
        
        // Check if enabled
        chrome.storage.sync.get(['enabled'], function(result) {
            isEnabled = result.enabled !== false;
            if (isEnabled) {
                scanAllLinks();
                observeDOMChanges();
            }
        });
        
        // Listen for messages
        chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
            if (request.action === 'scanPage') {
                scanAllLinks();
                sendResponse({status: 'scanning', count: scannedLinks.size});
            } else if (request.action === 'getResults') {
                const results = {};
                scannedLinks.forEach((value, key) => { results[key] = value; });
                sendResponse({results, count: scannedLinks.size});
            } else if (request.action === 'toggle') {
                isEnabled = request.enabled;
                isEnabled ? scanAllLinks() : clearAllHighlights();
                sendResponse({status: 'toggled', enabled: isEnabled});
            }
            return true;
        });
    }
    
    /**
     * Scan all links on the page
     */
    function scanAllLinks() {
        if (!isEnabled || isScanning) return;
        
        const links = document.querySelectorAll('a[href^="http"]');
        console.log(`[Phishing Guard] Scanning ${links.length} links...`);
        
        let scanned = 0;
        links.forEach((link, index) => {
            // Stagger scans to avoid blocking UI
            setTimeout(() => {
                scanLink(link);
                scanned++;
                if (scanned === links.length) {
                    console.log(`[Phishing Guard] Scan complete: ${scannedLinks.size} unique links`);
                }
            }, index * 10);
        });
    }
    
    /**
     * Scan a single link
     */
    function scanLink(link) {
        const url = link.href;
        
        // Skip if already scanned
        if (scannedLinks.has(url)) {
            applyHighlight(link, scannedLinks.get(url));
            return;
        }
        
        // Show scanning state
        applyHighlight(link, { classification: 'scanning' });
        
        // Analyze using standalone detector
        const result = detector.analyze(url);
        scannedLinks.set(url, result);
        
        // Apply highlight
        applyHighlight(link, result);
        
        // Notify background of high-risk links
        if (result.classification === 'phishing' && result.riskScore >= 70) {
            chrome.runtime.sendMessage({
                action: 'threatDetected',
                url: url,
                risk: result.riskScore
            });
        }
    }
    
    /**
     * Apply visual highlight to link
     */
    function applyHighlight(link, result) {
        const style = COLORS[result.classification] || COLORS.unknown;
        
        link.style.border = style.border;
        link.style.backgroundColor = style.background;
        link.style.padding = '1px 3px';
        link.style.borderRadius = '3px';
        link.style.transition = 'all 0.3s ease';
        
        // Add tooltip
        const tooltip = `Phishing Guard: ${result.classification.toUpperCase()} (Risk: ${result.riskScore}%)`;
        link.setAttribute('title', tooltip);
        
        // Add data attribute for styling
        link.setAttribute('data-phishing-status', result.classification);
    }
    
    /**
     * Clear all highlights
     */
    function clearAllHighlights() {
        document.querySelectorAll('a[data-phishing-status]').forEach(link => {
            link.style.border = '';
            link.style.backgroundColor = '';
            link.style.padding = '';
            link.style.borderRadius = '';
            link.removeAttribute('data-phishing-status');
        });
    }
    
    /**
     * Watch for new links added to DOM
     */
    function observeDOMChanges() {
        const observer = new MutationObserver(function(mutations) {
            let shouldScan = false;
            mutations.forEach(function(mutation) {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1) { // Element node
                        if (node.tagName === 'A' && node.href?.startsWith('http')) {
                            scanLink(node);
                        } else if (node.querySelectorAll) {
                            const links = node.querySelectorAll('a[href^="http"]');
                            links.forEach(scanLink);
                        }
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
