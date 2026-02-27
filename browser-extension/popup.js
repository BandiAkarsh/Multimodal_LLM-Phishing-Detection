/**
 * Phishing Guard - Popup Script (Standalone Mode)
 * Works without external API
 */

// Standalone detector for popup
const detector = {
    whitelist: new Set([
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
        'twitter.com', 'instagram.com', 'linkedin.com', 'github.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com'
    ]),
    
    brands: {
        'paypal': ['paypal.com'], 'amazon': ['amazon.com'], 'google': ['google.com'],
        'facebook': ['facebook.com'], 'apple': ['apple.com'], 'microsoft': ['microsoft.com'],
        'netflix': ['netflix.com'], 'chase': ['chase.com'], 'citi': ['citi.com']
    },
    
    analyze(url) {
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            
            // Check whitelist
            for (const trusted of this.whitelist) {
                if (domain === trusted || domain.endsWith('.' + trusted)) {
                    return { classification: 'legitimate', confidence: 1.0, riskScore: 0 };
                }
            }
            
            let riskScore = 0;
            const issues = [];
            
            // Check typosquatting
            const base = domain.split('.')[0];
            for (const [brand, legitDomains] of Object.entries(this.brands)) {
                if (base.includes(brand)) {
                    const isLegit = legitDomains.some(l => domain === l || domain.endsWith('.' + l));
                    if (!isLegit) {
                        riskScore += 60;
                        issues.push(`Brand impersonation: ${brand}`);
                    }
                }
            }
            
            // Check features
            if (!url.startsWith('https://')) { riskScore += 15; issues.push('No HTTPS'); }
            if (url.length > 75) { riskScore += 10; issues.push('Long URL'); }
            if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) { riskScore += 25; issues.push('IP address'); }
            if (url.includes('@')) { riskScore += 20; issues.push('Contains @ symbol'); }
            if (['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'].some(tld => domain.endsWith(tld))) {
                riskScore += 20; issues.push('Suspicious TLD');
            }
            
            riskScore = Math.min(100, riskScore);
            
            let classification, confidence;
            if (riskScore >= 70) {
                classification = 'phishing'; confidence = 0.85;
            } else if (riskScore >= 40) {
                classification = 'phishing'; confidence = 0.70;
            } else if (riskScore >= 20) {
                classification = 'suspicious'; confidence = 0.60;
            } else {
                classification = 'legitimate'; confidence = 0.85;
            }
            
            return { classification, confidence, riskScore, issues };
        } catch (e) {
            return { classification: 'unknown', confidence: 0, riskScore: 50, issues: ['Invalid URL'] };
        }
    }
};

// Initialize popup when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializePopup();
});

function initializePopup() {
    // Set mode indicator
    document.getElementById('statusIndicator').innerHTML = 
        '<span style="color: #22c55e;">●</span> <span>Standalone Mode</span>';
    
    // Load current tab info
    getCurrentTabInfo();
    
    // Setup event listeners
    document.getElementById('scanButton').addEventListener('click', performQuickScan);
    document.getElementById('urlInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') performQuickScan();
    });
    document.getElementById('toggleEnabled').addEventListener('change', toggleProtection);
    
    // Load statistics
    loadStatistics();
}

function getCurrentTabInfo() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs[0]) {
            document.getElementById('currentUrl').textContent = tabs[0].url;
            
            // Get scan results for current page
            chrome.tabs.sendMessage(tabs[0].id, {action: 'getResults'}, function(response) {
                if (response && response.results) {
                    const count = Object.keys(response.results).length;
                    const threats = Object.values(response.results).filter(r => 
                        r.classification === 'phishing' || r.classification === 'suspicious'
                    ).length;
                    
                    document.getElementById('pageStats').innerHTML = 
                        `<span>Links scanned: ${count}</span> | <span style="color: ${threats > 0 ? '#ef4444' : '#22c55e'}">Threats: ${threats}</span>`;
                } else {
                    document.getElementById('pageStats').innerHTML = '<span>Refresh page to scan</span>';
                }
            });
        }
    });
}

function performQuickScan() {
    const urlInput = document.getElementById('urlInput');
    const resultBox = document.getElementById('scanResult');
    const url = urlInput.value.trim();
    
    if (!url) {
        resultBox.innerHTML = '<p style="color: #ef4444;">Please enter a URL</p>';
        resultBox.style.display = 'block';
        return;
    }
    
    // Show loading
    document.getElementById('scanButton').textContent = 'Scanning...';
    
    // Scan using standalone detector
    setTimeout(() => {
        const result = detector.analyze(url);
        displayResult(resultBox, result);
        document.getElementById('scanButton').textContent = 'Scan';
    }, 500);
}

function displayResult(container, result) {
    const colors = {
        'legitimate': { bg: '#dcfce7', border: '#22c55e', text: '#166534' },
        'phishing': { bg: '#fee2e2', border: '#ef4444', text: '#991b1b' },
        'suspicious': { bg: '#ffedd5', border: '#f97316', text: '#9a3412' },
        'unknown': { bg: '#f3f4f6', border: '#6b7280', text: '#374151' }
    };
    
    const style = colors[result.classification] || colors.unknown;
    
    let html = `
        <div style="
            background: ${style.bg};
            border: 2px solid ${style.border};
            border-radius: 8px;
            padding: 12px;
            margin-top: 10px;
        ">
            <h3 style="color: ${style.text}; margin: 0 0 8px 0; text-transform: uppercase;">
                ${result.classification}
            </h3>
            <p style="margin: 4px 0;"><strong>Risk Score:</strong> ${result.riskScore}%</p>
            <p style="margin: 4px 0;"><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(0)}%</p>
    `;
    
    if (result.issues && result.issues.length > 0) {
        html += `<p style="margin: 8px 0 0 0; font-size: 12px;"><strong>Indicators:</strong> ${result.issues.join(', ')}</p>`;
    }
    
    html += '</div>';
    
    container.innerHTML = html;
    container.style.display = 'block';
}

function toggleProtection(e) {
    const enabled = e.target.checked;
    
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs[0]) {
            chrome.tabs.sendMessage(tabs[0].id, {
                action: 'toggle',
                enabled: enabled
            });
        }
    });
    
    // Show feedback
    const status = document.getElementById('statusIndicator');
    status.innerHTML = enabled ? 
        '<span style="color: #22c55e;">●</span> <span>Protection Enabled</span>' :
        '<span style="color: #ef4444;">●</span> <span>Protection Disabled</span>';
}

function loadStatistics() {
    chrome.runtime.sendMessage({action: 'getStats'}, function(response) {
        if (response) {
            const statsDiv = document.getElementById('statsSection') || createStatsSection();
            statsDiv.innerHTML = `
                <div style="margin-top: 15px; padding: 10px; background: #f9fafb; border-radius: 6px;">
                    <h4 style="margin: 0 0 8px 0; color: #374151;">Statistics</h4>
                    <p style="margin: 4px 0; font-size: 13px;">Total Threats Detected: <strong>${response.totalThreats}</strong></p>
                    <p style="margin: 4px 0; font-size: 13px;">Last 24 Hours: <strong>${response.recentThreats}</strong></p>
                    <p style="margin: 4px 0; font-size: 11px; color: #6b7280;">Mode: Standalone</p>
                </div>
            `;
        }
    });
}

function createStatsSection() {
    const section = document.createElement('div');
    section.id = 'statsSection';
    document.querySelector('.container').appendChild(section);
    return section;
}
