/**
 * Phishing Guard - Standalone Detection Engine
 * JavaScript-based phishing detection that works without external API
 * Features: URL analysis, typosquatting detection, heuristic scoring
 */

class PhishingDetector {
    constructor() {
        // Known legitimate domains (whitelist)
        this.whitelist = new Set([
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com',
            'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citi.com'
        ]);

        // Common brands for typosquatting detection
        this.brands = {
            'paypal': ['paypal.com'],
            'amazon': ['amazon.com'],
            'google': ['google.com'],
            'facebook': ['facebook.com'],
            'apple': ['apple.com'],
            'microsoft': ['microsoft.com'],
            'netflix': ['netflix.com'],
            'bank': ['bankofamerica.com', 'chase.com', 'wellsfargo.com'],
            'wellsfargo': ['wellsfargo.com'],
            'chase': ['chase.com'],
            'citi': ['citi.com'],
            'amex': ['americanexpress.com'],
            'visa': ['visa.com'],
            'mastercard': ['mastercard.com']
        };

        // Suspicious keywords in URLs
        this.suspiciousKeywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'authenticate', 'password', 'credential', 'banking',
            'security', 'verification', 'authenticate', 'limited', 'suspended'
        ];

        // Suspicious TLDs often used in phishing
        this.suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.date'];
    }

    /**
     * Main analysis function - returns complete result
     */
    analyze(url) {
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            
            // Check whitelist first
            if (this.isWhitelisted(domain)) {
                return this.createResult(url, 'legitimate', 1.0, 0, 'Domain is in trusted whitelist');
            }

            // Extract features
            const features = this.extractFeatures(url, urlObj);
            
            // Check for typosquatting
            const typosquatResult = this.checkTyposquatting(domain);
            
            // Calculate risk score
            const riskScore = this.calculateRiskScore(features, typosquatResult);
            
            // Determine classification
            let classification, confidence, explanation;
            
            if (typosquatResult.isTyposquatting) {
                classification = 'phishing';
                confidence = 0.95;
                explanation = `Brand impersonation detected: ${typosquatResult.brand}`;
            } else if (riskScore >= 70) {
                classification = 'phishing';
                confidence = 0.85;
                explanation = 'High-risk indicators: ' + features.issues.join(', ');
            } else if (riskScore >= 40) {
                classification = 'phishing';
                confidence = 0.70;
                explanation = 'Suspicious patterns detected: ' + features.issues.join(', ');
            } else if (riskScore >= 20) {
                classification = 'suspicious';
                confidence = 0.60;
                explanation = 'Some suspicious indicators: ' + features.issues.join(', ');
            } else {
                classification = 'legitimate';
                confidence = 0.80;
                explanation = 'No significant phishing indicators detected';
            }

            return this.createResult(url, classification, confidence, riskScore, explanation, features, typosquatResult);

        } catch (e) {
            return this.createResult(url, 'unknown', 0.0, 50, 'Invalid URL format');
        }
    }

    /**
     * Check if domain is whitelisted
     */
    isWhitelisted(domain) {
        for (const trusted of this.whitelist) {
            if (domain === trusted || domain.endsWith('.' + trusted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract features from URL
     */
    extractFeatures(url, urlObj) {
        const features = {
            urlLength: url.length,
            domainLength: urlObj.hostname.length,
            hasHttps: url.startsWith('https://'),
            numDots: (urlObj.hostname.match(/\./g) || []).length,
            numHyphens: (urlObj.hostname.match(/-/g) || []).length,
            numUnderscores: (urlObj.hostname.match(/_/g) || []).length,
            hasAtSymbol: url.includes('@'),
            hasIP: this.isIPAddress(urlObj.hostname),
            tld: urlObj.hostname.split('.').pop(),
            issues: []
        };

        // Check for suspicious patterns
        if (!features.hasHttps) {
            features.issues.push('no HTTPS');
        }
        if (features.urlLength > 75) {
            features.issues.push('long URL');
        }
        if (features.hasIP) {
            features.issues.push('IP address instead of domain');
        }
        if (features.hasAtSymbol) {
            features.issues.push('contains @ symbol');
        }
        if (features.numHyphens > 2) {
            features.issues.push('multiple hyphens');
        }

        // Check suspicious TLD
        const domain = urlObj.hostname.toLowerCase();
        for (const tld of this.suspiciousTLDs) {
            if (domain.endsWith(tld)) {
                features.issues.push(`suspicious TLD (${tld})`);
                break;
            }
        }

        // Check suspicious keywords
        for (const keyword of this.suspiciousKeywords) {
            if (domain.includes(keyword)) {
                features.issues.push(`suspicious keyword (${keyword})`);
                break;
            }
        }

        return features;
    }

    /**
     * Check if string is IP address
     */
    isIPAddress(str) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        return ipv4Regex.test(str);
    }

    /**
     * Check for typosquatting (brand impersonation)
     */
    checkTyposquatting(domain) {
        const result = {
            isTyposquatting: false,
            brand: null,
            similarity: 0,
            type: null
        };

        // Remove TLD for comparison
        const domainBase = domain.split('.')[0];

        for (const [brand, legitimateDomains] of Object.entries(this.brands)) {
            // Check exact match in domain
            if (domainBase.includes(brand)) {
                // Check if it's actually the legitimate domain
                let isLegitimate = false;
                for (const legit of legitimateDomains) {
                    if (domain === legit || domain.endsWith('.' + legit)) {
                        isLegitimate = true;
                        break;
                    }
                }
                
                if (!isLegitimate) {
                    result.isTyposquatting = true;
                    result.brand = brand;
                    result.type = 'subdomain_attack';
                    return result;
                }
            }

            // Check for character substitution attacks
            const similarity = this.calculateSimilarity(domainBase, brand);
            if (similarity > 0.7 && similarity < 1.0) {
                result.isTyposquatting = true;
                result.brand = brand;
                result.similarity = similarity;
                result.type = 'character_substitution';
                return result;
            }
        }

        return result;
    }

    /**
     * Calculate string similarity (Levenshtein-based)
     */
    calculateSimilarity(str1, str2) {
        const len1 = str1.length;
        const len2 = str2.length;
        const matrix = [];

        for (let i = 0; i <= len1; i++) {
            matrix[i] = [i];
        }
        for (let j = 0; j <= len2; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= len1; i++) {
            for (let j = 1; j <= len2; j++) {
                const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
                matrix[i][j] = Math.min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost
                );
            }
        }

        const distance = matrix[len1][len2];
        const maxLen = Math.max(len1, len2);
        return 1 - (distance / maxLen);
    }

    /**
     * Calculate overall risk score
     */
    calculateRiskScore(features, typosquatResult) {
        let score = 0;

        // Typosquatting is high risk
        if (typosquatResult.isTyposquatting) {
            score += 60;
        }

        // No HTTPS
        if (!features.hasHttps) {
            score += 15;
        }

        // Long URL
        if (features.urlLength > 75) {
            score += 10;
        }

        // IP address
        if (features.hasIP) {
            score += 25;
        }

        // @ symbol
        if (features.hasAtSymbol) {
            score += 20;
        }

        // Multiple issues
        score += features.issues.length * 5;

        return Math.min(100, score);
    }

    /**
     * Create result object
     */
    createResult(url, classification, confidence, riskScore, explanation, features = {}, typosquatResult = {}) {
        return {
            url: url,
            classification: classification,
            confidence: confidence,
            riskScore: riskScore,
            explanation: explanation,
            features: features,
            typosquatting: typosquatResult,
            timestamp: new Date().toISOString(),
            mode: 'standalone'
        };
    }

    /**
     * Quick check - returns just classification
     */
    quickCheck(url) {
        const result = this.analyze(url);
        return {
            safe: result.classification === 'legitimate',
            classification: result.classification,
            riskScore: result.riskScore
        };
    }
}

// Export for use in content scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishingDetector;
}
