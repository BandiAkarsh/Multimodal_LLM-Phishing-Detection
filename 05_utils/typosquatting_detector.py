"""
Typosquatting Detection Module

Detects brand impersonation through:
1. Levenshtein distance (edit distance)
2. Character substitution patterns (0 for o, 1 for l, etc.)
3. Homoglyph detection (characters that look similar)
4. Brand keyword presence in suspicious contexts
"""

import re
from difflib import SequenceMatcher
import tldextract

# Major brands that are commonly impersonated
PROTECTED_BRANDS = {
    # Financial
    'paypal': ['paypal.com'],
    'chase': ['chase.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'wellsfargo': ['wellsfargo.com'],
    'citibank': ['citibank.com', 'citi.com'],
    'americanexpress': ['americanexpress.com', 'amex.com'],
    'visa': ['visa.com'],
    'mastercard': ['mastercard.com'],
    
    # Tech Giants
    'google': ['google.com', 'gmail.com', 'youtube.com'],
    'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'aws.amazon.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'meta': ['meta.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'netflix': ['netflix.com'],
    'spotify': ['spotify.com'],
    
    # E-commerce
    'ebay': ['ebay.com'],
    'alibaba': ['alibaba.com', 'aliexpress.com'],
    'walmart': ['walmart.com'],
    'target': ['target.com'],
    
    # Crypto
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com'],
    'metamask': ['metamask.io'],
    'blockchain': ['blockchain.com'],
    
    # Services
    'dropbox': ['dropbox.com'],
    'github': ['github.com'],
    'slack': ['slack.com'],
    'zoom': ['zoom.us'],
    'adobe': ['adobe.com'],
    
    # Shipping
    'fedex': ['fedex.com'],
    'ups': ['ups.com'],
    'usps': ['usps.com'],
    'dhl': ['dhl.com'],
}

# Common character substitutions used in typosquatting
HOMOGLYPHS = {
    'a': ['4', '@', 'α', 'а'],  # Cyrillic 'a'
    'b': ['8', 'ß', 'в'],
    'c': ['(', 'с'],  # Cyrillic 'c'
    'e': ['3', 'є', 'е'],  # Cyrillic 'e'
    'g': ['9', 'q'],
    'i': ['1', 'l', '!', '|', 'і'],
    'l': ['1', 'i', '|', 'ӏ'],
    'o': ['0', 'ο', 'о'],  # Greek and Cyrillic 'o'
    's': ['5', '$', 'ѕ'],
    't': ['7', '+'],
    'u': ['v', 'υ', 'ц'],
    'w': ['vv', 'ω'],
    'x': ['×', 'х'],  # Cyrillic 'x'
    'y': ['ү', 'у'],
    'z': ['2'],
}

class TyposquattingDetector:
    def __init__(self):
        self.brands = PROTECTED_BRANDS
        self.homoglyphs = HOMOGLYPHS
        
    def analyze(self, url: str) -> dict:
        """
        Analyze URL for typosquatting/brand impersonation.
        
        Returns:
            dict with detection results
        """
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()
        full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".lower()
        full_domain = full_domain.strip('.')
        
        results = {
            'is_typosquatting': False,
            'impersonated_brand': None,
            'similarity_score': 0.0,
            'detection_method': None,
            'risk_increase': 0,
            'details': []
        }
        
        # Check each brand
        for brand, legitimate_domains in self.brands.items():
            # Skip if this IS a legitimate domain
            if any(full_domain.endswith(legit) for legit in legitimate_domains):
                continue
                
            # Check 1: Exact brand name in domain (but not legitimate)
            if brand in domain:
                results['is_typosquatting'] = True
                results['impersonated_brand'] = brand
                results['detection_method'] = 'brand_in_domain'
                results['similarity_score'] = 0.9
                results['risk_increase'] = 50
                results['details'].append(f"Contains '{brand}' but is not a legitimate {brand} domain")
                break
            
            # Check 2: Levenshtein similarity
            similarity = SequenceMatcher(None, domain, brand).ratio()
            if similarity > 0.7 and similarity < 1.0:
                results['is_typosquatting'] = True
                results['impersonated_brand'] = brand
                results['detection_method'] = 'levenshtein_similarity'
                results['similarity_score'] = similarity
                results['risk_increase'] = int(similarity * 50)
                results['details'].append(f"Domain '{domain}' is {similarity*100:.1f}% similar to '{brand}'")
                break
            
            # Check 3: Homoglyph substitution
            normalized = self._normalize_homoglyphs(domain)
            if normalized == brand or brand in normalized:
                results['is_typosquatting'] = True
                results['impersonated_brand'] = brand
                results['detection_method'] = 'homoglyph_substitution'
                results['similarity_score'] = 0.95
                results['risk_increase'] = 60
                results['details'].append(f"Domain uses character substitution to mimic '{brand}'")
                break
        
        # Check 4: Brand in subdomain (subdomain attack)
        if extracted.subdomain:
            for brand in self.brands.keys():
                if brand in extracted.subdomain.lower():
                    results['is_typosquatting'] = True
                    results['impersonated_brand'] = brand
                    results['detection_method'] = 'subdomain_attack'
                    results['similarity_score'] = 0.85
                    results['risk_increase'] = 45
                    results['details'].append(f"Uses '{brand}' in subdomain to appear legitimate")
                    break
        
        return results
    
    def _normalize_homoglyphs(self, text: str) -> str:
        """Replace homoglyphs with their standard character."""
        result = text.lower()
        for char, substitutes in self.homoglyphs.items():
            for sub in substitutes:
                result = result.replace(sub, char)
        return result
    
    def get_brand_similarity(self, domain: str, brand: str) -> float:
        """Calculate similarity between domain and brand."""
        return SequenceMatcher(None, domain.lower(), brand.lower()).ratio()


# Quick test
if __name__ == "__main__":
    detector = TyposquattingDetector()
    
    test_urls = [
        "https://paypa1.com",  # Homoglyph
        "https://arnazon.com",  # Typo
        "https://faceb00k.com",  # Homoglyph
        "https://google.com.malicious.net",  # Subdomain attack
        "https://secure-paypal-login.xyz",  # Brand in domain
        "https://google.com",  # Legitimate
        "https://amazon.com",  # Legitimate
        "https://amaz0n-deals.com",  # Homoglyph + extra
        "https://micros0ft-support.com",  # Homoglyph
        "https://netflix-account-verify.com",  # Brand impersonation
    ]
    
    print("Typosquatting Detection Results:")
    print("=" * 80)
    for url in test_urls:
        result = detector.analyze(url)
        status = "⚠️  TYPOSQUATTING" if result['is_typosquatting'] else "✓  Clean"
        brand = result['impersonated_brand'] or "-"
        method = result['detection_method'] or "-"
        print(f"{status:20} | {url:45} | Brand: {brand:12} | Method: {method}")
