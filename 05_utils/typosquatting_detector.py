"""
Typosquatting Detection Module

Detects brand impersonation through:
1. Levenshtein distance (edit distance)
2. Character substitution patterns (0 for o, 1 for l, etc.)
3. Homoglyph detection (characters that look similar)
4. Brand keyword presence in suspicious contexts
5. TLD typosquatting (.pom instead of .com, etc.)
"""

import re
from difflib import SequenceMatcher
import tldextract

# Major brands that are commonly impersonated
PROTECTED_BRANDS = {
    # Financial - Global
    'paypal': ['paypal.com'],
    'chase': ['chase.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'wellsfargo': ['wellsfargo.com'],
    'citibank': ['citibank.com', 'citi.com'],
    'americanexpress': ['americanexpress.com', 'amex.com'],
    'visa': ['visa.com'],
    'mastercard': ['mastercard.com'],
    
    # Financial - India
    'hdfc': ['hdfcbank.com', 'hdfc.com'],
    'icici': ['icicibank.com', 'icici.com'],
    'sbi': ['sbi.co.in', 'onlinesbi.com'],
    'axis': ['axisbank.com'],
    'kotak': ['kotak.com', 'kotakbank.com'],
    'paytm': ['paytm.com'],
    'phonepe': ['phonepe.com'],
    'gpay': ['pay.google.com'],
    'razorpay': ['razorpay.com'],
    
    # Tech Giants
    'google': ['google.com', 'gmail.com', 'youtube.com'],
    'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'amazon.in', 'aws.amazon.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'meta': ['meta.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'netflix': ['netflix.com'],
    'spotify': ['spotify.com'],
    
    # E-commerce - Global
    'ebay': ['ebay.com'],
    'alibaba': ['alibaba.com', 'aliexpress.com'],
    'walmart': ['walmart.com'],
    'target': ['target.com'],
    
    # E-commerce - India
    'flipkart': ['flipkart.com'],
    'myntra': ['myntra.com'],
    'ajio': ['ajio.com'],
    'nykaa': ['nykaa.com'],
    'blinkit': ['blinkit.com'],
    'zepto': ['zepto.com'],
    'swiggy': ['swiggy.com'],
    'zomato': ['zomato.com'],
    'bigbasket': ['bigbasket.com'],
    'jiomart': ['jiomart.com'],
    'meesho': ['meesho.com'],
    'snapdeal': ['snapdeal.com'],
    
    # Crypto
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com'],
    'metamask': ['metamask.io'],
    'blockchain': ['blockchain.com'],
    'wazirx': ['wazirx.com'],
    'coinswitch': ['coinswitch.co'],
    
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
    'bluedart': ['bluedart.com'],
    'delhivery': ['delhivery.com'],
    
    # Travel - India
    'irctc': ['irctc.co.in'],
    'makemytrip': ['makemytrip.com'],
    'goibibo': ['goibibo.com'],
    'ola': ['olacabs.com'],
    'uber': ['uber.com'],
    'redbus': ['redbus.in'],
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

# Legitimate TLDs
VALID_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
    'co', 'io', 'ai', 'app', 'dev', 'tech', 'online',
    'to', 'me', 'ly', 'sh', 'gg', 'so', 'xyz', 'cloud', 'site', 'top', 'club', 'vip',
    'in', 'uk', 'us', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br',
    'info', 'biz', 'name', 'pro', 'mobi', 'tv', 'me', 'cc',
    'co.in', 'co.uk', 'com.au', 'com.br', 'co.jp', 'net.in', 'org.in',
}

# Common TLD typos (suspicious TLDs that look like real ones)
TLD_TYPOS = {
    # Typos of .com
    'corn': 'com', 'cmo': 'com', 'con': 'com', 'vom': 'com', 'xom': 'com',
    'om': 'com', 'cm': 'com', 'comn': 'com', 'comm': 'com', 'coml': 'com',
    'pom': 'com', 'dom': 'com', 'oom': 'com', 'clm': 'com', 'cim': 'com',
    'cpm': 'com', 'c0m': 'com', 'conm': 'com',
    
    # Typos of .org
    'ogr': 'org', 'rog': 'org', 'prg': 'org', 'orgg': 'org', '0rg': 'org',
    'orc': 'org', 'orf': 'org', 'org1': 'org',
    
    # Typos of .net
    'ner': 'net', 'met': 'net', 'nett': 'net', 'bet': 'net', 'n3t': 'net',
    'nrt': 'net', 'het': 'net',
    
    # Typos of .edu
    'eud': 'edu', 'edu1': 'edu', 'eduu': 'edu', '3du': 'edu',
    
    # Typos of .gov
    'gof': 'gov', 'goov': 'gov', 'g0v': 'gov',
    
    # Typos of .in (India)
    'ln': 'in', '1n': 'in', 'im': 'in', 'inn': 'in',
    
    # Typos of .io
    'lo': 'io', '1o': 'io', 'i0': 'io',
}

class TyposquattingDetector:
    def __init__(self):
        self.brands = PROTECTED_BRANDS
        self.homoglyphs = HOMOGLYPHS
        self.tld_typos = TLD_TYPOS
        self.valid_tlds = VALID_TLDS
        
    def analyze(self, url: str) -> dict:
        """
        Analyze URL for typosquatting/brand impersonation.
        
        Returns:
            dict with detection results
        """
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()
        suffix = extracted.suffix.lower()
        subdomain = extracted.subdomain.lower()
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
        
        # SPECIAL CASE: When TLD is invalid, tldextract puts real domain in subdomain
        # e.g., "blinkit.pom" -> subdomain="blinkit", domain="pom", suffix=""
        if not suffix and domain in self.tld_typos:
            # The "domain" is actually a typo TLD, real domain is in subdomain
            real_domain = subdomain
            fake_tld = domain
            intended_tld = self.tld_typos[fake_tld]
            
            results['is_typosquatting'] = True
            results['impersonated_brand'] = None  # It's a TLD error, not necessarily brand impersonation
            results['detection_method'] = 'faulty_extension'
            results['similarity_score'] = 0.9
            results['risk_increase'] = 55
            results['details'].append(f"Faulty or incorrect extension: '.{fake_tld}' (Did you mean '.{intended_tld}'?)")
            return results
        
        # Check 0: TLD Typosquatting with valid suffix format
        if suffix in self.tld_typos:
            results['is_typosquatting'] = True
            results['impersonated_brand'] = None
            results['detection_method'] = 'faulty_extension'
            results['similarity_score'] = 0.9
            results['risk_increase'] = 55
            intended_tld = self.tld_typos[suffix]
            results['details'].append(f"Faulty or incorrect extension: '.{suffix}' (Did you mean '.{intended_tld}'?)")
            return results
        
        # Check 0.5: STRICT Invalid Extension Check
        effective_tld = suffix if suffix else domain
        
        # If no dot in URL (like "kabsis"), handle it
        if '.' not in url.split('//')[-1]: 
             if url.split('//')[-1] != 'localhost':
                results['is_typosquatting'] = True
                results['impersonated_brand'] = None
                results['detection_method'] = 'invalid_domain_structure'
                results['similarity_score'] = 1.0
                results['risk_increase'] = 80
                results['details'].append(f"Invalid domain structure: '{url}'. Missing valid extension.")
                return results

        # If extension exists but is NOT in our valid list -> Flag it
        if suffix and suffix not in self.valid_tlds:
            results['is_typosquatting'] = True
            results['impersonated_brand'] = None
            results['detection_method'] = 'invalid_extension'
            results['similarity_score'] = 1.0
            results['risk_increase'] = 75
            
            # Check if it's visually similar to a valid TLD for better error message
            similar_tld = None
            for valid in self.valid_tlds:
                if SequenceMatcher(None, suffix, valid).ratio() >= 0.75:
                    similar_tld = valid
                    break
            
            if similar_tld:
                msg = f"Invalid extension '.{suffix}' (Likely typo of '.{similar_tld}')"
            else:
                msg = f"Invalid/Non-existent extension '.{suffix}' detected."
                
            results['details'].append(msg)
            return results
        
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
        if not results['is_typosquatting'] and extracted.subdomain:
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
