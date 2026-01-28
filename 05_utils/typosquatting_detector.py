"""
Typosquatting Detection Module (Updated with Dynamic TLD Loading)

Detects brand impersonation through:
1. Levenshtein distance (edit distance)
2. Character substitution patterns (0 for o, 1 for l, etc.)
3. Homoglyph detection (characters that look similar)
4. Brand keyword presence in suspicious contexts
5. TLD typosquatting (.pom instead of .com, etc.)

IMPORTANT CHANGES:
- TLDs are now loaded from tld-list-details.json (1592 TLDs)
- Brand impersonation is ONLY flagged if the content doesn't match
- Content-based verification can override static detection
"""

import os
import re
import json
from difflib import SequenceMatcher
import tldextract
from typing import Dict, List, Optional, Set

# Get project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLD_JSON_PATH = os.path.join(PROJECT_ROOT, '01_data', 'external', 'tld_list.json')


def load_valid_tlds() -> Set[str]:
    """
    Load all valid TLDs from tld-list-details.json.
    This file contains 1592 TLDs from IANA registry.
    """
    try:
        with open(TLD_JSON_PATH, 'r', encoding='utf-8') as f:
            tld_data = json.load(f)
            # The JSON has TLDs as keys
            tlds = set(tld_data.keys())
            print(f"[TLD] Loaded {len(tlds)} valid TLDs from database")
            return tlds
    except FileNotFoundError:
        print(f"[TLD] Warning: {TLD_JSON_PATH} not found, using fallback TLD list")
        return _get_fallback_tlds()
    except json.JSONDecodeError as e:
        print(f"[TLD] Warning: Error parsing TLD JSON: {e}, using fallback")
        return _get_fallback_tlds()


def _get_fallback_tlds() -> Set[str]:
    """Fallback TLD list if JSON file is not available."""
    return {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
        'co', 'io', 'ai', 'app', 'dev', 'tech', 'online',
        'to', 'me', 'ly', 'sh', 'gg', 'so', 'xyz', 'cloud', 'site', 'top', 'club', 'vip', 'rs',
        'in', 'uk', 'us', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'nl', 'eu', 'es', 'it', 'ch', 'se', 'no',
        'info', 'biz', 'name', 'pro', 'mobi', 'tv', 'cc',
        'co.in', 'co.uk', 'com.au', 'com.br', 'co.jp', 'net.in', 'org.in',
        # Important newer TLDs
        'bank', 'insurance', 'law', 'money', 'credit', 'finance', 'loan',
    }


# Load TLDs at module import time
VALID_TLDS = load_valid_tlds()


# Major brands that are commonly impersonated
# Format: 'brand_keyword': {'domains': [...], 'industry': '...', 'keywords': [...]}
PROTECTED_BRANDS = {
    # Financial - Global
    'paypal': {'domains': ['paypal.com'], 'industry': 'payment', 'keywords': ['payment', 'money', 'transfer']},
    'chase': {'domains': ['chase.com'], 'industry': 'banking', 'keywords': ['bank', 'account']},
    'bankofamerica': {'domains': ['bankofamerica.com', 'bofa.com'], 'industry': 'banking', 'keywords': ['bank']},
    'wellsfargo': {'domains': ['wellsfargo.com'], 'industry': 'banking', 'keywords': ['bank']},
    'citibank': {'domains': ['citibank.com', 'citi.com'], 'industry': 'banking', 'keywords': ['bank']},
    'americanexpress': {'domains': ['americanexpress.com', 'amex.com'], 'industry': 'payment', 'keywords': ['card', 'credit']},
    'visa': {'domains': ['visa.com'], 'industry': 'payment', 'keywords': ['card', 'payment']},
    'mastercard': {'domains': ['mastercard.com'], 'industry': 'payment', 'keywords': ['card', 'payment']},
    
    # Financial - India
    'hdfc': {'domains': ['hdfcbank.com', 'hdfc.com'], 'industry': 'banking', 'keywords': ['bank', 'loan']},
    'icici': {'domains': ['icicibank.com', 'icici.com'], 'industry': 'banking', 'keywords': ['bank', 'loan']},
    'sbi': {'domains': ['sbi.co.in', 'onlinesbi.com'], 'industry': 'banking', 'keywords': ['bank', 'state']},
    'axis': {'domains': ['axisbank.com'], 'industry': 'banking', 'keywords': ['bank']},
    'kotak': {'domains': ['kotak.com', 'kotakbank.com', 'kotak.bank', 'kotak.bank.in'], 'industry': 'banking', 'keywords': ['bank', 'mahindra', 'netbanking']},
    'paytm': {'domains': ['paytm.com'], 'industry': 'payment', 'keywords': ['payment', 'wallet']},
    'phonepe': {'domains': ['phonepe.com'], 'industry': 'payment', 'keywords': ['payment', 'upi']},
    'gpay': {'domains': ['pay.google.com'], 'industry': 'payment', 'keywords': ['google', 'payment']},
    'razorpay': {'domains': ['razorpay.com'], 'industry': 'payment', 'keywords': ['payment', 'gateway']},
    
    # Tech Giants
    'google': {'domains': ['google.com', 'gmail.com', 'youtube.com'], 'industry': 'tech', 'keywords': ['search', 'mail', 'account']},
    'microsoft': {'domains': ['microsoft.com', 'outlook.com', 'live.com', 'office.com'], 'industry': 'tech', 'keywords': ['windows', 'office', 'account']},
    'apple': {'domains': ['apple.com', 'icloud.com'], 'industry': 'tech', 'keywords': ['iphone', 'mac', 'icloud']},
    'amazon': {'domains': ['amazon.com', 'amazon.in', 'aws.amazon.com'], 'industry': 'ecommerce', 'keywords': ['shop', 'prime', 'order']},
    'facebook': {'domains': ['facebook.com', 'fb.com'], 'industry': 'social', 'keywords': ['social', 'login']},
    'meta': {'domains': ['meta.com'], 'industry': 'tech', 'keywords': ['social']},
    'instagram': {'domains': ['instagram.com'], 'industry': 'social', 'keywords': ['photo', 'social']},
    'whatsapp': {'domains': ['whatsapp.com'], 'industry': 'messaging', 'keywords': ['chat', 'message']},
    'twitter': {'domains': ['twitter.com', 'x.com'], 'industry': 'social', 'keywords': ['tweet', 'social']},
    'linkedin': {'domains': ['linkedin.com'], 'industry': 'professional', 'keywords': ['job', 'network']},
    'netflix': {'domains': ['netflix.com'], 'industry': 'streaming', 'keywords': ['stream', 'watch', 'movie']},
    'spotify': {'domains': ['spotify.com'], 'industry': 'streaming', 'keywords': ['music', 'stream']},
    
    # E-commerce
    'ebay': {'domains': ['ebay.com'], 'industry': 'ecommerce', 'keywords': ['auction', 'buy']},
    'alibaba': {'domains': ['alibaba.com', 'aliexpress.com'], 'industry': 'ecommerce', 'keywords': ['wholesale', 'china']},
    'flipkart': {'domains': ['flipkart.com'], 'industry': 'ecommerce', 'keywords': ['shop', 'order']},
    
    # Crypto
    'coinbase': {'domains': ['coinbase.com'], 'industry': 'crypto', 'keywords': ['bitcoin', 'crypto']},
    'binance': {'domains': ['binance.com'], 'industry': 'crypto', 'keywords': ['bitcoin', 'trade']},
    'metamask': {'domains': ['metamask.io'], 'industry': 'crypto', 'keywords': ['wallet', 'ethereum']},
    
    # Shipping
    'fedex': {'domains': ['fedex.com'], 'industry': 'shipping', 'keywords': ['delivery', 'package', 'track']},
    'ups': {'domains': ['ups.com'], 'industry': 'shipping', 'keywords': ['delivery', 'package', 'track']},
    'dhl': {'domains': ['dhl.com'], 'industry': 'shipping', 'keywords': ['delivery', 'express']},
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
    """
    Detects typosquatting and brand impersonation in URLs.
    
    IMPORTANT: This detector now supports content-based verification.
    When web content is available, brand impersonation can be verified
    by checking if the page content matches the brand's industry.
    """
    
    def __init__(self):
        self.brands = PROTECTED_BRANDS
        self.homoglyphs = HOMOGLYPHS
        self.tld_typos = TLD_TYPOS
        self.valid_tlds = VALID_TLDS
        
    def analyze(self, url: str, page_content: Optional[Dict] = None) -> dict:
        """
        Analyze URL for typosquatting/brand impersonation.
        
        Args:
            url: The URL to analyze
            page_content: Optional dict with 'title', 'text', 'industry_keywords'
                         for content-based verification
        
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
            'details': [],
            'requires_content_verification': False,  # NEW: indicates if content should override
        }
        
        # SPECIAL CASE: When TLD is invalid, tldextract puts real domain in subdomain
        if not suffix and domain in self.tld_typos:
            real_domain = subdomain
            fake_tld = domain
            intended_tld = self.tld_typos[fake_tld]
            
            results['is_typosquatting'] = True
            results['impersonated_brand'] = None
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
        
        # Check 0.5: Invalid Domain Structure
        if '.' not in url.split('//')[-1]: 
            if url.split('//')[-1] != 'localhost':
                results['is_typosquatting'] = True
                results['impersonated_brand'] = None
                results['detection_method'] = 'invalid_domain_structure'
                results['similarity_score'] = 1.0
                results['risk_increase'] = 80
                results['details'].append(f"Invalid domain structure: '{url}'. Missing valid extension.")
                return results

        # Check TLD validity using the comprehensive list
        # Handle multi-part TLDs like "co.in", "bank.in"
        if suffix:
            # Split the suffix and check each part
            suffix_parts = suffix.split('.')
            
            # Check if full suffix is valid (e.g., "co.in")
            if suffix in self.valid_tlds:
                pass  # Valid
            # Check if last part is valid (e.g., "in" from "bank.in")
            elif suffix_parts[-1] in self.valid_tlds:
                pass  # Valid - the base TLD exists
            # Check if it's a two-part TLD where both parts are valid
            elif len(suffix_parts) == 2:
                # Check formats like "bank.in" where "bank" is a gTLD and "in" is a ccTLD
                # This is actually valid for some newer domains
                if suffix_parts[0] in self.valid_tlds and suffix_parts[1] in self.valid_tlds:
                    pass  # Valid - both parts are valid TLDs
                else:
                    # Only flag if neither part is a valid TLD
                    if suffix_parts[0] not in self.valid_tlds and suffix_parts[1] not in self.valid_tlds:
                        results['is_typosquatting'] = True
                        results['detection_method'] = 'invalid_extension'
                        results['similarity_score'] = 1.0
                        results['risk_increase'] = 75
                        results['details'].append(f"Invalid/Non-existent extension '.{suffix}' detected.")
                        return results
            else:
                # Single-part suffix not in valid list
                results['is_typosquatting'] = True
                results['detection_method'] = 'invalid_extension'
                results['similarity_score'] = 1.0
                results['risk_increase'] = 75
                
                # Check for similar valid TLD
                similar_tld = None
                for valid in list(self.valid_tlds)[:100]:  # Check first 100 for performance
                    if SequenceMatcher(None, suffix, valid).ratio() >= 0.75:
                        similar_tld = valid
                        break
                
                if similar_tld:
                    msg = f"Invalid extension '.{suffix}' (Likely typo of '.{similar_tld}')"
                else:
                    msg = f"Invalid/Non-existent extension '.{suffix}' detected."
                    
                results['details'].append(msg)
                return results
        
        # Check each brand for impersonation
        for brand, brand_info in self.brands.items():
            legitimate_domains = brand_info['domains'] if isinstance(brand_info, dict) else brand_info
            if isinstance(brand_info, dict):
                industry = brand_info.get('industry', '')
                brand_keywords = brand_info.get('keywords', [])
            else:
                industry = ''
                brand_keywords = []
            
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
                results['requires_content_verification'] = True  # Allow content to override
                results['expected_industry'] = industry
                results['expected_keywords'] = brand_keywords
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
                results['requires_content_verification'] = True
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
                    results['requires_content_verification'] = True
                    break
        
        return results
    
    def verify_with_content(self, typosquat_result: dict, page_title: str, 
                            page_text: str = "") -> dict:
        """
        Verify brand impersonation using page content.
        
        If the page content doesn't match the expected brand industry,
        the site might be legitimate (e.g., "kotaksalesianschool" is a school,
        not Kotak Bank).
        
        Args:
            typosquat_result: Result from analyze()
            page_title: Title of the page
            page_text: Text content of the page (optional)
            
        Returns:
            Updated result dict with content verification
        """
        if not typosquat_result.get('requires_content_verification'):
            return typosquat_result
        
        if not typosquat_result.get('is_typosquatting'):
            return typosquat_result
        
        brand = typosquat_result.get('impersonated_brand', '')
        expected_industry = typosquat_result.get('expected_industry', '')
        expected_keywords = typosquat_result.get('expected_keywords', [])
        
        if not brand or not page_title:
            return typosquat_result
        
        # Check if page content suggests it's a different type of business
        title_lower = page_title.lower()
        text_lower = (page_text or "").lower()
        combined = f"{title_lower} {text_lower}"
        
        # Non-financial/non-brand keywords that suggest legitimacy
        legitimate_indicators = [
            'school', 'college', 'university', 'education', 'academy',
            'hospital', 'clinic', 'medical', 'healthcare',
            'restaurant', 'cafe', 'hotel', 'resort',
            'church', 'temple', 'mosque', 'religious',
            'news', 'blog', 'magazine', 'media',
            'government', 'municipal', 'council',
            'ngo', 'foundation', 'charity', 'trust',
            'sports', 'club', 'association',
            'real estate', 'properties', 'realty',
        ]
        
        # Check for legitimate indicators
        found_legitimate = False
        for indicator in legitimate_indicators:
            if indicator in combined:
                found_legitimate = True
                break
        
        # Check if expected industry keywords are present
        industry_match = False
        for keyword in expected_keywords:
            if keyword in combined:
                industry_match = True
                break
        
        # If we found legitimate indicators but NO industry keywords, likely not impersonation
        if found_legitimate and not industry_match:
            typosquat_result['is_typosquatting'] = False
            typosquat_result['content_verified'] = True
            typosquat_result['verification_reason'] = f"Page appears to be a legitimate {title_lower.split()[0] if title_lower else 'business'}, not {brand}"
            typosquat_result['risk_increase'] = 0
            typosquat_result['details'] = [f"Content verification passed: Not related to {brand} {expected_industry}"]
        else:
            typosquat_result['content_verified'] = True
            if industry_match:
                typosquat_result['verification_reason'] = f"Page content matches {brand} {expected_industry} - likely impersonation"
        
        return typosquat_result
    
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
    
    print(f"\nLoaded {len(VALID_TLDS)} valid TLDs")
    print(f"Sample TLDs: {list(VALID_TLDS)[:10]}")
    print(f"'bank' in TLDs: {'bank' in VALID_TLDS}")
    print(f"'in' in TLDs: {'in' in VALID_TLDS}")
    
    test_urls = [
        # Should be VALID (bank is a valid TLD, in is a valid ccTLD)
        "https://netbanking.kotak.bank.in/knb2/",
        "https://kotaksalesianschool-vizag.com/",  # School, not bank
        
        # Should be INVALID/PHISHING
        "https://paypa1.com",  # Homoglyph
        "https://arnazon.com",  # Typo
        "https://blinkit.pom",  # Faulty TLD
        "https://secure-paypal-login.xyz",  # Brand in domain
        
        # Should be VALID
        "https://google.com",
        "https://amazon.com",
    ]
    
    print("\n" + "=" * 80)
    print("Typosquatting Detection Results:")
    print("=" * 80)
    
    for url in test_urls:
        result = detector.analyze(url)
        status = "TYPOSQUATTING" if result['is_typosquatting'] else "CLEAN"
        brand = result['impersonated_brand'] or "-"
        method = result['detection_method'] or "-"
        print(f"{status:15} | {url:45} | Brand: {brand:12} | Method: {method}")
