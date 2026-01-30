import re
import tldextract
from urllib.parse import urlparse
import numpy as np
import unicodedata
from typing import Dict, Any, Set, Tuple, List
try:
    from .common_words import COMMON_WORDS
except ImportError:
    try:
        from common_words import COMMON_WORDS
    except ImportError:
        COMMON_WORDS = set()

try:
    from .tls_analyzer import extract_tls_features
except ImportError:
    try:
        from tls_analyzer import extract_tls_features
    except ImportError:
        extract_tls_features = None

try:
    from .security_validator import URLSecurityValidator, validate_url_for_analysis
except ImportError:
    try:
        from security_validator import URLSecurityValidator, validate_url_for_analysis
    except ImportError:
        URLSecurityValidator = None
        validate_url_for_analysis = None

class URLFeatureExtractor:
    """Extract handcrafted features from URLs"""
    
    @staticmethod
    def extract_features(url, include_tls=False):
        """
        Extract URL-based features (50+ features total)
        
        Args:
            url: URL string to analyze
            include_tls: Whether to perform TLS certificate checks (slower)
            
        Returns:
            dict: Feature dictionary with 50+ features
        """
        features = {}
        
        # Parse URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        hostname = parsed.netloc
        
        # ========== BASIC LENGTH FEATURES ==========
        features['url_length'] = len(url)
        features['domain_length'] = len(extracted.domain)
        features['path_length'] = len(parsed.path)
        features['hostname_length'] = len(hostname)
        
        # ========== BASIC CHARACTER FEATURES ==========
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersand'] = url.count('&')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # ========== PROTOCOL FEATURES ==========
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_port'] = 1 if parsed.port else 0
        
        # ========== BASIC DOMAIN FEATURES ==========
        features['is_ip_address'] = 1 if URLFeatureExtractor._is_ip(hostname) else 0
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        
        # ========== SUSPICIOUS PATTERNS ==========
        features['has_suspicious_words'] = URLFeatureExtractor._has_suspicious_words(url)
        features['entropy'] = URLFeatureExtractor._calculate_entropy(url)
        
        # ========== DOMAIN ENTROPY & RANDOMNESS ==========
        features['domain_entropy'] = URLFeatureExtractor._calculate_entropy(extracted.domain)
        
        # Heuristic for random domains
        domain_text = extracted.domain.lower()
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels_list = "aeiou"
        
        max_consecutive_consonants = 0
        current_consecutive_consonants = 0
        max_consecutive_vowels = 0
        current_consecutive_vowels = 0
        
        for char in domain_text:
            if char in consonants:
                current_consecutive_consonants += 1
                max_consecutive_consonants = max(max_consecutive_consonants, current_consecutive_consonants)
                current_consecutive_vowels = 0
            elif char in vowels_list:
                current_consecutive_vowels += 1
                max_consecutive_vowels = max(max_consecutive_vowels, current_consecutive_vowels)
                current_consecutive_consonants = 0
            else:
                current_consecutive_consonants = 0
                current_consecutive_vowels = 0
        
        # Calculate vowel ratio
        letters_only = "".join([c for c in domain_text if c.isalpha()])
        num_vowels = sum(1 for c in letters_only if c in vowels_list)
        vowel_ratio = num_vowels / len(letters_only) if letters_only else 0
        
        features['max_consecutive_consonants'] = max_consecutive_consonants
        features['max_consecutive_vowels'] = max_consecutive_vowels
        features['vowel_ratio'] = vowel_ratio
        
        is_random = 0
        has_digits = any(c.isdigit() for c in extracted.domain)
        
        if features['domain_entropy'] > 3.7:
            is_random = 1
        elif features['domain_entropy'] > 2.7 and has_digits:
            is_random = 1
        elif max_consecutive_consonants >= 5:
            is_random = 1
        elif max_consecutive_vowels >= 3:
            is_random = 1
        elif len(letters_only) > 4 and vowel_ratio < 0.15:
            is_random = 1
        elif len(letters_only) > 5 and vowel_ratio >= 0.65:
            is_random = 1
        
        # Repetitive pattern check
        if len(domain_text) > 6:
            for k in [2, 3]:
                substrings = [domain_text[i:i+k] for i in range(len(domain_text)-k+1)]
                if len(set(substrings)) < len(substrings) * 0.6:
                    is_random = 1
                    break
        
        # Dictionary Check
        is_dictionary_word = 0
        if COMMON_WORDS:
            if domain_text in COMMON_WORDS:
                is_dictionary_word = 1
            elif len(domain_text) > 3:
                for i in range(2, len(domain_text)-1):
                    if domain_text[:i] in COMMON_WORDS and domain_text[i:] in COMMON_WORDS:
                        is_dictionary_word = 1
                        break
        
        if is_dictionary_word:
            is_random = 0
        
        features['is_random_domain'] = is_random
        features['is_dictionary_word'] = is_dictionary_word
        
        # ========== IDN & UNICODE FEATURES ==========
        idn_features = URLFeatureExtractor._get_idn_features(hostname)
        features.update(idn_features)
        
        # ========== ENHANCED HOST FEATURES ==========
        host_features = URLFeatureExtractor._extract_host_features(hostname, extracted)
        features.update(host_features)
        
        # ========== ENHANCED URL PATTERN FEATURES ==========
        pattern_features = URLFeatureExtractor._extract_url_pattern_features(url, parsed)
        features.update(pattern_features)
        
        # ========== SECURITY VALIDATION FEATURES ==========
        security_features = URLFeatureExtractor._extract_security_features(url)
        features.update(security_features)
        
        # ========== TLS/SSL FEATURES (OPTIONAL) ==========
        if include_tls and parsed.scheme == 'https':
            tls_features = URLFeatureExtractor._extract_tls_features(url)
            features.update(tls_features)
        else:
            # Add placeholder TLS features
            features['uses_https'] = 1 if parsed.scheme == 'https' else 0
            features['tls_secure'] = -1  # Not checked
            features['cert_valid'] = -1
            features['hsts_enabled'] = -1
            features['ct_logs_found'] = -1
            features['tls_security_score'] = -1
            features['tls_risk_score'] = -1
            features['has_tls_issues'] = -1
            features['tls_version_score'] = -1
            features['cert_days_remaining'] = -1
            features['cert_expiring_soon'] = -1
        
        # ========== COMPOSITE FEATURES ==========
        # Combined risk indicators
        features['idn_risk_score'] = (
            features.get('has_punycode', 0) * 25 +
            features.get('has_unicode', 0) * 15 +
            features.get('mixed_scripts', 0) * 30 +
            min(features.get('confusable_count', 0), 5) * 10
        )
        
        features['host_risk_score'] = (
            features.get('suspicious_subdomain_pattern', 0) * 20 +
            features.get('suspicious_tld', 0) * 15 +
            features.get('is_random_domain', 0) * 25 +
            features.get('brand_in_domain', 0) * 20
        )
        
        features['security_risk_score'] = (
            features.get('has_blocked_scheme', 0) * 50 +
            features.get('has_private_ip', 0) * 40 +
            features.get('has_dangerous_chars', 0) * 25 +
            features.get('has_path_traversal', 0) * 30 +
            (1 - features.get('security_validation_passed', 0)) * 20
        )
        
        return features
    
    @staticmethod
    def _is_ip(domain):
        """Check if domain is an IP address"""
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(pattern.match(domain))
    
    @staticmethod
    def _has_suspicious_words(url):
        """Check for suspicious keywords"""
        suspicious_words = [
            'login', 'signin', 'account', 'update', 'verify', 'secure',
            'banking', 'paypal', 'ebay', 'amazon', 'confirm'
        ]
        url_lower = url.lower()
        return sum(1 for word in suspicious_words if word in url_lower)
    
    @staticmethod
    def _calculate_entropy(text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = text.count(chr(x)) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    # ============== IDN & UNICODE DETECTION ==============
    
    @staticmethod
    def _is_punycode(domain: str) -> bool:
        """Check if domain uses punycode (xn-- prefix)"""
        return 'xn--' in domain.lower()
    
    @staticmethod
    def _contains_unicode(domain: str) -> bool:
        """Check if domain contains non-ASCII characters"""
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True
    
    @staticmethod
    def _get_unicode_categories(text: str) -> Dict[str, int]:
        """Count characters by Unicode category"""
        categories = {}
        for char in text:
            cat = unicodedata.category(char)
            categories[cat] = categories.get(cat, 0) + 1
        return categories
    
    @staticmethod
    def _detect_mixed_scripts(domain: str) -> Tuple[bool, List[str]]:
        """Detect mixing of different Unicode scripts"""
        scripts_found = set()
        script_map = {
            'LATIN': range(0x0041, 0x007A),
            'CYRILLIC': range(0x0400, 0x04FF),
            'GREEK': range(0x0370, 0x03FF),
            'ARABIC': range(0x0600, 0x06FF),
            'HEBREW': range(0x0590, 0x05FF),
            'CJK': range(0x4E00, 0x9FFF),
            'HANGUL': range(0xAC00, 0xD7AF),
            'THAI': range(0x0E00, 0x0E7F),
            'ARMENIAN': range(0x0530, 0x058F),
            'GEORGIAN': range(0x10A0, 0x10FF),
        }
        
        for char in domain:
            code_point = ord(char)
            for script, code_range in script_map.items():
                if code_point in code_range:
                    scripts_found.add(script)
                    break
        
        # Check for mixed scripts (excluding digits and special chars)
        meaningful_scripts = scripts_found - {'DIGITS'}
        is_mixed = len(meaningful_scripts) > 1
        return is_mixed, list(meaningful_scripts)
    
    @staticmethod
    def _check_confusable_chars(domain: str) -> Tuple[int, List[str]]:
        """Check for Unicode confusable/homoglyph characters"""
        # Common confusable mappings (Latin look-alikes)
        confusables = {
            'а': 'CYRILLIC SMALL LETTER A (looks like Latin a)',
            'о': 'CYRILLIC SMALL LETTER O (looks like Latin o)',
            'р': 'CYRILLIC SMALL LETTER ER (looks like Latin p)',
            'е': 'CYRILLIC SMALL LETTER IE (looks like Latin e)',
            'х': 'CYRILLIC SMALL LETTER HA (looks like Latin x)',
            'с': 'CYRILLIC SMALL LETTER ES (looks like Latin c)',
            'і': 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I (looks like Latin i)',
            'ј': 'CYRILLIC SMALL LETTER JE (looks like Latin j)',
            'ο': 'GREEK SMALL LETTER OMICRON (looks like Latin o)',
            'е': 'GREEK SMALL LETTER EPSILON (looks like Latin e)',
            'α': 'GREEK SMALL LETTER ALPHA (looks like Latin a)',
            'ρ': 'GREEK SMALL LETTER RHO (looks like Latin p)',
            'κ': 'GREEK SMALL LETTER KAPPA (looks like Latin k)',
            'х': 'GREEK SMALL LETTER CHI (looks like Latin x)',
            'τ': 'GREEK SMALL LETTER TAU (looks like Latin t)',
            'ν': 'GREEK SMALL LETTER NU (looks like Latin v)',
            'ω': 'GREEK SMALL LETTER OMEGA (looks like Latin w)',
            'ց': 'ARMENIAN SMALL LETTER CO (looks like Latin g)',
            'һ': 'CYRILLIC SMALL LETTER SHHA (looks like Latin h)',
            'ԛ': 'CYRILLIC SMALL LETTER QA (looks like Latin q)',
            'ԝ': 'CYRILLIC SMALL LETTER WE (looks like Latin w)',
            'տ': 'ARMENIAN SMALL LETTER TO (looks like Latin s)',
            'օ': 'ARMENIAN SMALL LETTER OH (looks like Latin o)',
        }
        
        found_confusables = []
        for char in domain.lower():
            if char in confusables:
                found_confusables.append(confusables[char])
        
        return len(found_confusables), found_confusables
    
    @staticmethod
    def _get_idn_features(domain: str) -> Dict[str, Any]:
        """Extract all IDN-related features"""
        features = {}
        
        # Punycode detection
        features['has_punycode'] = 1 if URLFeatureExtractor._is_punycode(domain) else 0
        features['has_unicode'] = 1 if URLFeatureExtractor._contains_unicode(domain) else 0
        
        # Unicode categories
        categories = URLFeatureExtractor._get_unicode_categories(domain)
        features['unicode_letter_count'] = sum(categories.get(cat, 0) for cat in ['Lu', 'Ll', 'Lt', 'Lm', 'Lo'])
        features['unicode_mark_count'] = sum(categories.get(cat, 0) for cat in ['Mn', 'Mc', 'Me'])
        features['unicode_number_count'] = sum(categories.get(cat, 0) for cat in ['Nd', 'Nl', 'No'])
        features['unicode_symbol_count'] = sum(categories.get(cat, 0) for cat in ['Sm', 'Sc', 'Sk', 'So'])
        features['unicode_punctuation_count'] = sum(categories.get(cat, 0) for cat in ['Pc', 'Pd', 'Ps', 'Pe', 'Pi', 'Pf', 'Po'])
        
        # Mixed script detection
        is_mixed, scripts = URLFeatureExtractor._detect_mixed_scripts(domain)
        features['mixed_scripts'] = 1 if is_mixed else 0
        features['script_count'] = len(scripts)
        
        # Confusable detection
        confusable_count, _ = URLFeatureExtractor._check_confusable_chars(domain)
        features['confusable_count'] = confusable_count
        features['has_confusables'] = 1 if confusable_count > 0 else 0
        
        return features
    
    # ============== ENHANCED HOST FEATURES ==============
    
    @staticmethod
    def _extract_host_features(hostname: str, extracted) -> Dict[str, Any]:
        """Extract enhanced host-based features"""
        features = {}
        
        # Subdomain features
        subdomain_parts = extracted.subdomain.split('.') if extracted.subdomain else []
        features['subdomain_depth'] = len(subdomain_parts)
        features['subdomain_length'] = len(extracted.subdomain) if extracted.subdomain else 0
        
        # Check for suspicious subdomain patterns
        suspicious_subdomain_patterns = [
            r'^www\d+\.',  # www1, www2, etc.
            r'^(mail|email|login|signin|account|secure|update|verify|confirm|bank)\d*\.',
            r'.*\d{4,}.*',  # Subdomain with 4+ consecutive digits
        ]
        features['suspicious_subdomain_pattern'] = 0
        subdomain_str = extracted.subdomain + '.' if extracted.subdomain else ''
        for pattern in suspicious_subdomain_patterns:
            if re.search(pattern, subdomain_str, re.I):
                features['suspicious_subdomain_pattern'] = 1
                break
        
        # Domain name structure
        features['domain_has_digits'] = 1 if any(c.isdigit() for c in extracted.domain) else 0
        features['domain_digit_count'] = sum(1 for c in extracted.domain if c.isdigit())
        features['domain_alpha_count'] = sum(1 for c in extracted.domain if c.isalpha())
        features['domain_special_char_count'] = sum(1 for c in extracted.domain if not c.isalnum())
        
        # TLD features
        features['tld_length'] = len(extracted.suffix)
        features['tld_parts'] = len(extracted.suffix.split('.')) if extracted.suffix else 0
        
        # Check for suspicious TLDs
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'date', 'party', 'link', 'click'}
        tld_base = extracted.suffix.split('.')[-1].lower() if extracted.suffix else ''
        features['suspicious_tld'] = 1 if tld_base in suspicious_tlds else 0
        
        # Brand impersonation check in domain
        brand_indicators = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'bank', 'gmail', 'outlook']
        features['brand_in_domain'] = 0
        domain_lower = extracted.domain.lower()
        for brand in brand_indicators:
            if brand in domain_lower:
                features['brand_in_domain'] = 1
                break
        
        # Hostname entropy
        features['hostname_entropy'] = URLFeatureExtractor._calculate_entropy(hostname)
        
        return features
    
    # ============== ENHANCED URL PATTERN FEATURES ==============
    
    @staticmethod
    def _extract_url_pattern_features(url: str, parsed) -> Dict[str, Any]:
        """Extract enhanced URL pattern features"""
        features = {}
        
        # Special character counts
        features['num_hashes'] = url.count('#')
        features['num_tildes'] = url.count('~')
        features['num_percent'] = url.count('%')
        features['num_plus'] = url.count('+')
        features['num_exclamation'] = url.count('!')
        features['num_asterisk'] = url.count('*')
        features['num_dollar'] = url.count('$')
        features['num_comma'] = url.count(',')
        features['num_semicolon'] = url.count(';')
        features['num_colon'] = url.count(':')
        
        # Ratio features
        url_len = len(url)
        if url_len > 0:
            features['digit_ratio'] = sum(c.isdigit() for c in url) / url_len
            features['letter_ratio'] = sum(c.isalpha() for c in url) / url_len
            features['special_char_ratio'] = sum(not c.isalnum() for c in url) / url_len
        else:
            features['digit_ratio'] = 0
            features['letter_ratio'] = 0
            features['special_char_ratio'] = 0
        
        # Path features
        path_parts = parsed.path.split('/') if parsed.path else []
        features['path_depth'] = len([p for p in path_parts if p])
        features['path_file_extension'] = URLFeatureExtractor._get_file_extension(parsed.path)
        
        # Query features
        features['has_query'] = 1 if parsed.query else 0
        if parsed.query:
            query_params = parsed.query.split('&')
            features['query_param_count'] = len(query_params)
            features['query_total_length'] = len(parsed.query)
        else:
            features['query_param_count'] = 0
            features['query_total_length'] = 0
        
        # Fragment features
        features['has_fragment'] = 1 if parsed.fragment else 0
        
        # Suspicious patterns
        features['has_data_uri'] = 1 if re.search(r'data:[^;]*;base64,', url, re.I) else 0
        features['has_hex_encoding'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
        features['has_ip_in_url'] = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0
        features['has_port_in_url'] = 1 if re.search(r':\d{1,5}(?:/|$)', url) else 0
        
        # Check for URL shortening indicators
        shortening_patterns = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link']
        features['is_shortened_url'] = 1 if any(pattern in url.lower() for pattern in shortening_patterns) else 0
        
        return features
    
    @staticmethod
    def _get_file_extension(path: str) -> int:
        """Check if path has a file extension and categorize it"""
        if not path or '.' not in path:
            return 0
        
        ext = path.split('/')[-1].split('.')[-1].lower()
        executable_exts = {'exe', 'dll', 'bat', 'cmd', 'sh', 'bin', 'msi', 'jar'}
        script_exts = {'js', 'php', 'asp', 'aspx', 'jsp', 'py', 'rb', 'pl'}
        document_exts = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'}
        
        if ext in executable_exts:
            return 1  # Executable
        elif ext in script_exts:
            return 2  # Script
        elif ext in document_exts:
            return 3  # Document
        else:
            return 4  # Other
    
    @staticmethod
    def _extract_security_features(url: str) -> Dict[str, Any]:
        """Extract security validation features"""
        features = {}
        
        # Initialize validator
        validator = URLSecurityValidator() if URLSecurityValidator else None
        
        if validator:
            is_valid, errors = validator.validate(url, strict=False)
            features['security_validation_passed'] = 1 if is_valid else 0
            features['security_error_count'] = len(errors)
            
            # Check for specific security issues
            features['has_blocked_scheme'] = 0
            features['has_private_ip'] = 0
            features['has_blocked_port'] = 0
            features['has_dangerous_chars'] = 0
            features['has_path_traversal'] = 0
            
            for error in errors:
                error_lower = error.lower()
                if 'scheme' in error_lower:
                    features['has_blocked_scheme'] = 1
                elif 'private' in error_lower or 'ssrf' in error_lower:
                    features['has_private_ip'] = 1
                elif 'port' in error_lower:
                    features['has_blocked_port'] = 1
                elif 'dangerous' in error_lower:
                    features['has_dangerous_chars'] = 1
                elif 'traversal' in error_lower:
                    features['has_path_traversal'] = 1
        else:
            # Fallback if validator not available
            features['security_validation_passed'] = 1
            features['security_error_count'] = 0
            features['has_blocked_scheme'] = 0
            features['has_private_ip'] = 0
            features['has_blocked_port'] = 0
            features['has_dangerous_chars'] = 0
            features['has_path_traversal'] = 0
        
        return features
    
    @staticmethod
    def _extract_tls_features(url: str) -> Dict[str, Any]:
        """Extract TLS/SSL security features"""
        features = {}
        
        if extract_tls_features:
            try:
                tls_results = extract_tls_features(url)
                features['uses_https'] = 1 if tls_results.get('uses_https') else 0
                features['tls_secure'] = 1 if tls_results.get('tls_secure') else 0
                features['cert_valid'] = 1 if tls_results.get('cert_valid') else 0
                features['hsts_enabled'] = 1 if tls_results.get('hsts_enabled') else 0
                features['ct_logs_found'] = 1 if tls_results.get('ct_logs') else 0
                features['tls_security_score'] = tls_results.get('tls_security_score', 0)
                features['tls_risk_score'] = tls_results.get('tls_risk_score', 100)
                features['has_tls_issues'] = 1 if tls_results.get('has_tls_issues') else 0
                
                # TLS version encoding
                tls_version = tls_results.get('tls_version', 'unknown')
                version_scores = {
                    'TLSv1.3': 100, 'TLSv1.2': 90, 'TLSv1.1': 20, 
                    'TLSv1.0': 10, 'SSLv3': 0, 'SSLv2': 0, 'unknown': 0
                }
                features['tls_version_score'] = version_scores.get(tls_version, 0)
                
                # Certificate days remaining
                cert_days = tls_results.get('cert_days_remaining', -1)
                features['cert_days_remaining'] = cert_days if cert_days is not None else -1
                features['cert_expiring_soon'] = 1 if cert_days is not None and 0 <= cert_days < 7 else 0
            except Exception:
                # TLS check failed, set defaults
                features['uses_https'] = 1 if url.startswith('https://') else 0
                features['tls_secure'] = 0
                features['cert_valid'] = 0
                features['hsts_enabled'] = 0
                features['ct_logs_found'] = 0
                features['tls_security_score'] = 0
                features['tls_risk_score'] = 100
                features['has_tls_issues'] = 1
                features['tls_version_score'] = 0
                features['cert_days_remaining'] = -1
                features['cert_expiring_soon'] = 0
        else:
            # Fallback: just check scheme
            features['uses_https'] = 1 if url.startswith('https://') else 0
            features['tls_secure'] = 0
            features['cert_valid'] = 0
            features['hsts_enabled'] = 0
            features['ct_logs_found'] = 0
            features['tls_security_score'] = 0
            features['tls_risk_score'] = 100
            features['has_tls_issues'] = 0
            features['tls_version_score'] = 0
            features['cert_days_remaining'] = -1
            features['cert_expiring_soon'] = 0
        
        return features
