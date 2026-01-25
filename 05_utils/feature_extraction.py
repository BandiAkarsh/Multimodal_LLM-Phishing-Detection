import re
import tldextract
from urllib.parse import urlparse
import numpy as np
try:
    from .common_words import COMMON_WORDS
except ImportError:
    try:
        from common_words import COMMON_WORDS
    except ImportError:
        COMMON_WORDS = set()

class URLFeatureExtractor:
    """Extract handcrafted features from URLs"""
    
    @staticmethod
    def extract_features(url):
        """
        Extract URL-based features
        
        Returns:
            dict: Feature dictionary
        """
        features = {}
        
        # Parse URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Length features
        features['url_length'] = len(url)
        features['domain_length'] = len(extracted.domain)
        features['path_length'] = len(parsed.path)
        
        # Character features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersand'] = url.count('&')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Protocol features
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_port'] = 1 if parsed.port else 0
        
        # Domain features
        features['is_ip_address'] = 1 if URLFeatureExtractor._is_ip(parsed.netloc) else 0
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        
        # Suspicious patterns
        features['has_suspicious_words'] = URLFeatureExtractor._has_suspicious_words(url)
        features['entropy'] = URLFeatureExtractor._calculate_entropy(url)
        
        # Domain specific features (New)
        features['domain_entropy'] = URLFeatureExtractor._calculate_entropy(extracted.domain)
        
        # Heuristic for random domains:
        # 1. Very high entropy (> 3.7) -> Likely random (e.g., 'abcdfghijk')
        # 2. Moderately high entropy (> 2.7) + Mixed Numbers/Letters -> Likely generated (e.g., 'ahs227wy')
        # 3. Gibberish check: Consonant clusters and Vowel ratio
        
        domain_text = extracted.domain.lower()
        
        # Calculate consonant clusters and vowel clusters
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
        
        # Calculate vowel ratio (excluding numbers)
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
        elif max_consecutive_consonants >= 5: # e.g. 'sqbqq'
            is_random = 1
        elif max_consecutive_vowels >= 3: # Reduced from 4 to 3 (e.g. 'aeiou')
            is_random = 1
        elif len(letters_only) > 4 and vowel_ratio < 0.15: # Very few vowels (e.g. 'ahsgyvwvb')
            is_random = 1
        # New check: High vowel ratio (too many vowels, e.g. 'aasaasaa' -> 0.75, 'asassasa' -> 0.5)
        elif len(letters_only) > 5 and vowel_ratio >= 0.65: # Stricter threshold
            is_random = 1
        
        # Repetitive pattern check (e.g., 'asassasa' has repetitive 'as')
        if len(domain_text) > 6:
            # Check for repeated substrings of length 2 or 3
            for k in [2, 3]:
                substrings = [domain_text[i:i+k] for i in range(len(domain_text)-k+1)]
                if len(set(substrings)) < len(substrings) * 0.6: # High repetition
                     is_random = 1
                     break
            
        # Dictionary Check (Override randomness if it's a known word)
        is_dictionary_word = 0
        if COMMON_WORDS:
            # Check full domain
            if domain_text in COMMON_WORDS:
                is_dictionary_word = 1
            # Check if domain is composed of 2 words (e.g. facebook, whatsapp)
            elif len(domain_text) > 3:
                for i in range(2, len(domain_text)-1):
                    if domain_text[:i] in COMMON_WORDS and domain_text[i:] in COMMON_WORDS:
                        is_dictionary_word = 1
                        break
        
        if is_dictionary_word:
            is_random = 0
            
        features['is_random_domain'] = is_random
        features['is_dictionary_word'] = is_dictionary_word
        
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
