import re
import tldextract
from urllib.parse import urlparse
import numpy as np

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
