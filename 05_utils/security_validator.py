"""
Security Validator Module

Provides URL validation, SSRF protection, and input sanitization.
Prevents attacks like:
- Server-Side Request Forgery (SSRF)
- Open redirects
- Malicious URL injection
- Private network access

Author: Phishing Guard Team
Version: 2.0.0
"""

import re
import ipaddress
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote, unquote
from typing import Dict, List, Set, Optional, Tuple


class URLSecurityValidator:
    """
    Validates URLs for security issues before processing.
    
    Checks:
    - URL format and structure
    - Blocked schemes (file://, javascript:, etc.)
    - Private IP ranges (SSRF protection)
    - Dangerous characters and encoding
    - Port restrictions
    - URL length limits
    """
    
    # Blocked URL schemes that could be dangerous
    BLOCKED_SCHEMES: Set[str] = {
        'file', 'ftp', 'sftp', 'javascript', 'vbscript', 'data', 
        'blob', 'about', 'chrome', 'resource', 'jar'
    }
    
    # Allowed schemes (whitelist approach)
    ALLOWED_SCHEMES: Set[str] = {'http', 'https'}
    
    # Blocked IP ranges for SSRF protection
    BLOCKED_IP_NETWORKS: List[ipaddress.IPv4Network] = [
        ipaddress.ip_network('10.0.0.0/8'),      # Private
        ipaddress.ip_network('172.16.0.0/12'),   # Private
        ipaddress.ip_network('192.168.0.0/16'),  # Private
        ipaddress.ip_network('127.0.0.0/8'),     # Loopback
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('0.0.0.0/8'),       # Current network
        ipaddress.ip_network('::1/128'),         # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),        # IPv6 private
        ipaddress.ip_network('fe80::/10'),       # IPv6 link-local
    ]
    
    # Blocked ports (common services that shouldn't be accessed)
    BLOCKED_PORTS: Set[int] = {
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        110,   # POP3
        143,   # IMAP
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        6379,  # Redis
        9200,  # Elasticsearch
        27017, # MongoDB
    }
    
    # Dangerous characters that could be used for injection
    DANGEROUS_CHARS: Set[str] = {
        '<', '>', '"', "'", '`', '{', '}', '|', '\\', '^', '\x00', '\x01'
    }
    
    # URL length limits
    MAX_URL_LENGTH: int = 2048
    MAX_DOMAIN_LENGTH: int = 253
    MAX_PATH_LENGTH: int = 1024
    
    # Suspicious patterns in URLs
    SUSPICIOUS_PATTERNS: List[re.Pattern] = [
        re.compile(r'@\d+\.\d+\.\d+\.\d+'),  # Userinfo with IP (e.g., http://user@1.2.3.4)
        re.compile(r'\.\./'),               # Path traversal
        re.compile(r'\.\.%2f', re.I),      # Path traversal (encoded)
        re.compile(r'%00'),                 # Null byte
        re.compile(r'\s'),                  # Whitespace
    ]
    
    def __init__(self):
        self.validation_errors: List[str] = []
    
    def validate(self, url: str, strict: bool = True) -> Tuple[bool, List[str]]:
        """
        Comprehensive URL validation.
        
        Args:
            url: URL to validate
            strict: If True, reject any suspicious URLs. If False, warn but allow.
            
        Returns:
            Tuple of (is_valid, list_of_errors)
            
        Example:
            validator = URLSecurityValidator()
            is_valid, errors = validator.validate("http://example.com")
            if not is_valid:
                print(f"URL rejected: {errors}")
        """
        self.validation_errors = []
        
        # 1. Basic checks
        if not url or not isinstance(url, str):
            self.validation_errors.append("URL must be a non-empty string")
            return False, self.validation_errors
        
        # 2. Length check
        if len(url) > self.MAX_URL_LENGTH:
            self.validation_errors.append(f"URL too long: {len(url)} > {self.MAX_URL_LENGTH}")
            return False, self.validation_errors
        
        # 3. Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            self.validation_errors.append(f"Failed to parse URL: {e}")
            return False, self.validation_errors
        
        # 4. Scheme validation
        scheme = parsed.scheme.lower()
        if not scheme:
            self.validation_errors.append("URL must include scheme (http:// or https://)")
            return False, self.validation_errors
        
        if scheme in self.BLOCKED_SCHEMES:
            self.validation_errors.append(f"Scheme '{scheme}' is not allowed")
            return False, self.validation_errors
        
        if scheme not in self.ALLOWED_SCHEMES:
            self.validation_errors.append(f"Scheme '{scheme}' is not in allowed list: {self.ALLOWED_SCHEMES}")
            if strict:
                return False, self.validation_errors
        
        # 5. Host validation
        hostname = parsed.hostname
        if not hostname:
            self.validation_errors.append("URL must have a hostname")
            return False, self.validation_errors
        
        # 6. Domain length
        if len(hostname) > self.MAX_DOMAIN_LENGTH:
            self.validation_errors.append(f"Domain name too long: {len(hostname)} > {self.MAX_DOMAIN_LENGTH}")
            return False, self.validation_errors
        
        # 7. Check for dangerous characters
        for char in self.DANGEROUS_CHARS:
            if char in url:
                self.validation_errors.append(f"Dangerous character found in URL: {repr(char)}")
                if strict:
                    return False, self.validation_errors
        
        # 8. Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.search(url):
                self.validation_errors.append(f"Suspicious pattern found: {pattern.pattern}")
                if strict:
                    return False, self.validation_errors
        
        # 9. SSRF Protection - Check if hostname resolves to private IP
        if self._is_private_host(hostname):
            self.validation_errors.append("URL resolves to private/internal IP address (SSRF protection)")
            return False, self.validation_errors
        
        # 10. Port validation
        port = parsed.port
        if port and port in self.BLOCKED_PORTS:
            self.validation_errors.append(f"Port {port} is blocked")
            return False, self.validation_errors
        
        # 11. Path validation
        if parsed.path:
            decoded_path = unquote(parsed.path)
            if len(decoded_path) > self.MAX_PATH_LENGTH:
                self.validation_errors.append(f"Path too long: {len(decoded_path)} > {self.MAX_PATH_LENGTH}")
                return False, self.validation_errors
            
            # Check for path traversal
            if '..' in decoded_path:
                self.validation_errors.append("Path traversal attempt detected")
                return False, self.validation_errors
        
        # 12. Query parameter validation
        if parsed.query:
            try:
                params = parse_qs(parsed.query)
                # Check for suspicious parameter names/values
                for key, values in params.items():
                    for value in values:
                        if any(char in key or char in value for char in self.DANGEROUS_CHARS):
                            self.validation_errors.append(f"Suspicious characters in query parameter: {key}")
                            if strict:
                                return False, self.validation_errors
            except Exception:
                pass  # Invalid query string format, but we'll allow it
        
        return len(self.validation_errors) == 0, self.validation_errors
    
    def _is_private_host(self, hostname: str) -> bool:
        """
        Check if hostname resolves to a private IP address.
        
        Args:
            hostname: Hostname to check
            
        Returns:
            bool: True if resolves to private IP
        """
        try:
            # Check if it's already an IP address
            ip = ipaddress.ip_address(hostname)
            # Check against blocked networks
            for network in self.BLOCKED_IP_NETWORKS:
                if ip in network:
                    return True
            return False
        except ValueError:
            # Not an IP, try DNS resolution
            pass
        
        # Try to resolve hostname
        try:
            import socket
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            
            for network in self.BLOCKED_IP_NETWORKS:
                if ip in network:
                    return True
        except Exception:
            # Can't resolve or other error - allow it
            pass
        
        return False
    
    def canonicalize(self, url: str) -> str:
        """
        Canonicalize URL to prevent bypass attacks.
        
        Performs:
        - Lowercase scheme and host
        - Remove default ports
        - Sort query parameters
        - Decode then re-encode path
        
        Args:
            url: URL to canonicalize
            
        Returns:
            str: Canonicalized URL
        """
        try:
            parsed = urlparse(url)
            
            # Lowercase scheme and netloc
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            
            # Remove default ports
            if ':80' in netloc and scheme == 'http':
                netloc = netloc.replace(':80', '')
            if ':443' in netloc and scheme == 'https':
                netloc = netloc.replace(':443', '')
            
            # Canonicalize path
            path = parsed.path
            if path:
                # Decode then re-encode properly
                decoded = unquote(path)
                path = quote(decoded, safe='/')
            
            # Sort query parameters
            query = parsed.query
            if query:
                params = parse_qs(query)
                # Sort by key
                sorted_params = sorted(params.items())
                query = urlencode(sorted_params, doseq=True)
            
            # Reconstruct URL
            canonical = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                query,
                parsed.fragment
            ))
            
            return canonical
            
        except Exception:
            # If canonicalization fails, return original
            return url
    
    def is_safe_url(self, url: str) -> bool:
        """
        Quick check if URL is safe (wrapper around validate).
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if safe, False otherwise
        """
        is_valid, _ = self.validate(url, strict=True)
        return is_valid


def validate_url_for_analysis(url: str) -> Tuple[bool, str]:
    """
    Convenience function for API endpoint validation.
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    validator = URLSecurityValidator()
    is_valid, errors = validator.validate(url, strict=True)
    
    if not is_valid:
        return False, "; ".join(errors)
    
    return True, ""


def demo():
    """Demonstrate URL security validation."""
    print("=" * 60)
    print("URL Security Validator Demo")
    print("=" * 60)
    
    validator = URLSecurityValidator()
    
    test_urls = [
        # Valid URLs
        ("https://example.com", True, "Standard HTTPS URL"),
        ("http://google.com", True, "Standard HTTP URL"),
        
        # SSRF attempts (should be blocked)
        ("http://127.0.0.1/admin", False, "Localhost IP"),
        ("http://192.168.1.1/config", False, "Private IP"),
        ("http://10.0.0.1/secret", False, "Private network"),
        ("http://localhost:8080/api", False, "Localhost hostname"),
        
        # Dangerous schemes (should be blocked)
        ("file:///etc/passwd", False, "File scheme"),
        ("javascript:alert(1)", False, "JavaScript scheme"),
        ("data:text/html,<script>alert(1)</script>", False, "Data scheme"),
        
        # Injection attempts (should be blocked)
        ("http://example.com/<script>", False, "Script tag in URL"),
        ("http://example.com/../../../etc/passwd", False, "Path traversal"),
        
        # Port blocking
        ("http://example.com:22/", False, "SSH port"),
        ("http://example.com:3306/", False, "MySQL port"),
    ]
    
    for url, expected_valid, description in test_urls:
        is_valid, errors = validator.validate(url)
        status = "✓" if is_valid == expected_valid else "✗"
        print(f"\n{status} {description}")
        print(f"   URL: {url}")
        print(f"   Valid: {is_valid} (expected: {expected_valid})")
        if errors:
            print(f"   Errors: {errors}")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    demo()
