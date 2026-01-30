"""
TLS/SSL Security Analyzer

Analyzes the security configuration of HTTPS connections including:
- TLS version (reject 1.0/1.1, prefer 1.3)
- Cipher suite strength
- Certificate validity and expiration
- Certificate Transparency (CT) log presence
- HSTS header configuration
- OCSP stapling

Author: Phishing Guard Team
Version: 2.0.0
"""

import ssl
import socket
import requests
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse


class TLSSecurityAnalyzer:
    """
    Analyzes TLS/SSL security configuration of HTTPS websites.
    
    Provides security scores and detailed analysis of:
    - Protocol versions
    - Cipher suites
    - Certificate properties
    - Security headers
    """
    
    # Secure TLS versions (in order of preference)
    TLS_VERSIONS = {
        'TLSv1.3': {'secure': True, 'score': 100},
        'TLSv1.2': {'secure': True, 'score': 90},
        'TLSv1.1': {'secure': False, 'score': 20, 'warning': 'Deprecated, upgrade to TLS 1.2+'},
        'TLSv1.0': {'secure': False, 'score': 10, 'warning': 'Insecure, deprecated since 2021'},
        'SSLv3': {'secure': False, 'score': 0, 'warning': 'Severely insecure, POODLE attack'},
        'SSLv2': {'secure': False, 'score': 0, 'warning': 'Severely insecure'},
    }
    
    # Secure cipher suites
    SECURE_CIPHERS = [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
    ]
    
    # Insecure cipher patterns
    INSECURE_CIPHER_PATTERNS = [
        'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL',
        'EXP', 'EXPORT', 'ANON', 'CBC'
    ]
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    def analyze(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Comprehensive TLS security analysis.
        
        Args:
            hostname: Domain to analyze
            port: Port number (default 443)
            
        Returns:
            dict: Complete security analysis results
        """
        results = {
            'hostname': hostname,
            'port': port,
            'supports_https': False,
            'tls_version': None,
            'tls_secure': False,
            'tls_score': 0,
            'cipher_suite': None,
            'cipher_secure': False,
            'certificate': {
                'valid': False,
                'expires_in_days': None,
                'issuer': None,
                'subject': None,
                'serial_number': None,
            },
            'hsts_enabled': False,
            'hsts_max_age': None,
            'ct_logs_found': False,
            'ocsp_stapling': False,
            'security_score': 0,
            'warnings': [],
            'critical_issues': [],
            'error': None
        }
        
        try:
            # 1. Check HTTPS connectivity and get TLS info
            tls_info = self._get_tls_info(hostname, port)
            results.update(tls_info)
            results['supports_https'] = True
            
            # 2. Check HTTP security headers
            headers_info = self._check_security_headers(hostname, port)
            results.update(headers_info)
            
            # 3. Check Certificate Transparency
            ct_info = self._check_certificate_transparency(hostname)
            results.update(ct_info)
            
            # 4. Calculate overall security score
            results['security_score'] = self._calculate_security_score(results)
            
        except Exception as e:
            results['error'] = str(e)
            results['critical_issues'].append(f"TLS analysis failed: {str(e)}")
        
        return results
    
    def _get_tls_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Get TLS connection information."""
        results = {}
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get TLS version
                    version = ssock.version()
                    results['tls_version'] = version
                    
                    # Check if version is secure
                    version_info = self.TLS_VERSIONS.get(version, {'secure': False, 'score': 0})
                    results['tls_secure'] = version_info['secure']
                    results['tls_score'] = version_info['score']
                    
                    if not version_info['secure'] and 'warning' in version_info:
                        results['critical_issues'].append(version_info['warning'])
                    
                    # Get cipher suite
                    cipher = ssock.cipher()
                    results['cipher_suite'] = cipher[0]
                    
                    # Check cipher security
                    results['cipher_secure'] = self._is_cipher_secure(cipher[0])
                    if not results['cipher_secure']:
                        results['warnings'].append(f"Weak cipher suite: {cipher[0]}")
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    results['certificate'] = self._parse_certificate(cert)
                    
                    # Check OCSP stapling
                    results['ocsp_stapling'] = self._check_ocsp_stapling(ssock)
                    
        except ssl.SSLError as e:
            results['critical_issues'].append(f"SSL Error: {str(e)}")
            raise
        except socket.error as e:
            results['critical_issues'].append(f"Connection error: {str(e)}")
            raise
        
        return results
    
    def _is_cipher_secure(self, cipher: str) -> bool:
        """Check if cipher suite is secure."""
        # Check if in secure list
        if cipher in self.SECURE_CIPHERS:
            return True
        
        # Check for insecure patterns
        for pattern in self.INSECURE_CIPHER_PATTERNS:
            if pattern in cipher:
                return False
        
        # Default to cautious
        return True
    
    def _parse_certificate(self, cert: Dict) -> Dict[str, Any]:
        """Parse certificate information."""
        cert_info = {
            'valid': False,
            'expires_in_days': None,
            'issuer': None,
            'subject': None,
            'serial_number': None,
        }
        
        if not cert:
            return cert_info
        
        cert_info['valid'] = True
        
        # Parse subject
        subject = cert.get('subject')
        if subject:
            cert_info['subject'] = dict(x[0] for x in subject)
        
        # Parse issuer
        issuer = cert.get('issuer')
        if issuer:
            cert_info['issuer'] = dict(x[0] for x in issuer)
        
        # Parse expiration
        not_after = cert.get('notAfter')
        if not_after:
            try:
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                cert_info['expires_in_days'] = (expiry - now).days
                
                if cert_info['expires_in_days'] < 0:
                    cert_info['valid'] = False
                elif cert_info['expires_in_days'] < 7:
                    # Warning: expires soon
                    pass
            except:
                pass
        
        # Serial number
        cert_info['serial_number'] = cert.get('serialNumber')
        
        # Subject Alternative Names
        san = cert.get('subjectAltName', [])
        cert_info['san_count'] = len(san)
        
        return cert_info
    
    def _check_ocsp_stapling(self, ssock: ssl.SSLSocket) -> bool:
        """Check if OCSP stapling is enabled."""
        try:
            # Try to get OCSP response
            ocsp_response = ssock.ocsp_response()
            return ocsp_response is not None
        except:
            return False
    
    def _check_security_headers(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check HTTP security headers."""
        results = {
            'hsts_enabled': False,
            'hsts_max_age': None,
        }
        
        try:
            # Make HTTPS request
            url = f"https://{hostname}:{port}"
            response = requests.get(url, timeout=self.timeout, verify=True)
            
            # Check HSTS
            hsts = response.headers.get('Strict-Transport-Security')
            if hsts:
                results['hsts_enabled'] = True
                # Parse max-age
                match = re.search(r'max-age=(\d+)', hsts)
                if match:
                    results['hsts_max_age'] = int(match.group(1))
                    
                    if results['hsts_max_age'] < 31536000:  # Less than 1 year
                        results['warnings'] = results.get('warnings', [])
                        results['warnings'].append(
                            f"HSTS max-age is short: {results['hsts_max_age']} seconds (recommend 31536000)"
                        )
            
        except Exception:
            # Request failed, but that's okay for TLS analysis
            pass
        
        return results
    
    def _check_certificate_transparency(self, hostname: str) -> Dict[str, Any]:
        """Check Certificate Transparency logs."""
        results = {'ct_logs_found': False}
        
        try:
            # Query crt.sh for CT logs
            url = f"https://crt.sh/?q={hostname}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 0:
                    results['ct_logs_found'] = True
                    results['ct_entries'] = len(data)
                    
                    # Check for recently issued certificates
                    if len(data) > 0:
                        latest = data[0]
                        entry_time = latest.get('entry_timestamp')
                        if entry_time:
                            results['latest_cert_date'] = entry_time
        
        except Exception:
            # CT check failed, but don't fail the whole analysis
            pass
        
        return results
    
    def _calculate_security_score(self, results: Dict[str, Any]) -> int:
        """Calculate overall security score (0-100)."""
        score = 0
        
        # TLS version score (up to 40 points)
        score += results.get('tls_score', 0) * 0.4
        
        # Cipher security (up to 20 points)
        if results.get('cipher_secure'):
            score += 20
        else:
            score += 5
        
        # Certificate validity (up to 20 points)
        cert = results.get('certificate', {})
        if cert.get('valid'):
            score += 20
            
            # Bonus for long validity
            days = cert.get('expires_in_days', 0)
            if days and days > 30:
                score += min(5, days / 60)  # Up to 5 bonus points
        
        # HSTS (up to 10 points)
        if results.get('hsts_enabled'):
            score += 10
        
        # CT logs (up to 5 points)
        if results.get('ct_logs_found'):
            score += 5
        
        # OCSP stapling (up to 5 points)
        if results.get('ocsp_stapling'):
            score += 5
        
        return int(min(100, score))
    
    def quick_check(self, url: str) -> Dict[str, Any]:
        """
        Quick TLS security check for a URL.
        
        Args:
            url: URL to check (must be HTTPS)
            
        Returns:
            dict: Simplified results
        """
        parsed = urlparse(url)
        
        if parsed.scheme != 'https':
            return {
                'supports_https': False,
                'error': 'URL is not HTTPS',
                'security_score': 0,
                'risk_score': 40  # Penalty for HTTP
            }
        
        hostname = parsed.hostname
        port = parsed.port or 443
        
        results = self.analyze(hostname, port)
        
        # Simplified output
        return {
            'supports_https': True,
            'tls_version': results['tls_version'],
            'tls_secure': results['tls_secure'],
            'cert_valid': results['certificate']['valid'],
            'cert_expires_in_days': results['certificate']['expires_in_days'],
            'hsts_enabled': results['hsts_enabled'],
            'ct_logs_found': results['ct_logs_found'],
            'security_score': results['security_score'],
            'risk_score': max(0, 100 - results['security_score']),
            'warnings': results['warnings'],
            'critical_issues': results['critical_issues']
        }


def extract_tls_features(url: str) -> Dict[str, Any]:
    """
    Convenience function to extract TLS features for ML model.
    
    Args:
        url: URL to analyze
        
    Returns:
        dict: TLS features for ML model
    """
    analyzer = TLSSecurityAnalyzer()
    results = analyzer.quick_check(url)
    
    return {
        'uses_https': results['supports_https'],
        'tls_version': results.get('tls_version', 'unknown'),
        'tls_secure': results.get('tls_secure', False),
        'cert_valid': results.get('cert_valid', False),
        'cert_days_remaining': results.get('cert_expires_in_days', -1),
        'hsts_enabled': results.get('hsts_enabled', False),
        'ct_logs': results.get('ct_logs_found', False),
        'tls_security_score': results.get('security_score', 0),
        'tls_risk_score': results.get('risk_score', 100),
        'has_tls_issues': len(results.get('critical_issues', [])) > 0,
    }


def demo():
    """Demonstrate TLS analyzer."""
    print("=" * 70)
    print("TLS Security Analyzer Demo")
    print("=" * 70)
    
    test_urls = [
        "https://google.com",
        "https://cloudflare.com",
        "https://github.com",
        "https://stackoverflow.com",
    ]
    
    analyzer = TLSSecurityAnalyzer()
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        print("-" * 70)
        
        try:
            results = analyzer.quick_check(url)
            
            print(f"  HTTPS: {'✓' if results['supports_https'] else '✗'}")
            print(f"  TLS Version: {results['tls_version']}")
            print(f"  TLS Secure: {'✓' if results['tls_secure'] else '✗'}")
            print(f"  Certificate Valid: {'✓' if results['cert_valid'] else '✗'}")
            print(f"  Cert Expires In: {results['cert_expires_in_days']} days")
            print(f"  HSTS Enabled: {'✓' if results['hsts_enabled'] else '✗'}")
            print(f"  CT Logs Found: {'✓' if results['ct_logs_found'] else '✗'}")
            print(f"  Security Score: {results['security_score']}/100")
            print(f"  Risk Score: {results['risk_score']}/100")
            
            if results['warnings']:
                print(f"  Warnings: {len(results['warnings'])}")
            if results['critical_issues']:
                print(f"  Critical: {len(results['critical_issues'])}")
                
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n" + "=" * 70)
    print("Demo complete!")
    print("=" * 70)


if __name__ == "__main__":
    demo()
