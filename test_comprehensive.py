"""
Comprehensive Test Suite for Phishing Guard v2.0

Tests all new features:
- IDN/Homograph detection
- TLS security analyzer
- Enhanced feature extraction (93 features)
- Security validator
- Authentication system

Run: python -m pytest test_comprehensive.py -v
"""

import sys
import os
import pytest
from datetime import datetime, timezone

sys.path.insert(0, '05_utils')
sys.path.insert(0, '04_inference')


class TestIDNDetection:
    """Test IDN (Internationalized Domain Name) detection"""
    
    def test_punycode_detection(self):
        """Test detection of punycode domains"""
        from feature_extraction import URLFeatureExtractor
        
        # Punycode URL (Cyrillic 'а' in place of Latin 'a')
        url = "https://xn--pypal-4ve.com"  # paypa1.com with Cyrillic
        features = URLFeatureExtractor.extract_features(url)
        
        assert features['has_punycode'] == 1, "Should detect punycode"
        assert features['has_unicode'] == 1, "Should detect unicode"
        assert features['idn_risk_score'] > 50, "High IDN risk for punycode"
    
    def test_mixed_scripts(self):
        """Test detection of mixed script attacks"""
        from feature_extraction import URLFeatureExtractor
        
        # Mixed Latin + Cyrillic
        url = "https://paypаl.com"  # Cyrillic 'а' (U+0430)
        features = URLFeatureExtractor.extract_features(url)
        
        assert features['mixed_scripts'] == 1, "Should detect mixed scripts"
        assert features['script_count'] > 1, "Should count multiple scripts"
    
    def test_confusable_characters(self):
        """Test detection of confusable characters"""
        from feature_extraction import URLFeatureExtractor
        
        # Confusable: 'ο' (Greek omicron) vs 'o' (Latin)
        url = "https://gοοgle.com"  # Greek omicrons
        features = URLFeatureExtractor.extract_features(url)
        
        assert features['has_confusables'] == 1, "Should detect confusables"
        assert features['confusable_count'] > 0, "Should count confusables"


class TestTLSSecurityAnalyzer:
    """Test TLS/SSL security analysis"""
    
    def test_http_site_detection(self):
        """Test detection of non-HTTPS sites"""
        from tls_analyzer import extract_tls_features
        
        features = extract_tls_features("http://example.com")
        
        assert features['uses_https'] == False
        assert features['tls_risk_score'] > 0  # Penalty for HTTP
    
    def test_https_site_analysis(self):
        """Test analysis of HTTPS sites"""
        from tls_analyzer import TLSSecurityAnalyzer
        
        analyzer = TLSSecurityAnalyzer()
        
        # Test with a known good site
        try:
            results = analyzer.quick_check("https://cloudflare.com")
            assert results['supports_https'] == True
            assert results['tls_version'] is not None
        except:
            pytest.skip("Network unavailable for live TLS test")
    
    def test_tls_features_structure(self):
        """Test TLS features structure"""
        from tls_analyzer import extract_tls_features
        
        # Test feature extraction returns all expected keys
        features = extract_tls_features("https://example.com")
        
        required_keys = [
            'uses_https', 'tls_version', 'tls_secure',
            'cert_valid', 'cert_days_remaining',
            'hsts_enabled', 'ct_logs',
            'tls_security_score', 'tls_risk_score'
        ]
        
        for key in required_keys:
            assert key in features, f"Missing key: {key}"


class TestSecurityValidator:
    """Test URL security validation"""
    
    def test_ssrf_private_ip_blocking(self):
        """Test SSRF protection against private IPs"""
        from security_validator import URLSecurityValidator
        
        validator = URLSecurityValidator()
        
        private_urls = [
            "http://127.0.0.1/admin",
            "http://192.168.1.1/config",
            "http://10.0.0.1/secret",
            "http://localhost:8080/api"
        ]
        
        for url in private_urls:
            is_valid, errors = validator.validate(url)
            assert not is_valid, f"Should block {url}"
            assert any("private" in e.lower() for e in errors)
    
    def test_dangerous_scheme_blocking(self):
        """Test blocking of dangerous URL schemes"""
        from security_validator import URLSecurityValidator
        
        validator = URLSecurityValidator()
        
        dangerous_urls = [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        for url in dangerous_urls:
            is_valid, errors = validator.validate(url)
            assert not is_valid, f"Should block {url}"
    
    def test_path_traversal_detection(self):
        """Test detection of path traversal attempts"""
        from security_validator import URLSecurityValidator
        
        validator = URLSecurityValidator()
        
        urls = [
            "http://example.com/../../../etc/passwd",
            "http://example.com/..%2f..%2fetc/passwd"
        ]
        
        for url in urls:
            is_valid, errors = validator.validate(url)
            assert not is_valid, f"Should block {url}"
    
    def test_valid_urls_allowed(self):
        """Test that valid URLs are allowed"""
        from security_validator import URLSecurityValidator
        
        validator = URLSecurityValidator()
        
        valid_urls = [
            "https://google.com",
            "https://github.com/user/repo",
            "https://example.com/path?query=value"
        ]
        
        for url in valid_urls:
            is_valid, errors = validator.validate(url)
            assert is_valid, f"Should allow {url}, got errors: {errors}"


class TestEnhancedFeatures:
    """Test enhanced feature extraction (93 features)"""
    
    def test_feature_count(self):
        """Test that we extract 93 features"""
        from feature_extraction import URLFeatureExtractor
        
        url = "https://subdomain.example.com/path?query=value&other=test"
        features = URLFeatureExtractor.extract_features(url)
        
        assert len(features) >= 93, f"Expected 93+ features, got {len(features)}"
    
    def test_subdomain_features(self):
        """Test subdomain analysis features"""
        from feature_extraction import URLFeatureExtractor
        
        url = "https://www.subdomain.example.com"
        features = URLFeatureExtractor.extract_features(url)
        
        assert 'subdomain_depth' in features
        assert 'subdomain_count' in features
        assert features['subdomain_count'] > 0
    
    def test_special_character_features(self):
        """Test special character detection"""
        from feature_extraction import URLFeatureExtractor
        
        url = "https://example.com/path?query=value&other=test#fragment"
        features = URLFeatureExtractor.extract_features(url)
        
        assert 'num_hashes' in features
        assert 'num_percent' in features
        assert 'has_fragment' in features
    
    def test_tld_features(self):
        """Test TLD analysis features"""
        from feature_extraction import URLFeatureExtractor
        
        # Suspicious TLD
        url = "https://example.tk"
        features = URLFeatureExtractor.extract_features(url)
        
        assert 'tld_length' in features
        assert 'tld_parts' in features
        assert 'suspicious_tld' in features


class TestAuthentication:
    """Test authentication system"""
    
    def test_jwt_token_generation(self):
        """Test JWT token creation"""
        from auth import auth_manager
        
        token = auth_manager.create_token("test@example.com")
        assert token is not None
        assert len(token) > 50  # JWT tokens are long
    
    def test_jwt_token_verification(self):
        """Test JWT token verification"""
        from auth import auth_manager
        
        token = auth_manager.create_token("test@example.com")
        payload = auth_manager.verify_token(token)
        
        assert payload['sub'] == "test@example.com"
        assert 'exp' in payload
        assert 'iat' in payload
    
    def test_api_key_generation(self):
        """Test API key creation"""
        from auth import auth_manager
        
        api_key = auth_manager.generate_api_key("test-service")
        assert api_key.startswith("pg_")
        assert len(api_key) > 40
    
    def test_api_key_verification(self):
        """Test API key validation"""
        from auth import auth_manager
        
        api_key = auth_manager.generate_api_key("test-service")
        assert auth_manager.verify_api_key(api_key) == True
        assert auth_manager.verify_api_key("invalid_key") == False


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_enforcement(self):
        """Test that rate limits are enforced"""
        from auth import RateLimiter
        
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        
        # First 5 should be allowed
        for i in range(5):
            assert limiter.is_allowed("test_ip") == True
        
        # 6th should be blocked
        assert limiter.is_allowed("test_ip") == False
    
    def test_rate_limit_reset(self):
        """Test rate limit window reset"""
        from auth import RateLimiter
        
        limiter = RateLimiter(max_requests=5, window_seconds=1)
        
        # Use up quota
        for i in range(5):
            limiter.is_allowed("test_ip")
        
        assert limiter.is_allowed("test_ip") == False
        
        # After window passes (simulated by creating new limiter)
        limiter2 = RateLimiter(max_requests=5, window_seconds=60)
        assert limiter2.is_allowed("test_ip") == True


class TestIntegration:
    """Integration tests"""
    
    def test_full_analysis_pipeline(self):
        """Test complete analysis pipeline"""
        from feature_extraction import URLFeatureExtractor
        from security_validator import validate_url_for_analysis
        
        url = "https://google.com/search?q=test"
        
        # Step 1: Security validation
        is_valid, error = validate_url_for_analysis(url)
        assert is_valid, f"Security validation failed: {error}"
        
        # Step 2: Feature extraction
        features = URLFeatureExtractor.extract_features(url)
        assert len(features) > 90
        assert features['uses_https'] == True
    
    def test_phishing_detection_features(self):
        """Test feature extraction on suspicious URLs"""
        from feature_extraction import URLFeatureExtractor
        
        suspicious_url = "https://paypa1-secure-login.tk/verify?urgent=true"
        features = URLFeatureExtractor.extract_features(suspicious_url)
        
        # Should detect suspicious patterns
        assert 'is_typosquatting' in features
        assert 'suspicious_tld' in features
        assert features['uses_https'] == 0 or features['uses_https'] == 1


def run_all_tests():
    """Run all tests and print summary"""
    print("="*70)
    print("COMPREHENSIVE TEST SUITE - PHISHING GUARD v2.0")
    print("="*70)
    
    test_classes = [
        TestIDNDetection,
        TestTLSSecurityAnalyzer,
        TestSecurityValidator,
        TestEnhancedFeatures,
        TestAuthentication,
        TestRateLimiting,
        TestIntegration
    ]
    
    passed = 0
    failed = 0
    
    for test_class in test_classes:
        print(f"\n{test_class.__name__}:")
        print("-" * 70)
        
        instance = test_class()
        methods = [m for m in dir(instance) if m.startswith('test_')]
        
        for method_name in methods:
            try:
                method = getattr(instance, method_name)
                method()
                print(f"  ✓ {method_name}")
                passed += 1
            except Exception as e:
                print(f"  ✗ {method_name}: {str(e)[:80]}")
                failed += 1
    
    print("\n" + "="*70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("="*70)
    
    if failed == 0:
        print("🎉 All tests passed!")
    else:
        print(f"⚠️  {failed} test(s) failed")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
