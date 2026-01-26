"""
Phishing Detection Service - Core Detection Engine

This is the main service class that orchestrates all phishing detection logic.
It uses a DUAL-MODE approach:

1. ONLINE MODE (Internet Available):
   - Performs full web scraping to analyze actual website content
   - Uses DOM features (forms, inputs, links, title) for accurate detection
   - Ignores static URL heuristics when content is successfully scraped
   - More accurate because it validates the actual website

2. OFFLINE MODE (No Internet):
   - Falls back to static URL feature analysis
   - Uses vowel/consonant patterns, entropy, etc.
   - Less accurate but still useful
   - Clearly marks results as "[OFFLINE MODE]"

The system automatically detects internet connectivity and switches modes.
"""

import sys
import os
import importlib.util
import numpy as np
import joblib
import tldextract
import asyncio

# Add parent directory to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

# Dynamic imports for modules in numbered directories
def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    raise ImportError(f"Cannot load module from {path}")

feature_extraction = load_module('feature_extraction', os.path.join(project_root, '05_utils/feature_extraction.py'))
mllm_transformer = load_module('mllm_transformer', os.path.join(project_root, '05_utils/mllm_transformer.py'))
typosquatting_detector = load_module('typosquatting_detector', os.path.join(project_root, '05_utils/typosquatting_detector.py'))
web_scraper = load_module('web_scraper', os.path.join(project_root, '05_utils/web_scraper.py'))
connectivity = load_module('connectivity', os.path.join(project_root, '05_utils/connectivity.py'))

URLFeatureExtractor = feature_extraction.URLFeatureExtractor
MLLMFeatureTransformer = mllm_transformer.MLLMFeatureTransformer
TyposquattingDetector = typosquatting_detector.TyposquattingDetector
WebScraper = web_scraper.WebScraper
check_internet_connection = connectivity.check_internet_connection
ConnectivityMonitor = connectivity.ConnectivityMonitor

class PhishingDetectionService:
    """
    Main service for phishing detection using MLLM + ML Classifier.
    
    This service implements INTERNET-AWARE detection:
    - When online: Scrapes websites and uses content-based analysis
    - When offline: Falls back to static URL heuristics
    
    The goal is to always use the MOST ACCURATE method available.
    Web scraping (when online) is more accurate than static URL analysis.
    """
    
    # Whitelisted domains for marketing/infrastructure that often have "messy" URLs
    WHITELISTED_DOMAINS = {
        'customeriomail.com', 'sendgrid.net', 'mailchimp.com', 'google.com',
        'github.com', 'microsoft.com', 'cursor.com', 'cursor.sh',
        'amazonaws.com', 'azure.com', 'googleapis.com', 'gstatic.com',
        'slack.com', 'zoom.us', 'atlassian.com', 'linear.app', 'stripe.com'
    }
    
    def __init__(self, load_mllm=False, load_ml_model=True):
        """
        Initialize the phishing detection service.
        
        Args:
            load_mllm: Whether to load the MLLM model (GPU-intensive)
            load_ml_model: Whether to load the ML classifier (recommended)
        """
        self.url_extractor = URLFeatureExtractor()
        self.typosquatting_detector = TyposquattingDetector()
        self.mllm_transformer = None
        self.ml_model = None
        self.ml_scaler = None
        self.ml_feature_cols = None
        self.model_loaded = False
        self.ml_model_loaded = False
        
        # NEW: Initialize connectivity monitor
        self.connectivity_monitor = ConnectivityMonitor(check_interval=30)
        self._is_online = self.connectivity_monitor.is_online
        
        # Log connectivity status
        if self._is_online:
            print("Internet connection: ONLINE - Full multimodal analysis available")
        else:
            print("Internet connection: OFFLINE - Using static URL analysis fallback")
        
        # Load ML classifier (lightweight, fast)
        if load_ml_model:
            try:
                model_dir = os.path.join(project_root, '02_models')
                self.ml_model = joblib.load(os.path.join(model_dir, 'phishing_classifier.joblib'))
                self.ml_scaler = joblib.load(os.path.join(model_dir, 'feature_scaler.joblib'))
                self.ml_feature_cols = joblib.load(os.path.join(model_dir, 'feature_columns.joblib'))
                self.ml_model_loaded = True
                print("ML classifier loaded successfully!")
            except Exception as e:
                print(f"Warning: Could not load ML model: {e}")
                self.ml_model_loaded = False
        
        # Load MLLM (heavy, for explanations)
        if load_mllm:
            try:
                print("Loading MLLM model...")
                self.mllm_transformer = MLLMFeatureTransformer()
                self.model_loaded = True
                print("MLLM model loaded successfully!")
            except Exception as e:
                print(f"Warning: Could not load MLLM model: {e}")
                self.model_loaded = False
    
    @property
    def is_online(self) -> bool:
        """Check current connectivity status."""
        self._is_online = self.connectivity_monitor.is_online
        return self._is_online
    
    @property
    def analysis_mode(self) -> str:
        """Get current analysis mode as string."""
        return "online" if self.is_online else "offline"
    
    def refresh_connectivity(self) -> bool:
        """Force refresh of connectivity status."""
        self._is_online = self.connectivity_monitor.force_refresh()
        return self._is_online
    
    async def analyze_url_async(self, url: str, force_mllm: bool = False) -> dict:
        """
        Analyze a URL for phishing indicators using INTERNET-AWARE detection.
        
        This method automatically chooses the best analysis approach:
        - ONLINE: Full web scraping + content analysis (ignores static heuristics)
        - OFFLINE: Static URL analysis + ML model (uses vowel/consonant checks)
        
        Args:
            url: The URL to analyze
            force_mllm: Force MLLM explanation (only works if MLLM is loaded)
        
        Returns:
            dict: Analysis result with classification, confidence, risk_score, etc.
        """
        # Tier 0: Check Whitelist first (fastest path)
        extracted = tldextract.extract(url)
        domain_part = f"{extracted.domain}.{extracted.suffix}"
        if domain_part in self.WHITELISTED_DOMAINS:
            return self._create_whitelist_result(url, domain_part)
        
        # Check current connectivity status
        is_online = self.is_online
        
        if is_online:
            # ONLINE MODE: Full multimodal scraping analysis
            return await self._analyze_with_scraping(url, force_mllm)
        else:
            # OFFLINE MODE: Static analysis fallback
            return self._analyze_static_fallback(url, force_mllm)
    
    async def _analyze_with_scraping(self, url: str, force_mllm: bool = False) -> dict:
        """
        Full multimodal analysis with web scraping (ONLINE MODE).
        
        This is the PREFERRED analysis method because it:
        1. Validates that the website actually exists and loads
        2. Analyzes the actual page content (forms, inputs, title, etc.)
        3. Ignores static URL heuristics that can cause false positives
        
        A website with a "weird" URL but valid content is likely legitimate.
        """
        # Always check typosquatting first (quick check, very reliable)
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        # If obvious TLD typo (like .pom instead of .com), skip scraping
        if typosquat_result.get('is_typosquatting'):
            if typosquat_result.get('detection_method') in ['faulty_extension', 'invalid_extension', 'invalid_domain_structure']:
                # Clear phishing - invalid domain structure
                return self._create_typosquat_result(url, typosquat_result)
        
        # Attempt web scraping
        print(f"[ONLINE MODE] Scraping {url}...")
        scraper = WebScraper(headless=True, timeout=30000)
        scrape_result = None
        scrape_success = False
        proof = None
        
        try:
            scrape_result = await scraper.scrape_url(url)
            scrape_success = scrape_result.get('success', False)
            
            if scrape_success:
                html_summary = scrape_result.get('dom_structure', {})
                
                # Create proof of scraping
                proof = {
                    'title': html_summary.get('title', 'No Title'),
                    'html_size_bytes': len(scrape_result.get('html', '')),
                    'screenshot_size': scrape_result.get('screenshot').size if scrape_result.get('screenshot') else (0, 0),
                    'num_links': html_summary.get('num_links', 0),
                    'num_images': html_summary.get('num_images', 0),
                    'num_forms': html_summary.get('num_forms', 0),
                    'has_login_form': html_summary.get('has_login_form', False)
                }
                
                print(f"   [SUCCESS] Scraped: {proof['title'][:50]}...")
                print(f"   [PROOF] HTML: {proof['html_size_bytes']} bytes, Links: {proof['num_links']}")
                
                # Use CONTENT-BASED analysis (more accurate)
                return self._analyze_scraped_content(url, scrape_result, typosquat_result, proof, force_mllm)
            else:
                print(f"   [FAILED] Could not scrape {url} - site may be offline")
                # Site is unreachable - this is suspicious for new/unknown URLs
                return self._analyze_unreachable_site(url, typosquat_result)
                
        except Exception as e:
            print(f"   [ERROR] Scraping error: {e}")
            return self._analyze_unreachable_site(url, typosquat_result)
        finally:
            await scraper.close()
    
    def _analyze_scraped_content(self, url: str, scrape_result: dict, typosquat_result: dict, 
                                  proof: dict, force_mllm: bool = False) -> dict:
        """
        Analyze based on ACTUAL SCRAPED CONTENT.
        
        This method does NOT use static URL heuristics like vowel/consonant count
        because we have validated the website content directly.
        
        A website that loads successfully with valid content is more trustworthy
        than what its URL structure might suggest.
        """
        html_summary = scrape_result.get('dom_structure', {})
        
        # Calculate CONTENT-BASED risk score
        risk_score = 0
        risk_factors = []
        
        # Factor 1: Typosquatting (brand impersonation)
        if typosquat_result.get('is_typosquatting'):
            method = typosquat_result.get('detection_method')
            if method not in ['faulty_extension', 'invalid_extension']:
                # Brand impersonation with working site - very suspicious!
                risk_score += 60
                risk_factors.append(f"Brand impersonation detected: {typosquat_result.get('impersonated_brand')}")
        
        # Factor 2: Login form detection
        if html_summary.get('has_login_form'):
            # Having a login form isn't inherently bad, but combined with other factors...
            if typosquat_result.get('is_typosquatting'):
                risk_score += 30
                risk_factors.append("Login form on suspected impersonation site")
        
        # Factor 3: Minimal content (potential phishing landing page)
        num_links = html_summary.get('num_links', 0)
        num_images = html_summary.get('num_images', 0)
        title = html_summary.get('title', '')
        
        if num_links < 3 and num_images < 2 and not title:
            risk_score += 20
            risk_factors.append("Minimal page content (potential phishing landing page)")
        
        # Factor 4: Too many forms/inputs (credential harvesting)
        num_forms = html_summary.get('num_forms', 0)
        num_inputs = html_summary.get('num_inputs', 0)
        
        if num_forms > 3 or num_inputs > 10:
            risk_score += 15
            risk_factors.append("Excessive form inputs detected")
        
        # Factor 5: Suspicious iframe usage
        if html_summary.get('num_iframes', 0) > 2:
            risk_score += 10
            risk_factors.append("Multiple iframes detected")
        
        # Factor 6: ML model prediction (if loaded)
        url_features = self.url_extractor.extract_features(url)
        ml_prediction = None
        ml_confidence = 0.5
        
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
            if ml_prediction == 1 and ml_confidence >= 0.9:
                # High confidence ML prediction - add to risk
                risk_score += int(ml_confidence * 30)
                risk_factors.append(f"ML model predicts phishing ({ml_confidence*100:.1f}% confidence)")
        
        # CREDIBILITY BONUS: Valid website with substantial content
        # This is the KEY DIFFERENCE from static analysis
        if num_links >= 10 and title and len(title) > 3:
            # Significant content = likely legitimate
            old_risk = risk_score
            risk_score = max(0, risk_score - 40)
            if old_risk > risk_score:
                risk_factors.append(f"Content validation bonus: -40 (substantial page content)")
        
        # Determine classification
        risk_score = min(100, max(0, risk_score))
        
        if typosquat_result.get('is_typosquatting') and typosquat_result.get('detection_method') != 'subdomain_attack':
            classification = "phishing"
            confidence = 0.85
            recommended_action = "block" if risk_score >= 50 else "warn"
        elif risk_score >= 70:
            classification = "phishing"
            confidence = 0.9
            recommended_action = "block"
        elif risk_score >= 40:
            classification = "phishing"
            confidence = 0.7
            recommended_action = "warn"
        else:
            classification = "legitimate"
            confidence = 0.85
            recommended_action = "allow"
        
        # Generate explanation
        if risk_factors:
            explanation = "Analysis based on scraped content: " + "; ".join(risk_factors)
        else:
            explanation = "Website content validated. No suspicious indicators found."
        
        # MLLM explanation if requested and loaded
        if force_mllm and self.mllm_transformer:
            try:
                metadata = {
                    'url': url,
                    'url_features': url_features,
                    'typosquatting': typosquat_result,
                    'html_summary': html_summary
                }
                explanation = self.mllm_transformer.transform_to_text(metadata)
            except Exception:
                pass  # Keep rule-based explanation
        
        # Add typosquatting info to features
        url_features['typosquatting'] = typosquat_result
        
        return {
            'url': url,
            'classification': classification,
            'confidence': round(confidence, 3),
            'risk_score': round(risk_score, 2),
            'explanation': explanation,
            'features': url_features,
            'recommended_action': recommended_action,
            'ml_model_used': self.ml_model_loaded,
            'mllm_used': force_mllm and self.model_loaded,
            'scraped': True,
            'scrape_proof': proof,
            'analysis_mode': 'online'
        }
    
    def _analyze_unreachable_site(self, url: str, typosquat_result: dict) -> dict:
        """
        Handle case where website could not be scraped.
        
        An unreachable site could be:
        1. A taken-down phishing site (suspicious)
        2. A temporarily offline legitimate site (less suspicious)
        3. A typo in the URL (neutral)
        
        We err on the side of caution and flag as suspicious.
        """
        url_features = self.url_extractor.extract_features(url)
        
        risk_score = 30  # Base risk for unreachable site
        
        # Typosquatting increases risk significantly
        if typosquat_result.get('is_typosquatting'):
            risk_score += typosquat_result.get('risk_increase', 40)
        
        # Use static heuristics as backup (only for unreachable sites)
        if url_features.get('is_random_domain'):
            risk_score += 25  # Reduced from 45 because site is unreachable anyway
        
        if url_features.get('is_ip_address'):
            risk_score += 15
        
        risk_score = min(100, risk_score)
        
        if risk_score >= 60:
            classification = "phishing"
            recommended_action = "block"
            confidence = 0.7
        elif risk_score >= 35:
            classification = "phishing"
            recommended_action = "warn"
            confidence = 0.6
        else:
            classification = "legitimate"
            recommended_action = "allow"
            confidence = 0.5  # Low confidence because we couldn't verify
        
        explanation = "Website is unreachable. "
        if typosquat_result.get('is_typosquatting'):
            explanation += f"Suspicious URL pattern detected: {typosquat_result.get('detection_method')}. "
        explanation += "Could be a taken-down phishing site or temporarily offline."
        
        url_features['typosquatting'] = typosquat_result
        
        return {
            'url': url,
            'classification': classification,
            'confidence': round(confidence, 3),
            'risk_score': round(risk_score, 2),
            'explanation': explanation,
            'features': url_features,
            'recommended_action': recommended_action,
            'ml_model_used': False,
            'mllm_used': False,
            'scraped': False,
            'scrape_proof': None,
            'analysis_mode': 'online_failed'
        }
    
    def _analyze_static_fallback(self, url: str, force_mllm: bool = False) -> dict:
        """
        Static analysis when OFFLINE (no internet connection).
        
        This uses the traditional heuristics including:
        - Vowel/consonant patterns
        - URL entropy
        - Character analysis
        - ML model prediction
        
        Results are marked with "[OFFLINE MODE]" to indicate lower confidence.
        """
        print(f"[OFFLINE MODE] Static analysis for {url}...")
        
        # Extract URL features (includes vowel/consonant analysis)
        url_features = self.url_extractor.extract_features(url)
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        # Check for clear typosquatting first
        if typosquat_result.get('is_typosquatting'):
            if typosquat_result.get('detection_method') in ['faulty_extension', 'invalid_extension', 'invalid_domain_structure']:
                return self._create_typosquat_result(url, typosquat_result, offline=True)
        
        # ML Model prediction
        ml_prediction = None
        ml_confidence = 0.5
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
        
        # Calculate risk score using ALL static heuristics
        risk_score = self._calculate_risk_score(url_features, typosquat_result, ml_prediction, ml_confidence)
        
        # Determine classification
        if typosquat_result.get('is_typosquatting'):
            classification = "phishing"
            confidence = max(0.85, ml_confidence) if ml_prediction == 1 else 0.85
            recommended_action = "block" if risk_score >= 50 else "warn"
        elif risk_score >= 40:
            classification = "phishing"
            confidence = 0.75
            recommended_action = "block" if risk_score >= 60 else "warn"
        elif ml_prediction is not None:
            classification = "phishing" if ml_prediction == 1 else "legitimate"
            confidence = ml_confidence
            recommended_action = "block" if (classification == "phishing" and confidence >= 0.8) else ("warn" if classification == "phishing" else "allow")
        else:
            classification = "phishing" if risk_score >= 35 else "legitimate"
            confidence = 0.7 if classification == "phishing" else 0.8
            recommended_action = "block" if risk_score >= 70 else ("warn" if risk_score >= 35 else "allow")
        
        # Generate explanation
        explanation = self._generate_rule_based_analysis(url_features, typosquat_result)
        explanation = f"[OFFLINE MODE] {explanation}"
        
        # MLLM explanation if available (unlikely offline, but possible)
        if force_mllm and self.mllm_transformer:
            try:
                metadata = {'url': url, 'url_features': url_features, 'typosquatting': typosquat_result}
                explanation = f"[OFFLINE MODE] {self.mllm_transformer.transform_to_text(metadata)}"
            except Exception:
                pass
        
        url_features['typosquatting'] = typosquat_result
        
        return {
            'url': url,
            'classification': classification,
            'confidence': round(confidence * 0.9, 3),  # Reduce confidence for offline mode
            'risk_score': round(risk_score, 2),
            'explanation': explanation,
            'features': url_features,
            'recommended_action': recommended_action,
            'ml_model_used': self.ml_model_loaded,
            'mllm_used': force_mllm and self.model_loaded,
            'scraped': False,
            'scrape_proof': None,
            'analysis_mode': 'offline'
        }
    
    def _create_whitelist_result(self, url: str, domain_part: str) -> dict:
        """Create result for whitelisted domains."""
        return {
            'url': url,
            'classification': 'legitimate',
            'confidence': 1.0,
            'risk_score': 0,
            'explanation': f"Domain '{domain_part}' is in the trusted whitelist.",
            'features': {},
            'recommended_action': 'allow',
            'ml_model_used': False,
            'mllm_used': False,
            'scraped': False,
            'scrape_proof': None,
            'analysis_mode': 'whitelist'
        }
    
    def _create_typosquat_result(self, url: str, typosquat_result: dict, offline: bool = False) -> dict:
        """Create result for clear typosquatting detections."""
        method = typosquat_result.get('detection_method', 'unknown')
        details = typosquat_result.get('details', ['Invalid domain detected'])[0]
        
        mode_prefix = "[OFFLINE MODE] " if offline else ""
        
        return {
            'url': url,
            'classification': 'phishing',
            'confidence': 0.95,
            'risk_score': 90,
            'explanation': f"{mode_prefix}INVALID DOMAIN: {details}",
            'features': {'typosquatting': typosquat_result},
            'recommended_action': 'block',
            'ml_model_used': False,
            'mllm_used': False,
            'scraped': False,
            'scrape_proof': None,
            'analysis_mode': 'offline' if offline else 'online'
        }
    
    def analyze_url(self, url: str, force_mllm: bool = False) -> dict:
        """
        Synchronous version of URL analysis.
        
        This is a wrapper around analyze_url_async for backward compatibility.
        It uses asyncio.run() to execute the async version.
        
        For best performance in async contexts, use analyze_url_async directly.
        """
        return asyncio.get_event_loop().run_until_complete(
            self.analyze_url_async(url, force_mllm)
        )
    
    def _predict_with_ml(self, features: dict) -> tuple:
        """Use ML model to predict phishing probability."""
        try:
            # Create feature vector in correct order
            feature_vector = []
            for col in self.ml_feature_cols:
                val = features.get(col, 0)
                # Convert numpy types to python types
                if hasattr(val, 'item'):
                    val = val.item()
                feature_vector.append(val if val is not None else 0)
            
            X = np.array([feature_vector])
            X = np.nan_to_num(X, nan=0.0)
            X_scaled = self.ml_scaler.transform(X)
            
            prediction = self.ml_model.predict(X_scaled)[0]
            probability = self.ml_model.predict_proba(X_scaled)[0]
            confidence = max(probability)
            
            return int(prediction), float(confidence)
        except Exception as e:
            print(f"ML prediction error: {e}")
            return None, 0.5
    
    def _calculate_risk_score(self, features: dict, typosquat: dict = None, ml_pred: int = None, ml_conf: float = 0.5) -> float:
        """
        Calculate risk score based on URL features (0-100).
        
        This is the STATIC analysis method used when:
        1. We're in offline mode
        2. Web scraping failed
        
        It uses vowel/consonant patterns and other heuristics.
        """
        score = 0
        
        # ML Model prediction is the strongest signal
        if ml_pred == 1:
            score += int(ml_conf * 50)  # Up to 50 points based on confidence
        
        # TYPOSQUATTING - Major risk indicator
        if typosquat and typosquat.get('is_typosquatting'):
            score += typosquat.get('risk_increase', 50)
        
        # Length-based risks
        if features.get('url_length', 0) > 75:
            score += 10
        if features.get('path_length', 0) > 50:
            score += 5
            
        # Suspicious patterns
        if features.get('is_ip_address', 0):
            score += 20
        
        # Suspicious words
        suspicious_count = features.get('has_suspicious_words', 0)
        if suspicious_count > 0:
            score += min(20, suspicious_count * 5)
            
        if not features.get('is_https', 0):
            score += 10
            
        # Entropy (randomness in URL)
        entropy = features.get('entropy', 0)
        if entropy > 4.5:
            score += 10
            
        # Domain Entropy (Specific check for random string domains)
        domain_entropy = features.get('domain_entropy', 0)
        is_random = features.get('is_random_domain', 0)
        
        if is_random:
            score += 45  # High penalty for randomness (almost certainly phishing/DGA)
        if domain_entropy > 3.5:
            score += 15  # Extra penalty for very high entropy
            
        # Character-based risks
        if features.get('num_hyphens', 0) > 3:
            score += 10
        if features.get('subdomain_count', 0) > 2:
            score += 10
        if features.get('num_at', 0) > 0:
            score += 15
            
        return min(100, score)
    
    def _generate_rule_based_analysis(self, features: dict, typosquat: dict = None) -> str:
        """Fallback rule-based analysis when MLLM is not available."""
        issues = []
        
        # Typosquatting is the most important indicator
        if typosquat and typosquat.get('is_typosquatting'):
            method = typosquat.get('detection_method', 'unknown')
            if method == 'faulty_extension':
                details = typosquat.get('details', ["Faulty extension detected"])[0]
                issues.append(details)
            elif method == 'invalid_domain_structure' or method == 'invalid_extension':
                details = typosquat.get('details', ["Invalid domain detected"])[0]
                issues.append(details)
            else:
                brand = typosquat.get('impersonated_brand', 'unknown')
                issues.append(f"BRAND IMPERSONATION: Attempting to mimic '{brand}' ({method})")
        
        if features.get('is_random_domain', 0):
            if features.get('is_ip_address'):
                issues.append("URL uses an IP address instead of domain name")
            else:
                issues.append("High entropy domain name with no recognizable pattern")
            
        if not features.get('is_https'):
            issues.append("Connection is not secure (no HTTPS)")
        if features.get('has_suspicious_words', 0) > 0:
            issues.append("URL contains suspicious keywords like 'login', 'verify', 'account'")
            
        if issues:
            return "Suspicious indicators found: " + "; ".join(issues)
        else:
            return "No obvious phishing indicators detected based on URL structure."
