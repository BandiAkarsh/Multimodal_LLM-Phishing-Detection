"""
Phishing Detection Service - Core Detection Engine with 4-Category Classification

CRITICAL DESIGN PRINCIPLE:
When ONLINE, content-based analysis ALWAYS takes precedence over static URL analysis.
This prevents false positives like "kotaksalesianschool-vizag.com" being flagged
as phishing just because it contains "kotak" in the domain name.

Classification Categories:
1. LEGITIMATE - Safe, authentic website
2. PHISHING - Traditional manually-created phishing attack
3. AI_GENERATED_PHISHING - Phishing created using AI tools (ChatGPT, etc.)
4. PHISHING_KIT - Phishing created using toolkits (Gophish, HiddenEye, etc.)

Detection Modes:
1. ONLINE MODE (Internet Available):
   - Performs full web scraping to analyze actual website content
   - Content verification OVERRIDES static brand detection
   - Detects toolkit signatures (Gophish ?rid= params, form structures)
   - Uses MLLM to detect AI-generated content
   - Most accurate classification

2. OFFLINE MODE (No Internet):
   - Falls back to static URL feature analysis
   - Can only classify as LEGITIMATE or PHISHING
   - Cannot detect AI-generated or toolkit-based attacks
   - Results marked as "[OFFLINE MODE]"
"""

import sys
import os
import importlib.util
import numpy as np
import joblib
import tldextract
import asyncio
from enum import Enum
from typing import Dict, Any, Optional, Tuple

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
ThreatCategory = mllm_transformer.ThreatCategory
TyposquattingDetector = typosquatting_detector.TyposquattingDetector
WebScraper = web_scraper.WebScraper
ToolkitSignatureDetector = web_scraper.ToolkitSignatureDetector
check_internet_connection = connectivity.check_internet_connection
ConnectivityMonitor = connectivity.ConnectivityMonitor


class PhishingDetectionService:
    """
    Main service for phishing detection with 4-category classification.
    
    IMPORTANT: Content-based analysis takes precedence over static detection
    when online. This prevents false positives for legitimate sites that
    happen to contain brand keywords in their domain names.
    """
    
    # Whitelisted domains
    WHITELISTED_DOMAINS = {
        'customeriomail.com', 'sendgrid.net', 'mailchimp.com', 'google.com',
        'github.com', 'microsoft.com', 'cursor.com', 'cursor.sh',
        'amazonaws.com', 'azure.com', 'googleapis.com', 'gstatic.com',
        'slack.com', 'zoom.us', 'atlassian.com', 'linear.app', 'stripe.com'
    }
    
    def __init__(self, load_mllm=False, load_ml_model=True):
        """Initialize the phishing detection service."""
        self.url_extractor = URLFeatureExtractor()
        self.typosquatting_detector = TyposquattingDetector()
        self.mllm_transformer = None
        self.ml_model = None
        self.ml_scaler = None
        self.ml_feature_cols = None
        self.model_loaded = False
        self.ml_model_loaded = False
        
        # Initialize connectivity monitor
        self.connectivity_monitor = ConnectivityMonitor(check_interval=30)
        self._is_online = self.connectivity_monitor.is_online
        
        # Log connectivity status
        if self._is_online:
            print("Internet connection: ONLINE - Full 4-category classification available")
        else:
            print("Internet connection: OFFLINE - Limited to LEGITIMATE/PHISHING classification")
        
        # Load ML classifier (with MLflow support)
        if load_ml_model:
            try:
                # Try MLflow first
                try:
                    sys.path.insert(0, os.path.join(project_root, '03_training'))
                    from model_manager import ModelManager
                    
                    model_manager = ModelManager()
                    self.ml_model = model_manager.load_model("phishing_classifier")
                    print("✓ ML model loaded from MLflow registry")
                    
                    # Load scaler and columns from joblib (not versioned in MLflow)
                    model_dir = os.path.join(project_root, '02_models')
                    self.ml_scaler = joblib.load(os.path.join(model_dir, 'feature_scaler.joblib'))
                    self.ml_feature_cols = joblib.load(os.path.join(model_dir, 'feature_columns.joblib'))
                    
                except Exception as mlflow_error:
                    print(f"Note: MLflow loading failed ({mlflow_error}), falling back to joblib...")
                    
                    # Fallback to joblib
                    model_dir = os.path.join(project_root, '02_models')
                    self.ml_model = joblib.load(os.path.join(model_dir, 'phishing_classifier.joblib'))
                    self.ml_scaler = joblib.load(os.path.join(model_dir, 'feature_scaler.joblib'))
                    self.ml_feature_cols = joblib.load(os.path.join(model_dir, 'feature_columns.joblib'))
                    print("✓ ML model loaded from joblib (fallback)")
                
                self.ml_model_loaded = True
                
            except Exception as e:
                print(f"Warning: Could not load ML model: {e}")
                self.ml_model_loaded = False
        
        # Load MLLM
        if load_mllm:
            try:
                print("Loading MLLM model for AI-generated content detection...")
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
        Analyze a URL for phishing indicators with 4-category classification.
        
        PRIORITY ORDER:
        1. Whitelist check (fastest)
        2. For ONLINE mode: Scrape FIRST, then verify static detection with content
        3. For OFFLINE mode: Use static analysis only
        """
        # Tier 0: Check Whitelist first
        extracted = tldextract.extract(url)
        domain_part = f"{extracted.domain}.{extracted.suffix}"
        if domain_part in self.WHITELISTED_DOMAINS:
            return self._create_whitelist_result(url, domain_part)
        
        # Check connectivity
        is_online = self.is_online
        
        if is_online:
            # ONLINE MODE: Scrape first, then verify
            return await self._analyze_with_scraping(url, force_mllm)
        else:
            # OFFLINE MODE: Static analysis only
            return self._analyze_static_fallback(url, force_mllm)
    
    async def _analyze_with_scraping(self, url: str, force_mllm: bool = False) -> dict:
        """
        Full multimodal analysis (ONLINE MODE).
        
        CRITICAL: We scrape FIRST, then use content to verify/override static detection.
        This prevents false positives like schools being flagged as bank phishing.
        """
        print(f"[ONLINE MODE] Analyzing {url}...")
        
        # Attempt web scraping FIRST
        scraper = WebScraper(headless=True, timeout=30000)
        scrape_result = None
        scrape_success = False
        proof = None
        
        try:
            scrape_result = await scraper.scrape_url(url)
            scrape_success = scrape_result.get('success', False)
            
            if scrape_success:
                html_summary = scrape_result.get('dom_structure', {})
                toolkit_signatures = scrape_result.get('toolkit_signatures', {})
                page_title = html_summary.get('title', '')
                text_content = scrape_result.get('text_content', '')
                
                # Create proof
                proof = {
                    'title': page_title[:60] if page_title else 'No Title',
                    'html_size_bytes': len(scrape_result.get('html', '')),
                    'screenshot_size': scrape_result.get('screenshot').size if scrape_result.get('screenshot') else (0, 0),
                    'num_links': html_summary.get('num_links', 0),
                    'num_images': html_summary.get('num_images', 0),
                    'num_forms': html_summary.get('num_forms', 0),
                    'has_login_form': html_summary.get('has_login_form', False),
                    'toolkit_detected': toolkit_signatures.get('detected', False),
                    'toolkit_name': toolkit_signatures.get('toolkit_name', None),
                }
                
                print(f"   [SUCCESS] Scraped: {proof['title']}")
                
                # NOW do typosquatting check WITH content verification
                typosquat_result = self.typosquatting_detector.analyze(url)
                
                # If typosquatting was detected but content verification is available
                if typosquat_result.get('requires_content_verification') and page_title:
                    typosquat_result = self.typosquatting_detector.verify_with_content(
                        typosquat_result, page_title, text_content
                    )
                    if typosquat_result.get('content_verified') and not typosquat_result.get('is_typosquatting'):
                        print(f"   [CONTENT OK] {typosquat_result.get('verification_reason', 'Content verified')}")
                
                # Only skip to typosquat result for STRUCTURAL issues (TLD typos)
                if typosquat_result.get('is_typosquatting'):
                    method = typosquat_result.get('detection_method')
                    if method in ['faulty_extension', 'invalid_extension', 'invalid_domain_structure']:
                        return self._create_typosquat_result(url, typosquat_result)
                
                # Use CONTENT-BASED 4-category classification
                return self._analyze_scraped_content_4cat(
                    url, scrape_result, typosquat_result, proof, force_mllm
                )
            else:
                print(f"   [FAILED] Could not scrape {url}")
                # Scrape failed - now use static analysis with typosquatting
                typosquat_result = self.typosquatting_detector.analyze(url)
                return self._analyze_unreachable_site(url, typosquat_result)
                
        except Exception as e:
            print(f"   [ERROR] Scraping error: {e}")
            typosquat_result = self.typosquatting_detector.analyze(url)
            return self._analyze_unreachable_site(url, typosquat_result)
        finally:
            await scraper.close()
    
    def _analyze_scraped_content_4cat(self, url: str, scrape_result: dict, 
                                       typosquat_result: dict, proof: dict,
                                       force_mllm: bool = False) -> dict:
        """
        Analyze scraped content with 4-category classification.
        
        Priority Order:
        1. PHISHING_KIT - Toolkit signatures (highest confidence)
        2. AI_GENERATED_PHISHING - AI content patterns
        3. Content-verified legitimate (overrides static detection)
        4. PHISHING - Traditional phishing indicators
        5. LEGITIMATE - No threats
        """
        html_summary = scrape_result.get('dom_structure', {})
        toolkit_signatures = scrape_result.get('toolkit_signatures', {})
        text_content = scrape_result.get('text_content', '')
        html_content = scrape_result.get('html', '')
        page_title = html_summary.get('title', '')
        
        # Initialize
        classification = 'legitimate'
        confidence = 0.85
        risk_score = 0
        risk_factors = []
        
        # ========== PRIORITY 1: TOOLKIT DETECTION ==========
        if toolkit_signatures.get('detected'):
            classification = 'phishing_kit'
            confidence = toolkit_signatures.get('confidence', 0.85)
            risk_score = 85 + (confidence * 15)
            
            toolkit_name = toolkit_signatures.get('toolkit_name', 'Unknown')
            signatures = toolkit_signatures.get('signatures_found', [])
            
            risk_factors.append(f"PHISHING KIT DETECTED: {toolkit_name}")
            for sig in signatures[:3]:
                risk_factors.append(f"  - {sig}")
            
            explanation = f"Phishing toolkit detected: {toolkit_name}. " + \
                         f"Found {len(signatures)} toolkit signatures."
            
            return self._build_result(
                url=url,
                classification=classification,
                confidence=round(min(0.99, confidence), 3),
                risk_score=round(min(100, risk_score), 2),
                explanation=explanation,
                features=self.url_extractor.extract_features(url),
                typosquat_result=typosquat_result,
                recommended_action='block',
                scraped=True,
                proof=proof,
                analysis_mode='online',
                toolkit_signatures=toolkit_signatures
            )
        
        # ========== PRIORITY 2: AI-GENERATED CONTENT DETECTION ==========
        ai_score, ai_indicators = self._lightweight_ai_detection(text_content, html_summary)
        
        if ai_score >= 0.5:
            classification = 'ai_generated_phishing'
            confidence = max(0.7, ai_score)
            risk_score = 65 + (ai_score * 30)
            
            explanation = "AI-generated content patterns detected: " + "; ".join(ai_indicators[:3])
            
            return self._build_result(
                url=url,
                classification=classification,
                confidence=round(confidence, 3),
                risk_score=round(risk_score, 2),
                explanation=explanation,
                features=self.url_extractor.extract_features(url),
                typosquat_result=typosquat_result,
                recommended_action='warn',
                scraped=True,
                proof=proof,
                analysis_mode='online',
                ai_indicators=ai_indicators
            )
        
        # ========== PRIORITY 3: CONTENT-VERIFIED LEGITIMATE ==========
        # If content verification cleared the typosquatting flag, trust it
        if typosquat_result.get('content_verified') and not typosquat_result.get('is_typosquatting'):
            return self._build_result(
                url=url,
                classification='legitimate',
                confidence=0.85,
                risk_score=10,
                explanation=f"Content verified: {typosquat_result.get('verification_reason', 'Page content matches legitimate business')}",
                features=self.url_extractor.extract_features(url),
                typosquat_result=typosquat_result,
                recommended_action='allow',
                scraped=True,
                proof=proof,
                analysis_mode='online'
            )
        
        # ========== PRIORITY 4: TRADITIONAL PHISHING ANALYSIS ==========
        return self._analyze_traditional_phishing(
            url, scrape_result, typosquat_result, proof, force_mllm, ai_score
        )
    
    def _lightweight_ai_detection(self, text_content: str, html_summary: dict) -> Tuple[float, list]:
        """Lightweight AI-generated content detection without MLLM."""
        if not text_content:
            return 0.0, []
        
        text_lower = text_content.lower()
        score = 0.0
        indicators = []
        
        # AI-typical phrases
        ai_phrases = [
            ('as an ai', 0.15), ('i cannot', 0.1), ('it is important to', 0.1),
            ('please note that', 0.1), ('in conclusion', 0.08), ('furthermore', 0.08),
            ('moreover', 0.08), ('at the end of the day', 0.1), ('needless to say', 0.1),
        ]
        
        for phrase, weight in ai_phrases:
            if phrase in text_lower:
                score += weight
                indicators.append(f"AI phrase: '{phrase}'")
        
        # Urgency language
        import re
        urgency_patterns = [
            (r'immediately|urgent|expires|suspended|locked|verify now|act now', 0.15),
            (r'your account (?:has been|will be) (?:suspended|locked|terminated)', 0.2),
            (r'failure to (?:verify|respond|confirm) will result', 0.2),
            (r'click (?:the )?(?:link|button) (?:below|here) to (?:verify|confirm)', 0.15),
        ]
        
        for pattern, weight in urgency_patterns:
            if re.search(pattern, text_lower):
                score += weight
                indicators.append("Urgency pattern detected")
        
        # Generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear valued', 'dear member', 'dear account holder']
        for greeting in generic_greetings:
            if greeting in text_lower:
                score += 0.15
                indicators.append(f"Generic greeting: '{greeting}'")
                break
        
        # Structural indicators
        if html_summary:
            has_login = html_summary.get('has_login_form', False)
            num_links = html_summary.get('num_links', 0)
            num_forms = html_summary.get('num_forms', 0)
            
            if has_login and num_links < 5 and num_forms <= 2:
                score += 0.15
                indicators.append("Minimal focused page with login form")
        
        return min(1.0, score), indicators
    
    def _analyze_traditional_phishing(self, url: str, scrape_result: dict,
                                       typosquat_result: dict, proof: dict,
                                       force_mllm: bool, ai_score: float) -> dict:
        """Analyze for traditional phishing."""
        html_summary = scrape_result.get('dom_structure', {})
        
        risk_score = 0
        risk_factors = []
        
        # Factor 1: Typosquatting ONLY if not content-verified
        if typosquat_result.get('is_typosquatting') and not typosquat_result.get('content_verified'):
            method = typosquat_result.get('detection_method')
            if method not in ['faulty_extension', 'invalid_extension']:
                risk_score += 60
                risk_factors.append(f"Brand impersonation: {typosquat_result.get('impersonated_brand')}")
        
        # Factor 2: Login form with brand impersonation
        if html_summary.get('has_login_form'):
            if typosquat_result.get('is_typosquatting') and not typosquat_result.get('content_verified'):
                risk_score += 30
                risk_factors.append("Login form on suspected impersonation site")
        
        # Factor 3: Minimal content
        num_links = html_summary.get('num_links', 0)
        num_images = html_summary.get('num_images', 0)
        title = html_summary.get('title', '')
        
        if num_links < 3 and num_images < 2 and not title:
            risk_score += 20
            risk_factors.append("Minimal page content")
        
        # Factor 4: Excessive forms
        if html_summary.get('num_forms', 0) > 3 or html_summary.get('num_inputs', 0) > 10:
            risk_score += 15
            risk_factors.append("Excessive form inputs")
        
        # Factor 5: Iframes
        if html_summary.get('num_iframes', 0) > 2:
            risk_score += 10
            risk_factors.append("Multiple iframes")
        
        # Factor 6: ML model
        url_features = self.url_extractor.extract_features(url)
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
            if ml_prediction == 1 and ml_confidence >= 0.9:
                risk_score += int(ml_confidence * 30)
                risk_factors.append(f"ML model: phishing ({ml_confidence*100:.1f}%)")
        
        # CREDIBILITY BONUS: Substantial content
        if num_links >= 10 and title and len(title) > 3:
            old_risk = risk_score
            risk_score = max(0, risk_score - 40)
            if old_risk > risk_score:
                risk_factors.append("Content validation bonus: -40")
        
        # AI score contribution
        if ai_score > 0.3:
            risk_score += int(ai_score * 20)
            risk_factors.append(f"AI content indicators: +{int(ai_score * 20)}")
        
        # Determine classification
        risk_score = min(100, max(0, risk_score))
        
        if typosquat_result.get('is_typosquatting') and not typosquat_result.get('content_verified'):
            method = typosquat_result.get('detection_method')
            if method != 'subdomain_attack':
                classification = 'phishing'
                confidence = 0.85
                recommended_action = 'block' if risk_score >= 50 else 'warn'
            else:
                classification = 'phishing' if risk_score >= 40 else 'legitimate'
                confidence = 0.7
                recommended_action = 'warn' if classification == 'phishing' else 'allow'
        elif risk_score >= 70:
            classification = 'phishing'
            confidence = 0.9
            recommended_action = 'block'
        elif risk_score >= 40:
            classification = 'phishing'
            confidence = 0.7
            recommended_action = 'warn'
        else:
            classification = 'legitimate'
            confidence = 0.85
            recommended_action = 'allow'
        
        # Generate explanation
        if risk_factors:
            explanation = "Analysis: " + "; ".join(risk_factors)
        else:
            explanation = "Website content validated. No suspicious indicators."
        
        return self._build_result(
            url=url,
            classification=classification,
            confidence=round(confidence, 3),
            risk_score=round(risk_score, 2),
            explanation=explanation,
            features=url_features,
            typosquat_result=typosquat_result,
            recommended_action=recommended_action,
            scraped=True,
            proof=proof,
            analysis_mode='online',
            mllm_used=force_mllm and self.model_loaded
        )
    
    def _analyze_unreachable_site(self, url: str, typosquat_result: dict) -> dict:
        """Handle unreachable sites."""
        url_features = self.url_extractor.extract_features(url)
        
        risk_score = 30
        
        if typosquat_result.get('is_typosquatting'):
            risk_score += typosquat_result.get('risk_increase', 40)
        
        if url_features.get('is_random_domain'):
            risk_score += 25
        
        if url_features.get('is_ip_address'):
            risk_score += 15
        
        risk_score = min(100, risk_score)
        
        if risk_score >= 60:
            classification = 'phishing'
            recommended_action = 'block'
            confidence = 0.7
        elif risk_score >= 35:
            classification = 'phishing'
            recommended_action = 'warn'
            confidence = 0.6
        else:
            classification = 'unknown'  # NEW: Unknown for unreachable sites
            recommended_action = 'warn'
            confidence = 0.5
        
        explanation = "Website unreachable. "
        if typosquat_result.get('is_typosquatting'):
            explanation += f"Suspicious pattern: {typosquat_result.get('detection_method')}. "
        explanation += "Could be a taken-down phishing site or server issue."
        
        return self._build_result(
            url=url,
            classification=classification,
            confidence=round(confidence, 3),
            risk_score=round(risk_score, 2),
            explanation=explanation,
            features=url_features,
            typosquat_result=typosquat_result,
            recommended_action=recommended_action,
            scraped=False,
            proof=None,
            analysis_mode='online_failed'
        )
    
    def _analyze_static_fallback(self, url: str, force_mllm: bool = False) -> dict:
        """Static analysis when OFFLINE."""
        print(f"[OFFLINE MODE] Static analysis for {url}...")
        
        url_features = self.url_extractor.extract_features(url)
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        # Check for clear typosquatting
        if typosquat_result.get('is_typosquatting'):
            method = typosquat_result.get('detection_method')
            if method in ['faulty_extension', 'invalid_extension', 'invalid_domain_structure']:
                return self._create_typosquat_result(url, typosquat_result, offline=True)
        
        # ML Model prediction
        ml_prediction = None
        ml_confidence = 0.5
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
        
        # Calculate risk
        risk_score = self._calculate_risk_score(url_features, typosquat_result, ml_prediction, ml_confidence)
        
        # Classification (only LEGITIMATE or PHISHING in offline mode)
        if typosquat_result.get('is_typosquatting'):
            classification = 'phishing'
            confidence = max(0.85, ml_confidence) if ml_prediction == 1 else 0.85
            recommended_action = 'block' if risk_score >= 50 else 'warn'
        elif risk_score >= 40:
            classification = 'phishing'
            confidence = 0.75
            recommended_action = 'block' if risk_score >= 60 else 'warn'
        elif ml_prediction is not None:
            classification = 'phishing' if ml_prediction == 1 else 'legitimate'
            confidence = ml_confidence
            recommended_action = 'block' if (classification == 'phishing' and confidence >= 0.8) else \
                                 ('warn' if classification == 'phishing' else 'allow')
        else:
            classification = 'phishing' if risk_score >= 35 else 'legitimate'
            confidence = 0.7 if classification == 'phishing' else 0.8
            recommended_action = 'block' if risk_score >= 70 else ('warn' if risk_score >= 35 else 'allow')
        
        explanation = self._generate_rule_based_analysis(url_features, typosquat_result)
        explanation = f"[OFFLINE MODE] {explanation}"
        
        return self._build_result(
            url=url,
            classification=classification,
            confidence=round(confidence * 0.9, 3),
            risk_score=round(risk_score, 2),
            explanation=explanation,
            features=url_features,
            typosquat_result=typosquat_result,
            recommended_action=recommended_action,
            scraped=False,
            proof=None,
            analysis_mode='offline'
        )
    
    def _build_result(self, url: str, classification: str, confidence: float,
                      risk_score: float, explanation: str, features: dict,
                      typosquat_result: dict, recommended_action: str,
                      scraped: bool, proof: Optional[dict], analysis_mode: str,
                      toolkit_signatures: Optional[dict] = None,
                      ai_indicators: Optional[list] = None,
                      mllm_used: bool = False) -> dict:
        """Build standardized result dictionary."""
        features['typosquatting'] = typosquat_result
        
        result = {
            'url': url,
            'classification': classification,
            'confidence': confidence,
            'risk_score': risk_score,
            'explanation': explanation,
            'features': features,
            'recommended_action': recommended_action,
            'ml_model_used': self.ml_model_loaded,
            'mllm_used': mllm_used,
            'scraped': scraped,
            'scrape_proof': proof,
            'analysis_mode': analysis_mode,
        }
        
        if toolkit_signatures:
            result['toolkit_signatures'] = toolkit_signatures
        if ai_indicators:
            result['ai_indicators'] = ai_indicators
        
        return result
    
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
        """Synchronous version of URL analysis."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.analyze_url_async(url, force_mllm))
    
    def _predict_with_ml(self, features: dict) -> tuple:
        """Use ML model to predict phishing probability."""
        try:
            feature_vector = []
            for col in self.ml_feature_cols:
                val = features.get(col, 0)
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
    
    def _calculate_risk_score(self, features: dict, typosquat: dict = None,
                              ml_pred: int = None, ml_conf: float = 0.5) -> float:
        """Calculate risk score."""
        score = 0
        
        if ml_pred == 1:
            score += int(ml_conf * 50)
        
        if typosquat and typosquat.get('is_typosquatting'):
            score += typosquat.get('risk_increase', 50)
        
        if features.get('url_length', 0) > 75:
            score += 10
        if features.get('is_ip_address', 0):
            score += 20
        
        suspicious_count = features.get('has_suspicious_words', 0)
        if suspicious_count > 0:
            score += min(20, suspicious_count * 5)
        
        if not features.get('is_https', 0):
            score += 10
        
        if features.get('entropy', 0) > 4.5:
            score += 10
        
        if features.get('is_random_domain', 0):
            score += 45
        if features.get('domain_entropy', 0) > 3.5:
            score += 15
        
        if features.get('num_hyphens', 0) > 3:
            score += 10
        if features.get('subdomain_count', 0) > 2:
            score += 10
        if features.get('num_at', 0) > 0:
            score += 15
        
        return min(100, score)
    
    def _generate_rule_based_analysis(self, features: dict, typosquat: dict = None) -> str:
        """Generate rule-based analysis."""
        issues = []
        
        if typosquat and typosquat.get('is_typosquatting'):
            method = typosquat.get('detection_method', 'unknown')
            if method in ['faulty_extension', 'invalid_domain_structure', 'invalid_extension']:
                details = typosquat.get('details', ["Invalid domain detected"])[0]
                issues.append(details)
            else:
                brand = typosquat.get('impersonated_brand', 'unknown')
                issues.append(f"Brand impersonation: {brand}")
        
        if features.get('is_random_domain', 0):
            if features.get('is_ip_address'):
                issues.append("Uses IP address instead of domain")
            else:
                issues.append("High entropy domain name")
        
        if not features.get('is_https'):
            issues.append("No HTTPS")
        if features.get('has_suspicious_words', 0) > 0:
            issues.append("Suspicious keywords in URL")
        
        if issues:
            return "Suspicious indicators: " + "; ".join(issues)
        else:
            return "No obvious phishing indicators based on URL structure."
