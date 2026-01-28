"""
Phishing Detection Service - Core Detection Engine with 4-Category Classification

This is the main service class that orchestrates all phishing detection logic.
It classifies URLs into 4 categories:

1. LEGITIMATE - Safe, authentic website
2. PHISHING - Traditional manually-created phishing attack
3. AI_GENERATED_PHISHING - Phishing created using AI tools (ChatGPT, etc.)
4. PHISHING_KIT - Phishing created using toolkits (Gophish, HiddenEye, etc.)

Detection Modes:
1. ONLINE MODE (Internet Available):
   - Performs full web scraping to analyze actual website content
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
    
    Classification Categories:
    - LEGITIMATE: Safe website
    - PHISHING: Traditional phishing attack
    - AI_GENERATED_PHISHING: AI-created phishing (ChatGPT, etc.)
    - PHISHING_KIT: Toolkit-based phishing (Gophish, HiddenEye, etc.)
    
    This service implements INTERNET-AWARE detection:
    - When online: Scrapes websites, detects toolkits, analyzes AI patterns
    - When offline: Falls back to static URL heuristics (limited classification)
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
            load_mllm: Whether to load the MLLM model (GPU-intensive, enables AI detection)
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
        
        # Initialize connectivity monitor
        self.connectivity_monitor = ConnectivityMonitor(check_interval=30)
        self._is_online = self.connectivity_monitor.is_online
        
        # Log connectivity status
        if self._is_online:
            print("Internet connection: ONLINE - Full 4-category classification available")
        else:
            print("Internet connection: OFFLINE - Limited to LEGITIMATE/PHISHING classification")
        
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
        
        # Load MLLM (heavy, for AI detection and explanations)
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
        
        This method automatically chooses the best analysis approach:
        - ONLINE: Full web scraping + toolkit detection + AI analysis
        - OFFLINE: Static URL analysis (limited to LEGITIMATE/PHISHING)
        
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
            # ONLINE MODE: Full multimodal analysis with 4-category classification
            return await self._analyze_with_scraping(url, force_mllm)
        else:
            # OFFLINE MODE: Static analysis (limited classification)
            return self._analyze_static_fallback(url, force_mllm)
    
    async def _analyze_with_scraping(self, url: str, force_mllm: bool = False) -> dict:
        """
        Full multimodal analysis with 4-category classification (ONLINE MODE).
        
        Classification Priority:
        1. PHISHING_KIT - If toolkit signatures detected (Gophish, HiddenEye, etc.)
        2. AI_GENERATED_PHISHING - If AI-generated content patterns found
        3. PHISHING - If suspicious but no toolkit/AI indicators
        4. LEGITIMATE - If no threats detected
        """
        # Quick typosquatting check first
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        # If obvious TLD typo (like .pom instead of .com), skip scraping
        if typosquat_result.get('is_typosquatting'):
            if typosquat_result.get('detection_method') in ['faulty_extension', 'invalid_extension', 'invalid_domain_structure']:
                return self._create_typosquat_result(url, typosquat_result)
        
        # Attempt web scraping with toolkit detection
        print(f"[ONLINE MODE] Scraping {url} for 4-category analysis...")
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
                
                # Create proof of scraping
                proof = {
                    'title': html_summary.get('title', 'No Title'),
                    'html_size_bytes': len(scrape_result.get('html', '')),
                    'screenshot_size': scrape_result.get('screenshot').size if scrape_result.get('screenshot') else (0, 0),
                    'num_links': html_summary.get('num_links', 0),
                    'num_images': html_summary.get('num_images', 0),
                    'num_forms': html_summary.get('num_forms', 0),
                    'has_login_form': html_summary.get('has_login_form', False),
                    'toolkit_detected': toolkit_signatures.get('detected', False),
                    'toolkit_name': toolkit_signatures.get('toolkit_name', None),
                }
                
                print(f"   [SUCCESS] Scraped: {proof['title'][:50]}...")
                
                if toolkit_signatures.get('detected'):
                    print(f"   [TOOLKIT] Detected: {toolkit_signatures['toolkit_name']}")
                
                # Use 4-CATEGORY classification
                return self._analyze_scraped_content_4cat(
                    url, scrape_result, typosquat_result, proof, force_mllm
                )
            else:
                print(f"   [FAILED] Could not scrape {url}")
                return self._analyze_unreachable_site(url, typosquat_result)
                
        except Exception as e:
            print(f"   [ERROR] Scraping error: {e}")
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
        3. PHISHING - Traditional phishing indicators
        4. LEGITIMATE - No threats
        """
        html_summary = scrape_result.get('dom_structure', {})
        toolkit_signatures = scrape_result.get('toolkit_signatures', {})
        text_content = scrape_result.get('text_content', '')
        html_content = scrape_result.get('html', '')
        
        # Initialize classification
        classification = 'legitimate'
        confidence = 0.85
        risk_score = 0
        risk_factors = []
        
        # ========== PRIORITY 1: TOOLKIT DETECTION ==========
        if toolkit_signatures.get('detected'):
            classification = 'phishing_kit'
            confidence = toolkit_signatures.get('confidence', 0.85)
            risk_score = 85 + (confidence * 15)  # 85-100 range
            
            toolkit_name = toolkit_signatures.get('toolkit_name', 'Unknown')
            signatures = toolkit_signatures.get('signatures_found', [])
            
            risk_factors.append(f"PHISHING KIT DETECTED: {toolkit_name}")
            for sig in signatures[:3]:
                risk_factors.append(f"  - {sig}")
            
            explanation = f"Phishing toolkit detected: {toolkit_name}. " + \
                         f"Found {len(signatures)} toolkit signatures. " + \
                         "This is a mass phishing campaign using automated tools."
            
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
        ai_score = 0.0
        ai_indicators = []
        
        if self.mllm_transformer:
            # Use MLLM for AI detection
            try:
                metadata = {
                    'url': url,
                    'html': html_content,
                    'text_content': text_content,
                    'dom_structure': html_summary,
                    'url_features': self.url_extractor.extract_features(url),
                    'typosquatting': typosquat_result,
                }
                
                category, ai_confidence, mllm_explanation = self.mllm_transformer.classify_threat(
                    metadata, toolkit_signatures
                )
                
                if category == ThreatCategory.AI_GENERATED_PHISHING:
                    classification = 'ai_generated_phishing'
                    confidence = ai_confidence
                    risk_score = 70 + (ai_confidence * 25)
                    risk_factors.append("AI-GENERATED PHISHING DETECTED")
                    risk_factors.append(f"MLLM Analysis: {mllm_explanation[:100]}...")
                    
                    return self._build_result(
                        url=url,
                        classification=classification,
                        confidence=round(confidence, 3),
                        risk_score=round(risk_score, 2),
                        explanation=mllm_explanation,
                        features=self.url_extractor.extract_features(url),
                        typosquat_result=typosquat_result,
                        recommended_action='block',
                        scraped=True,
                        proof=proof,
                        analysis_mode='online',
                        mllm_used=True
                    )
                elif category == ThreatCategory.PHISHING:
                    # Continue to regular phishing analysis with MLLM input
                    ai_score = 0.3  # Some AI involvement detected
                    
            except Exception as e:
                print(f"   [MLLM] Error during AI detection: {e}")
        else:
            # Lightweight AI detection without MLLM
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
        
        # ========== PRIORITY 3: TRADITIONAL PHISHING ANALYSIS ==========
        return self._analyze_traditional_phishing(
            url, scrape_result, typosquat_result, proof, force_mllm, ai_score
        )
    
    def _lightweight_ai_detection(self, text_content: str, html_summary: dict) -> Tuple[float, list]:
        """
        Lightweight AI-generated content detection without MLLM.
        
        Detects patterns common in AI-generated phishing:
        - Overly formal language
        - Generic urgency phrases
        - Perfect grammar with impersonal tone
        """
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
        
        # Urgency language (common in AI-generated phishing)
        urgency_patterns = [
            (r'immediately|urgent|expires|suspended|locked|verify now|act now', 0.15),
            (r'your account (?:has been|will be) (?:suspended|locked|terminated)', 0.2),
            (r'failure to (?:verify|respond|confirm) will result', 0.2),
            (r'click (?:the )?(?:link|button) (?:below|here) to (?:verify|confirm)', 0.15),
        ]
        
        import re
        for pattern, weight in urgency_patterns:
            if re.search(pattern, text_lower):
                score += weight
                indicators.append(f"Urgency pattern detected")
        
        # Generic greetings (AI tends to use these)
        generic_greetings = [
            'dear customer', 'dear user', 'dear valued', 'dear member', 
            'dear account holder', 'dear client'
        ]
        
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
            
            # AI-generated phishing often has minimal but focused content
            if has_login and num_links < 5 and num_forms <= 2:
                score += 0.15
                indicators.append("Minimal focused page with login form")
        
        return min(1.0, score), indicators
    
    def _analyze_traditional_phishing(self, url: str, scrape_result: dict,
                                       typosquat_result: dict, proof: dict,
                                       force_mllm: bool, ai_score: float) -> dict:
        """
        Analyze for traditional (non-AI, non-toolkit) phishing.
        
        Uses content-based analysis to determine if the site is phishing.
        """
        html_summary = scrape_result.get('dom_structure', {})
        
        # Calculate CONTENT-BASED risk score
        risk_score = 0
        risk_factors = []
        
        # Factor 1: Typosquatting (brand impersonation)
        if typosquat_result.get('is_typosquatting'):
            method = typosquat_result.get('detection_method')
            if method not in ['faulty_extension', 'invalid_extension']:
                risk_score += 60
                risk_factors.append(f"Brand impersonation: {typosquat_result.get('impersonated_brand')}")
        
        # Factor 2: Login form with brand impersonation
        if html_summary.get('has_login_form'):
            if typosquat_result.get('is_typosquatting'):
                risk_score += 30
                risk_factors.append("Login form on suspected impersonation site")
        
        # Factor 3: Minimal content (phishing landing page pattern)
        num_links = html_summary.get('num_links', 0)
        num_images = html_summary.get('num_images', 0)
        title = html_summary.get('title', '')
        
        if num_links < 3 and num_images < 2 and not title:
            risk_score += 20
            risk_factors.append("Minimal page content (potential phishing landing)")
        
        # Factor 4: Excessive forms/inputs
        num_forms = html_summary.get('num_forms', 0)
        num_inputs = html_summary.get('num_inputs', 0)
        
        if num_forms > 3 or num_inputs > 10:
            risk_score += 15
            risk_factors.append("Excessive form inputs")
        
        # Factor 5: Suspicious iframes
        if html_summary.get('num_iframes', 0) > 2:
            risk_score += 10
            risk_factors.append("Multiple iframes")
        
        # Factor 6: ML model prediction
        url_features = self.url_extractor.extract_features(url)
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
            if ml_prediction == 1 and ml_confidence >= 0.9:
                risk_score += int(ml_confidence * 30)
                risk_factors.append(f"ML model: phishing ({ml_confidence*100:.1f}%)")
        
        # CREDIBILITY BONUS: Valid website with substantial content
        if num_links >= 10 and title and len(title) > 3:
            old_risk = risk_score
            risk_score = max(0, risk_score - 40)
            if old_risk > risk_score:
                risk_factors.append("Content validation bonus: -40")
        
        # Add AI score contribution
        if ai_score > 0.3:
            risk_score += int(ai_score * 20)
            risk_factors.append(f"AI content indicators: +{int(ai_score * 20)}")
        
        # Determine classification
        risk_score = min(100, max(0, risk_score))
        
        if typosquat_result.get('is_typosquatting') and \
           typosquat_result.get('detection_method') != 'subdomain_attack':
            classification = 'phishing'
            confidence = 0.85
            recommended_action = 'block' if risk_score >= 50 else 'warn'
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
        
        # MLLM explanation if requested
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
                pass
        
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
        """Handle case where website could not be scraped."""
        url_features = self.url_extractor.extract_features(url)
        
        risk_score = 30  # Base risk for unreachable site
        
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
            classification = 'legitimate'
            recommended_action = 'allow'
            confidence = 0.5
        
        explanation = "Website unreachable. "
        if typosquat_result.get('is_typosquatting'):
            explanation += f"Suspicious pattern: {typosquat_result.get('detection_method')}. "
        explanation += "Could be a taken-down phishing site."
        
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
        """
        Static analysis when OFFLINE (no internet connection).
        
        Can only classify as LEGITIMATE or PHISHING.
        Cannot detect AI-generated or toolkit-based attacks.
        """
        print(f"[OFFLINE MODE] Static analysis for {url}...")
        print("   [NOTE] Limited to LEGITIMATE/PHISHING classification")
        
        url_features = self.url_extractor.extract_features(url)
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        # Check for clear typosquatting
        if typosquat_result.get('is_typosquatting'):
            if typosquat_result.get('detection_method') in ['faulty_extension', 'invalid_extension', 'invalid_domain_structure']:
                return self._create_typosquat_result(url, typosquat_result, offline=True)
        
        # ML Model prediction
        ml_prediction = None
        ml_confidence = 0.5
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(url_features, typosquat_result, ml_prediction, ml_confidence)
        
        # Determine classification (only LEGITIMATE or PHISHING in offline mode)
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
            recommended_action = 'block' if risk_score >= 70 else \
                                 ('warn' if risk_score >= 35 else 'allow')
        
        # Generate explanation
        explanation = self._generate_rule_based_analysis(url_features, typosquat_result)
        explanation = f"[OFFLINE MODE] {explanation}"
        
        return self._build_result(
            url=url,
            classification=classification,
            confidence=round(confidence * 0.9, 3),  # Reduce for offline
            risk_score=round(risk_score, 2),
            explanation=explanation,
            features=url_features,
            typosquat_result=typosquat_result,
            recommended_action=recommended_action,
            scraped=False,
            proof=None,
            analysis_mode='offline',
            mllm_used=False
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
        """Calculate risk score based on URL features (0-100)."""
        score = 0
        
        if ml_pred == 1:
            score += int(ml_conf * 50)
        
        if typosquat and typosquat.get('is_typosquatting'):
            score += typosquat.get('risk_increase', 50)
        
        if features.get('url_length', 0) > 75:
            score += 10
        if features.get('path_length', 0) > 50:
            score += 5
        
        if features.get('is_ip_address', 0):
            score += 20
        
        suspicious_count = features.get('has_suspicious_words', 0)
        if suspicious_count > 0:
            score += min(20, suspicious_count * 5)
        
        if not features.get('is_https', 0):
            score += 10
        
        entropy = features.get('entropy', 0)
        if entropy > 4.5:
            score += 10
        
        domain_entropy = features.get('domain_entropy', 0)
        is_random = features.get('is_random_domain', 0)
        
        if is_random:
            score += 45
        if domain_entropy > 3.5:
            score += 15
        
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
        
        if typosquat and typosquat.get('is_typosquatting'):
            method = typosquat.get('detection_method', 'unknown')
            if method == 'faulty_extension':
                details = typosquat.get('details', ["Faulty extension detected"])[0]
                issues.append(details)
            elif method in ['invalid_domain_structure', 'invalid_extension']:
                details = typosquat.get('details', ["Invalid domain detected"])[0]
                issues.append(details)
            else:
                brand = typosquat.get('impersonated_brand', 'unknown')
                issues.append(f"BRAND IMPERSONATION: Attempting to mimic '{brand}'")
        
        if features.get('is_random_domain', 0):
            if features.get('is_ip_address'):
                issues.append("URL uses an IP address instead of domain name")
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
