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

URLFeatureExtractor = feature_extraction.URLFeatureExtractor
MLLMFeatureTransformer = mllm_transformer.MLLMFeatureTransformer
TyposquattingDetector = typosquatting_detector.TyposquattingDetector
WebScraper = web_scraper.WebScraper

class PhishingDetectionService:
    """
    Main service for phishing detection using MLLM + ML Classifier.
    Combines URL feature extraction + typosquatting + ML model + MLLM explanation.
    """
    
    # Whitelisted domains for marketing/infrastructure that often have "messy" URLs
    WHITELISTED_DOMAINS = {
        'customeriomail.com', 'sendgrid.net', 'mailchimp.com', 'google.com',
        'github.com', 'microsoft.com', 'cursor.com', 'cursor.sh',
        'amazonaws.com', 'azure.com', 'googleapis.com', 'gstatic.com',
        'slack.com', 'zoom.us', 'atlassian.com', 'linear.app', 'stripe.com'
    }
    
    def __init__(self, load_mllm=False, load_ml_model=True):
        self.url_extractor = URLFeatureExtractor()
        self.typosquatting_detector = TyposquattingDetector()
        self.mllm_transformer = None
        self.ml_model = None
        self.ml_scaler = None
        self.ml_feature_cols = None
        self.model_loaded = False
        self.ml_model_loaded = False
        
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
    
    async def analyze_url_async(self, url: str, force_mllm: bool = False) -> dict:
        """
        Async version of analyze_url that supports full Multimodal Scraping (Tier 3).
        """
        # Tier 0, 1, 2 (Fast Static Checks)
        # Reuse logic from synchronous method for consistency
        # In a real refactor, logic should be shared. For now, I'll copy critical parts.
        
        extracted = tldextract.extract(url)
        domain_part = f"{extracted.domain}.{extracted.suffix}"
        if domain_part in self.WHITELISTED_DOMAINS:
             return self.analyze_url(url) # Return static result

        url_features = self.url_extractor.extract_features(url)
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        ml_prediction = None
        ml_confidence = 0.5
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
            
        risk_score = self._calculate_risk_score(url_features, typosquat_result, ml_prediction, ml_confidence)
        
        # Decide if we need full scraping (Tier 3)
        # 1. User forced it
        # 2. Risk is ambiguous (between 30 and 70)
        # 3. Typosquatting found (verify if it's a parked page vs real clone)
        needs_scraping = force_mllm or (30 <= risk_score <= 70) or typosquat_result.get('is_typosquatting')
        
        html_summary = {}
        scrape_success = False
        
        if needs_scraping:
            print(f"Initiating Multimodal Scrape for {url}...")
            scraper = WebScraper(headless=True, timeout=30000) # 30s timeout
            try:
                scrape_result = await scraper.scrape_url(url)
                if scrape_result['success']:
                    scrape_success = True
                    html_summary = scrape_result['dom_structure']
                    
                    # Content Credibility Bonus
                    # If site works and has substantial content, reduce risk from "random domain" heuristic
                    if html_summary:
                        links_count = html_summary.get('num_links', 0)
                        has_title = bool(html_summary.get('title'))
                        
                        if links_count > 10 and has_title:
                            print(f"Site content validated: {links_count} links found. Reducing risk.")
                            # Increase bonus from -20 to -50 to save legitimate long URLs (like blog posts)
                            risk_score = max(0, risk_score - 50)
                            
                else:
                    # Scenario: "jurassicpark.com" (NXDOMAIN / Connection Refused)
                    print(f"Scraping failed for {url}. Site might be offline.")
                    # If site is offline, it might be a taken-down phishing site or invalid.
                    # We flag it as suspicious if it had other risk factors.
                    risk_score += 10 # Penalty for being unreachable
            except Exception as e:
                print(f"Scraper error: {e}")
            finally:
                await scraper.close()
        
        # MLLM Processing
        if self.mllm_transformer and (needs_scraping or force_mllm):
            try:
                metadata = {
                    'url': url, 
                    'url_features': url_features, 
                    'typosquatting': typosquat_result,
                    'html_summary': html_summary if scrape_success else "Site unreachable or content extraction failed."
                }
                text_description = self.mllm_transformer.transform_to_text(metadata)
            except Exception as e:
                text_description = self._generate_rule_based_analysis(url_features, typosquat_result)
        else:
            text_description = self._generate_rule_based_analysis(url_features, typosquat_result)
            if not scrape_success and needs_scraping:
                 text_description += " [Note: Website content was unreachable]"

        # Determine Final Classification (similar logic to sync)
        if typosquat_result.get('is_typosquatting'):
            classification = "phishing"
            recommended_action = "block" if risk_score >= 50 else "warn"
            confidence = 0.85
        elif not scrape_success and needs_scraping and risk_score > 40:
             # Site unreachable + High Risk = Suspicious
             classification = "phishing"
             recommended_action = "warn"
             confidence = 0.6
             text_description = "Site is unreachable but has suspicious URL characteristics."
        elif risk_score >= 70:
            classification = "phishing"
            recommended_action = "block"
            confidence = 0.9
        elif risk_score >= 35:
            classification = "phishing"
            recommended_action = "warn"
            confidence = 0.7
        else:
            classification = "legitimate"
            recommended_action = "allow"
            confidence = 0.85

        return {
            'url': url,
            'classification': classification,
            'confidence': confidence,
            'risk_score': risk_score,
            'explanation': text_description,
            'features': url_features,
            'recommended_action': recommended_action,
            'ml_model_used': self.ml_model_loaded,
            'mllm_used': (self.mllm_transformer is not None) and needs_scraping,
            'scraped': scrape_success
        }

    def analyze_url(self, url: str, force_mllm: bool = False) -> dict:
        """
        Analyze a single URL for phishing indicators using Tiered Detection.
        
        Tiers:
        1. Whitelist/Typosquatting/Heuristics (Instant)
        2. ML Model (Very Fast)
        3. MLLM (Slow, GPU-intensive) - Only if uncertain or forced
        """
        # Tier 0: Check Whitelist (Marketing/Infrastructure domains)
        extracted = tldextract.extract(url)
        domain_part = f"{extracted.domain}.{extracted.suffix}"
        if domain_part in self.WHITELISTED_DOMAINS:
            return {
                'url': url,
                'classification': 'legitimate',
                'confidence': 1.0,
                'risk_score': 0,
                'explanation': f"Domain '{domain_part}' is in the trusted whitelist.",
                'features': {},
                'recommended_action': 'allow',
                'ml_model_used': False,
                'mllm_used': False
            }

        # Tier 1: Extract URL features & Check Typosquatting
        url_features = self.url_extractor.extract_features(url)
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        # Tier 2: ML Model prediction
        ml_prediction = None
        ml_confidence = 0.5
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
        
        # Tier 3: Determine if MLLM is needed
        # Logic: Only run MLLM if:
        # a) Forced by user
        # b) ML model is uncertain (confidence < 0.85)
        # c) Typosquatting detected (to get detailed brand analysis)
        needs_mllm = force_mllm or (ml_confidence < 0.85) or typosquat_result.get('is_typosquatting')
        
        # Calculate initial risk score
        risk_score = self._calculate_risk_score(url_features, typosquat_result, ml_prediction, ml_confidence)
        
        # Determine classification
        if typosquat_result.get('is_typosquatting'):
            classification = "phishing"
            confidence = max(0.85, ml_confidence) if ml_prediction == 1 else 0.85
            recommended_action = "block" if risk_score >= 50 else "warn"
        elif risk_score >= 40: # Heuristics override ML if risk is high (e.g. random domain)
            classification = "phishing"
            confidence = 0.75 # Heuristic confidence
            recommended_action = "block" if risk_score >= 60 else "warn"
        elif ml_prediction is not None:
            classification = "phishing" if ml_prediction == 1 else "legitimate"
            confidence = ml_confidence
            recommended_action = "block" if (classification == "phishing" and confidence >= 0.8) else ("warn" if classification == "phishing" else "allow")
        else:
            # Fallback to heuristics
            classification = "phishing" if risk_score >= 35 else "legitimate"
            confidence = 0.7 if classification == "phishing" else 0.8
            recommended_action = "block" if risk_score >= 70 else ("warn" if risk_score >= 35 else "allow")
        
        # Run MLLM if needed and loaded
        if needs_mllm and self.mllm_transformer:
            try:
                metadata = {'url': url, 'url_features': url_features, 'typosquatting': typosquat_result}
                text_description = self.mllm_transformer.transform_to_text(metadata)
            except Exception as e:
                text_description = self._generate_rule_based_analysis(url_features, typosquat_result)
        else:
            # Skip MLLM to save resources
            text_description = self._generate_rule_based_analysis(url_features, typosquat_result)
            if not needs_mllm:
                text_description = f"[FastScan] {text_description}"
        
        # Add typosquatting info to features
        url_features['typosquatting'] = typosquat_result
        
        return {
            'url': url,
            'classification': classification,
            'confidence': round(confidence, 3),
            'risk_score': round(risk_score, 2),
            'explanation': text_description,
            'features': url_features,
            'recommended_action': recommended_action,
            'ml_model_used': self.ml_model_loaded,
            'mllm_used': needs_mllm and self.model_loaded
        }
    
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
        """Calculate risk score based on URL features (0-100)."""
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
            score += 45 # High penalty for randomness (almost certainly phishing/DGA)
        if domain_entropy > 3.5:
            score += 15 # Extra penalty for very high entropy
            
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
        
        # Check DOM Features if available (from Scraping)
        # Note: 'dom_structure' might be passed inside features or handled separately.
        # Currently, analyze_url_async doesn't merge dom features into 'features' dict for this function.
        # But we can infer legitimacy.
        
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
            # If we successfully scraped content, we might relax this
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
