import sys
import os
import importlib.util

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

URLFeatureExtractor = feature_extraction.URLFeatureExtractor
MLLMFeatureTransformer = mllm_transformer.MLLMFeatureTransformer

class PhishingDetectionService:
    """
    Main service for phishing detection using MLLM.
    Combines URL feature extraction + MLLM text transformation + classification.
    """
    
    def __init__(self, load_mllm=True):
        self.url_extractor = URLFeatureExtractor()
        self.mllm_transformer = None
        self.model_loaded = False
        
        if load_mllm:
            try:
                print("Loading MLLM model...")
                self.mllm_transformer = MLLMFeatureTransformer()
                self.model_loaded = True
                print("MLLM model loaded successfully!")
            except Exception as e:
                print(f"Warning: Could not load MLLM model: {e}")
                self.model_loaded = False
    
    def analyze_url(self, url: str) -> dict:
        """
        Analyze a single URL for phishing indicators.
        
        Returns:
            dict with classification, confidence, explanation, etc.
        """
        # Step 1: Extract URL features
        url_features = self.url_extractor.extract_features(url)
        
        # Step 2: Create metadata for MLLM
        metadata = {
            'url': url,
            'url_features': url_features,
            'dom_structure': {}  # Would come from web scraper in production
        }
        
        # Step 3: Generate text description using MLLM
        if self.mllm_transformer:
            try:
                text_description = self.mllm_transformer.transform_to_text(metadata)
            except Exception as e:
                text_description = f"Analysis failed: {e}"
        else:
            text_description = self._generate_rule_based_analysis(url_features)
        
        # Step 4: Calculate risk score based on features
        risk_score = self._calculate_risk_score(url_features)
        
        # Step 5: Determine classification
        if risk_score >= 70:
            classification = "phishing"
            recommended_action = "block"
        elif risk_score >= 40:
            classification = "phishing"
            recommended_action = "warn"
        else:
            classification = "legitimate"
            recommended_action = "allow"
        
        confidence = min(0.95, 0.5 + (risk_score / 200))
        
        return {
            'url': url,
            'classification': classification,
            'confidence': round(confidence, 3),
            'risk_score': round(risk_score, 2),
            'explanation': text_description,
            'features': url_features,
            'recommended_action': recommended_action
        }
    
    def _calculate_risk_score(self, features: dict) -> float:
        """Calculate risk score based on URL features (0-100)."""
        score = 0
        
        # Length-based risks
        if features.get('url_length', 0) > 75:
            score += 15
        if features.get('path_length', 0) > 50:
            score += 10
            
        # Suspicious patterns
        if features.get('is_ip_address', 0):
            score += 30
        
        # Suspicious words (each word adds risk)
        suspicious_count = features.get('has_suspicious_words', 0)
        if suspicious_count > 0:
            score += min(40, suspicious_count * 10)  # Up to 40 points
            
        if not features.get('is_https', 0):
            score += 15
            
        # Entropy (randomness in URL)
        entropy = features.get('entropy', 0)
        if entropy > 4.5:
            score += 15
            
        # Character-based risks
        if features.get('num_hyphens', 0) > 3:
            score += 15
        if features.get('subdomain_count', 0) > 2:
            score += 15
        if features.get('num_at', 0) > 0:
            score += 25
            
        return min(100, score)
    
    def _generate_rule_based_analysis(self, features: dict) -> str:
        """Fallback rule-based analysis when MLLM is not available."""
        issues = []
        
        if features.get('is_ip_address'):
            issues.append("URL uses an IP address instead of domain name")
        if not features.get('is_https'):
            issues.append("Connection is not secure (no HTTPS)")
        if features.get('has_suspicious_words', 0) > 0:
            issues.append("URL contains suspicious keywords like 'login', 'verify', 'account'")
        if features.get('entropy', 0) > 4.5:
            issues.append("URL contains random-looking characters (high entropy)")
        if features.get('subdomain_count', 0) > 2:
            issues.append("Excessive number of subdomains")
            
        if issues:
            return "Suspicious indicators found: " + "; ".join(issues)
        else:
            return "No obvious phishing indicators detected based on URL structure."
