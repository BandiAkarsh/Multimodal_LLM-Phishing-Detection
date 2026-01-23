import sys
import os
import importlib.util
import numpy as np
import joblib

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

URLFeatureExtractor = feature_extraction.URLFeatureExtractor
MLLMFeatureTransformer = mllm_transformer.MLLMFeatureTransformer
TyposquattingDetector = typosquatting_detector.TyposquattingDetector

class PhishingDetectionService:
    """
    Main service for phishing detection using MLLM + ML Classifier.
    Combines URL feature extraction + typosquatting + ML model + MLLM explanation.
    """
    
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
    
    def analyze_url(self, url: str) -> dict:
        """
        Analyze a single URL for phishing indicators.
        
        Returns:
            dict with classification, confidence, explanation, etc.
        """
        # Step 1: Extract URL features
        url_features = self.url_extractor.extract_features(url)
        
        # Step 2: Check for typosquatting/brand impersonation
        typosquat_result = self.typosquatting_detector.analyze(url)
        
        # Step 3: ML Model prediction (if available)
        ml_prediction = None
        ml_confidence = 0.5
        if self.ml_model_loaded:
            ml_prediction, ml_confidence = self._predict_with_ml(url_features)
        
        # Step 4: Calculate combined risk score
        risk_score = self._calculate_risk_score(url_features, typosquat_result, ml_prediction, ml_confidence)
        
        # Step 5: Determine classification
        if typosquat_result.get('is_typosquatting'):
            classification = "phishing"
            confidence = max(0.85, ml_confidence) if ml_prediction == 1 else 0.85
            recommended_action = "block" if risk_score >= 50 else "warn"
        elif ml_prediction is not None:
            classification = "phishing" if ml_prediction == 1 else "legitimate"
            confidence = ml_confidence
            if classification == "phishing":
                recommended_action = "block" if confidence >= 0.8 else "warn"
            else:
                recommended_action = "allow"
        elif risk_score >= 70:
            classification = "phishing"
            confidence = 0.85
            recommended_action = "block"
        elif risk_score >= 35:
            classification = "phishing"
            confidence = 0.7
            recommended_action = "warn"
        else:
            classification = "legitimate"
            confidence = 0.8
            recommended_action = "allow"
        
        # Step 6: Generate explanation
        if self.mllm_transformer:
            try:
                metadata = {'url': url, 'url_features': url_features, 'typosquatting': typosquat_result}
                text_description = self.mllm_transformer.transform_to_text(metadata)
            except Exception as e:
                text_description = self._generate_rule_based_analysis(url_features, typosquat_result)
        else:
            text_description = self._generate_rule_based_analysis(url_features, typosquat_result)
        
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
            'ml_model_used': self.ml_model_loaded
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
            brand = typosquat.get('impersonated_brand', 'unknown')
            method = typosquat.get('detection_method', 'unknown')
            issues.append(f"BRAND IMPERSONATION: Attempting to mimic '{brand}' ({method})")
        
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
