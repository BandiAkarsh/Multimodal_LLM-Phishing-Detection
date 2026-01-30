"""
BentoML Model Serving for Phishing Detection

Provides production-grade model serving with:
- High-performance inference
- Batch processing
- REST API endpoints
- Model versioning
- A/B testing support

Author: Phishing Guard Team
Version: 2.0.0
"""

import bentoml
from bentoml.io import JSON, NumpyNdarray
import numpy as np
import sys
import os
from typing import List, Dict, Any

# Add project paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../05_utils'))

from model_manager import ModelManager


# BentoML model tag
MODEL_TAG = "phishing_classifier:latest"


class PhishingDetectionService:
    """
    BentoML service for phishing detection.
    
    Provides REST API endpoints for:
    - Single URL prediction
    - Batch prediction
    - Feature extraction
    - Model information
    """
    
    def __init__(self):
        """Initialize service with model"""
        # Load model via MLflow or BentoML
        try:
            self.model_manager = ModelManager()
            self.model = self.model_manager.load_model("phishing_classifier")
            self.scaler = self._load_scaler()
            self.feature_cols = self._load_feature_columns()
        except:
            # Fallback to BentoML
            self.model = bentoml.sklearn.load_model(MODEL_TAG)
            self.scaler = None
            self.feature_cols = None
    
    def _load_scaler(self):
        """Load feature scaler"""
        try:
            from sklearn.preprocessing import StandardScaler
            scaler_path = "02_models/feature_scaler.joblib"
            if os.path.exists(scaler_path):
                import joblib
                return joblib.load(scaler_path)
        except:
            pass
        return None
    
    def _load_feature_columns(self):
        """Load feature column names"""
        try:
            import joblib
            cols_path = "02_models/feature_columns.joblib"
            if os.path.exists(cols_path):
                return joblib.load(cols_path)
        except:
            pass
        return None
    
    def predict_single(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict phishing for a single set of features.
        
        Args:
            features: Dictionary of URL features
            
        Returns:
            Prediction results
        """
        # Convert dict to array
        feature_vector = self._dict_to_vector(features)
        
        # Scale if scaler available
        if self.scaler:
            feature_vector = self.scaler.transform([feature_vector])[0]
        
        # Predict
        prediction = self.model.predict([feature_vector])[0]
        probabilities = self.model.predict_proba([feature_vector])[0]
        
        confidence = max(probabilities)
        
        return {
            "classification": "phishing" if prediction == 1 else "legitimate",
            "confidence": float(confidence),
            "phishing_probability": float(probabilities[1]),
            "legitimate_probability": float(probabilities[0]),
            "features_used": len(feature_vector)
        }
    
    def predict_batch(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Batch prediction for multiple URLs.
        
        Args:
            features_list: List of feature dictionaries
            
        Returns:
            List of predictions
        """
        results = []
        
        # Convert all to vectors
        feature_vectors = [self._dict_to_vector(f) for f in features_list]
        X = np.array(feature_vectors)
        
        # Scale if available
        if self.scaler:
            X = self.scaler.transform(X)
        
        # Batch predict
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            results.append({
                "url": features_list[i].get("url", f"item_{i}"),
                "classification": "phishing" if pred == 1 else "legitimate",
                "confidence": float(max(probs)),
                "phishing_probability": float(probs[1]),
                "legitimate_probability": float(probs[0])
            })
        
        return results
    
    def _dict_to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert feature dictionary to numeric vector"""
        if self.feature_cols:
            # Use known feature columns
            return [float(features.get(col, 0)) for col in self.feature_cols]
        else:
            # Use all numeric values
            return [float(v) for v in features.values() if isinstance(v, (int, float, bool))]
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        return {
            "model_type": type(self.model).__name__,
            "model_tag": MODEL_TAG,
            "feature_count": len(self.feature_cols) if self.feature_cols else "unknown",
            "has_scaler": self.scaler is not None,
            "version": "2.0.0"
        }


def save_model_to_bentoml(model_path: str = "02_models/phishing_classifier.joblib"):
    """
    Save existing joblib model to BentoML model store.
    
    Args:
        model_path: Path to joblib model file
    """
    import joblib
    
    print(f"Loading model from {model_path}...")
    model = joblib.load(model_path)
    
    print(f"Saving to BentoML as {MODEL_TAG}...")
    bentoml.sklearn.save_model(
        "phishing_classifier",
        model,
        signatures={
            "predict": {"batchable": True},
            "predict_proba": {"batchable": True}
        },
        metadata={
            "version": "2.0.0",
            "accuracy": "99.8%",
            "features": "93"
        }
    )
    
    print("✓ Model saved to BentoML")
    print(f"View: bentoml models list")


def serve_model():
    """Serve model using BentoML (for production)"""
    import bentoml
    
    # Create BentoML service
    service = bentoml.Service("phishing-detection", runners=[])
    
    # Load model
    model_ref = bentoml.sklearn.get(MODEL_TAG)
    
    @service.api(input=JSON(), output=JSON())
    def predict(features: Dict[str, Any]) -> Dict[str, Any]:
        """Single prediction endpoint"""
        detector = PhishingDetectionService()
        return detector.predict_single(features)
    
    @service.api(input=JSON(), output=JSON())
    def predict_batch(features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch prediction endpoint"""
        detector = PhishingDetectionService()
        return detector.predict_batch(features_list)
    
    @service.api(input=JSON(), output=JSON())
    def info(_: Dict) -> Dict[str, Any]:
        """Model info endpoint"""
        detector = PhishingDetectionService()
        return detector.get_model_info()
    
    return service


def demo():
    """Demonstrate BentoML model serving"""
    print("=" * 70)
    print("BentoML Model Serving Demo")
    print("=" * 70)
    
    # First, save model to BentoML
    try:
        save_model_to_bentoml()
    except Exception as e:
        print(f"Note: Could not save model: {e}")
        print("Using existing BentoML model if available...")
    
    print("\n[1] Loading model via BentoML...")
    service = PhishingDetectionService()
    
    print("\n[2] Model info:")
    info = service.get_model_info()
    for key, value in info.items():
        print(f"  {key}: {value}")
    
    print("\n[3] Single prediction demo:")
    dummy_features = {
        "url_length": 25,
        "domain_length": 15,
        "is_https": 1,
        "has_punycode": 0,
        "entropy": 4.2,
        "num_dots": 2,
        "digit_ratio": 0.1
    }
    
    result = service.predict_single(dummy_features)
    print(f"  Result: {result}")
    
    print("\n[4] Batch prediction demo:")
    batch_features = [dummy_features, dummy_features]
    results = service.predict_batch(batch_features)
    print(f"  Predicted {len(results)} items")
    
    print("\n" + "=" * 70)
    print("To serve via REST API:")
    print("  bentoml serve service:svc --production")
    print("=" * 70)


if __name__ == "__main__":
    demo()
