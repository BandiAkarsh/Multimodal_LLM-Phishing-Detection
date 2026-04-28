"""
Model Serving and Monitoring Module

Provides:
- Batch inference with caching
- Performance metrics tracking
- Model drift detection
- Prediction monitoring

This module enhances the production-readiness of the ML model.
"""

import hashlib
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np


@dataclass
class PredictionRecord:
    """Record of a single prediction for monitoring."""
    timestamp: datetime
    url: str
    features_hash: str
    prediction: int
    probability: float
    classification: str
    latency_ms: float
    model_version: str


@dataclass
class ModelMetrics:
    """Model performance metrics."""
    total_predictions: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    cache_hit_rate: float = 0.0
    predictions_per_minute: float = 0.0
    class_distribution: Dict[str, int] = field(default_factory=dict)
    error_rate: float = 0.0


class PredictionCache:
    """
    LRU cache for prediction results.
    Caches predictions based on URL features hash.
    """
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        """
        Initialize prediction cache.
        
        Args:
            max_size: Maximum number of cached predictions
            ttl_seconds: Time-to-live for cached predictions
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Tuple[Dict, datetime]] = {}
        self.hits = 0
        self.misses = 0
    
    def _make_key(self, features: Dict) -> str:
        """Create cache key from features."""
        # Sort features for consistent hashing
        feature_str = json.dumps(features, sort_keys=True)
        return hashlib.sha256(feature_str.encode()).hexdigest()[:16]
    
    def get(self, features: Dict) -> Optional[Dict]:
        """Get cached prediction if available and not expired."""
        key = self._make_key(features)
        
        if key in self.cache:
            result, cached_time = self.cache[key]
            age = (datetime.now() - cached_time).total_seconds()
            
            if age < self.ttl_seconds:
                self.hits += 1
                return result
            else:
                # Expired - remove
                del self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, features: Dict, prediction: Dict) -> None:
        """Cache a prediction result."""
        key = self._make_key(features)
        
        # Evict oldest if full
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.cache.keys(), 
                           key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]
        
        self.cache[key] = (prediction, datetime.now())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0.0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "ttl_seconds": self.ttl_seconds,
        }


class DriftDetector:
    """
    Detects model drift by monitoring prediction distributions.
    
    Monitors:
    - Feature drift: Changes in input feature distributions
    - Prediction drift: Changes in output class distributions
    - Performance drift: Changes in model accuracy over time
    """
    
    def __init__(
        self,
        window_size: int = 1000,
        drift_threshold: float = 0.1,
        warmup_samples: int = 100
    ):
        """
        Initialize drift detector.
        
        Args:
            window_size: Number of recent predictions to monitor
            drift_threshold: Threshold for drift detection (0-1)
            warmup_samples: Number of samples needed before drift detection
        """
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.warmup_samples = warmup_samples
        
        # Store recent predictions for analysis
        self.recent_predictions: deque = deque(maxlen=window_size)
        
        # Baseline distributions (computed from initial data)
        self.baseline_distribution: Optional[Dict[str, float]] = None
        self.baseline_features: Optional[Dict[str, List[float]]] = None
        
        # Drift history
        self.drift_events: List[Dict] = []
    
    def add_prediction(self, features: Dict, prediction: str) -> None:
        """Add a prediction for drift monitoring."""
        self.recent_predictions.append({
            "timestamp": datetime.now(),
            "features": features,
            "prediction": prediction,
        })
        
        # Initialize baseline after warmup
        if len(self.recent_predictions) == self.warmup_samples:
            self._compute_baseline()
    
    def _compute_baseline(self) -> None:
        """Compute baseline distribution from warmup data."""
        # Class distribution
        class_counts = defaultdict(int)
        feature_values: Dict[str, List[float]] = defaultdict(list)
        
        for pred in self.recent_predictions:
            class_counts[pred["prediction"]] += 1
            
            # Collect numeric features
            for key, value in pred["features"].items():
                if isinstance(value, (int, float)):
                    feature_values[key].append(value)
        
        total = len(self.recent_predictions)
        self.baseline_distribution = {
            k: v / total for k, v in class_counts.items()
        }
        
        # Feature statistics
        self.baseline_features = {
            key: {
                "mean": np.mean(values),
                "std": np.std(values),
                "min": np.min(values),
                "max": np.max(values),
            }
            for key, values in feature_values.items()
            if len(values) > 10
        }
        
        print(f"Drift detector initialized with baseline from {self.warmup_samples} samples")
    
    def check_drift(self) -> Dict[str, Any]:
        """
        Check for drift since baseline.
        
        Returns:
            Dictionary with drift status and details
        """
        if len(self.recent_predictions) < self.warmup_samples:
            return {
                "status": "warming_up",
                "samples": len(self.recent_predictions),
                "needed": self.warmup_samples,
            }
        
        # Check prediction drift
        current_distribution = self._get_current_distribution()
        
        drift_score = self._compute_drift_score(
            self.baseline_distribution,
            current_distribution
        )
        
        # Check feature drift
        feature_drift = self._check_feature_drift()
        
        # Determine overall status
        is_drifted = drift_score > self.drift_threshold or any(
            fd["drifted"] for fd in feature_drift.values()
        )
        
        result = {
            "status": "drifted" if is_drifted else "stable",
            "drift_score": drift_score,
            "threshold": self.drift_threshold,
            "prediction_drift": {
                "baseline": self.baseline_distribution,
                "current": current_distribution,
                "change": drift_score,
            },
            "feature_drift": feature_drift,
            "total_samples": len(self.recent_predictions),
            "last_check": datetime.now().isoformat(),
        }
        
        # Log drift event if detected
        if is_drifted:
            self.drift_events.append({
                "timestamp": datetime.now().isoformat(),
                "drift_score": drift_score,
                "feature_drift": feature_drift,
            })
        
        return result
    
    def _get_current_distribution(self) -> Dict[str, float]:
        """Get current prediction distribution."""
        class_counts = defaultdict(int)
        
        for pred in self.recent_predictions:
            class_counts[pred["prediction"]] += 1
        
        total = len(self.recent_predictions)
        return {k: v / total for k, v in class_counts.items()}
    
    def _compute_drift_score(
        self,
        baseline: Dict[str, float],
        current: Dict[str, float]
    ) -> float:
        """Compute drift score using KL divergence approximation."""
        score = 0.0
        
        all_classes = set(baseline.keys()) | set(current.keys())
        
        for cls in all_classes:
            b = baseline.get(cls, 0.0)
            c = current.get(cls, 0.0)
            
            # Simple absolute difference
            score += abs(c - b)
        
        return score / 2.0  # Normalize to 0-1
    
    def _check_feature_drift(self) -> Dict[str, Dict]:
        """Check for drift in individual features."""
        if not self.baseline_features:
            return {}
        
        feature_drift = {}
        
        # Collect current feature values
        current_features: Dict[str, List[float]] = defaultdict(list)
        
        for pred in self.recent_predictions:
            for key, value in pred["features"].items():
                if isinstance(value, (int, float)):
                    current_features[key].append(value)
        
        # Compare with baseline
        for key, stats in self.baseline_features.items():
            if key in current_features and len(current_features[key]) > 10:
                current_mean = np.mean(current_features[key])
                current_std = np.std(current_features[key])
                
                baseline_mean = stats["mean"]
                baseline_std = stats["std"]
                
                # Check if current mean is outside baseline ± 2 std
                drift_detected = (
                    current_mean < baseline_mean - 2 * baseline_std or
                    current_mean > baseline_mean + 2 * baseline_std
                )
                
                feature_drift[key] = {
                    "baseline_mean": baseline_mean,
                    "current_mean": current_mean,
                    "drifted": drift_detected,
                    "change_pct": abs(current_mean - baseline_mean) / (abs(baseline_mean) + 1e-6) * 100
                }
        
        return feature_drift


class ModelMonitor:
    """
    Comprehensive model monitoring system.
    
    Tracks:
    - Prediction latency
    - Throughput
    - Error rates
    - Class distribution
    - Cache performance
    - Drift detection
    """
    
    def __init__(
        self,
        cache_size: int = 1000,
        metrics_window: int = 1000
    ):
        """Initialize model monitor."""
        self.cache = PredictionCache(max_size=cache_size)
        self.drift_detector = DriftDetector(warmup_samples=100)
        
        # Metrics tracking
        self.metrics_window = metrics_window
        self.predictions: deque = deque(maxlen=metrics_window)
        self.errors: deque = deque(maxlen=100)
        
        # Latency tracking
        self.latencies: deque = deque(maxlen=metrics_window)
        
        # Start time
        self.start_time = datetime.now()
        
        # Model version
        self.model_version = "2.0.0"
    
    def record_prediction(
        self,
        url: str,
        features: Dict,
        prediction: int,
        probability: float,
        classification: str,
        latency_ms: float,
        error: Optional[str] = None
    ) -> None:
        """Record a prediction for monitoring."""
        # Create prediction record
        features_hash = hashlib.sha256(
            json.dumps(features, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        record = PredictionRecord(
            timestamp=datetime.now(),
            url=url,
            features_hash=features_hash,
            prediction=prediction,
            probability=probability,
            classification=classification,
            latency_ms=latency_ms,
            model_version=self.model_version
        )
        
        self.predictions.append(record)
        self.latencies.append(latency_ms)
        
        # Add to drift detector
        self.drift_detector.add_prediction(features, classification)
        
        # Record error if any
        if error:
            self.errors.append({
                "timestamp": datetime.now(),
                "url": url,
                "error": error,
            })
    
    def get_metrics(self) -> ModelMetrics:
        """Get current model metrics."""
        if not self.predictions:
            return ModelMetrics()
        
        # Calculate metrics
        total = len(self.predictions)
        
        # Latency metrics
        latencies_list = list(self.latencies)
        avg_latency = np.mean(latencies_list) if latencies_list else 0.0
        p95_latency = np.percentile(latencies_list, 95) if latencies_list else 0.0
        p99_latency = np.percentile(latencies_list, 99) if latencies_list else 0.0
        
        # Throughput
        uptime = (datetime.now() - self.start_time).total_seconds() / 60
        predictions_per_minute = total / uptime if uptime > 0 else 0.0
        
        # Class distribution
        class_counts = defaultdict(int)
        for pred in self.predictions:
            class_counts[pred.classification] += 1
        
        # Error rate
        error_rate = len(self.errors) / total if total > 0 else 0.0
        
        # Cache stats
        cache_stats = self.cache.get_stats()
        
        return ModelMetrics(
            total_predictions=total,
            avg_latency_ms=avg_latency,
            p95_latency_ms=p95_latency,
            p99_latency_ms=p99_latency,
            cache_hit_rate=cache_stats["hit_rate"],
            predictions_per_minute=predictions_per_minute,
            class_distribution=dict(class_counts),
            error_rate=error_rate,
        )
    
    def get_drift_status(self) -> Dict[str, Any]:
        """Get current drift status."""
        return self.drift_detector.check_drift()
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall model health status."""
        metrics = self.get_metrics()
        drift = self.get_drift_status()
        
        # Determine health
        health = "healthy"
        issues = []
        
        if metrics.error_rate > 0.05:
            health = "degraded"
            issues.append(f"High error rate: {metrics.error_rate*100:.1f}%")
        
        if metrics.p99_latency_ms > 1000:
            health = "degraded"
            issues.append(f"High P99 latency: {metrics.p99_latency_ms:.0f}ms")
        
        if drift.get("status") == "drifted":
            health = "warning"
            issues.append("Model drift detected")
        
        return {
            "health": health,
            "issues": issues,
            "metrics": {
                "total_predictions": metrics.total_predictions,
                "avg_latency_ms": round(metrics.avg_latency_ms, 2),
                "p95_latency_ms": round(metrics.p95_latency_ms, 2),
                "error_rate": round(metrics.error_rate * 100, 2),
                "cache_hit_rate": round(metrics.cache_hit_rate * 100, 1),
            },
            "drift": drift,
            "uptime_minutes": round((datetime.now() - self.start_time).total_seconds() / 60, 1),
        }
    
    def get_recent_predictions(self, limit: int = 10) -> List[Dict]:
        """Get recent predictions."""
        recent = list(self.predictions)[-limit:]
        
        return [
            {
                "timestamp": p.timestamp.isoformat(),
                "url": p.url[:50] + "..." if len(p.url) > 50 else p.url,
                "classification": p.classification,
                "probability": round(p.probability, 3),
                "latency_ms": round(p.latency_ms, 2),
            }
            for p in reversed(recent)
        ]


# Global monitor instance
_model_monitor: Optional[ModelMonitor] = None


def get_model_monitor() -> ModelMonitor:
    """Get or create global model monitor."""
    global _model_monitor
    
    if _model_monitor is None:
        _model_monitor = ModelMonitor()
    
    return _model_monitor


def record_prediction(
    url: str,
    features: Dict,
    prediction: int,
    probability: float,
    classification: str,
    latency_ms: float,
    error: Optional[str] = None
) -> None:
    """Convenience function to record a prediction."""
    monitor = get_model_monitor()
    monitor.record_prediction(
        url=url,
        features=features,
        prediction=prediction,
        probability=probability,
        classification=classification,
        latency_ms=latency_ms,
        error=error
    )


def get_model_health() -> Dict[str, Any]:
    """Get model health status."""
    return get_model_monitor().get_health_status()


def get_model_metrics() -> ModelMetrics:
    """Get model metrics."""
    return get_model_monitor().get_metrics()


def get_predictions_history(limit: int = 10) -> List[Dict]:
    """Get prediction history."""
    return get_model_monitor().get_recent_predictions(limit)