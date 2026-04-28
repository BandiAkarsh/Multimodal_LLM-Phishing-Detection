"""
Model Monitoring API Endpoints

Provides REST endpoints for:
- Model health status
- Performance metrics
- Drift detection
- Prediction history

Usage:
    Import and add to your FastAPI app:
    from monitoring_api import router
    app.include_router(router)
"""

import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import auth dependencies
try:
    from auth import get_current_user
    auth_available = True
except ImportError:
    auth_available = False
    def get_current_user():
        return {"user_id": "anonymous"}


# ============== Request/Response Models ==============

class HealthResponse(BaseModel):
    """Model health response."""
    health: str = Field(..., description="Health status: healthy, degraded, warning")
    issues: List[str] = Field(default_factory=list, description="List of issues")
    uptime_minutes: float = Field(..., description="Model uptime in minutes")
    drift: Dict[str, Any] = Field(..., description="Drift detection status")


class MetricsResponse(BaseModel):
    """Model metrics response."""
    total_predictions: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    cache_hit_rate: float
    predictions_per_minute: float
    class_distribution: Dict[str, int]
    error_rate: float


class DriftResponse(BaseModel):
    """Drift detection response."""
    status: str = Field(..., description="Drift status: stable, drifted, warming_up")
    drift_score: Optional[float] = None
    threshold: Optional[float] = None
    prediction_drift: Optional[Dict[str, Any]] = None
    feature_drift: Optional[Dict[str, Any]] = None
    total_samples: Optional[int] = None
    last_check: Optional[str] = None


class PredictionHistoryItem(BaseModel):
    """Single prediction history item."""
    timestamp: str
    url: str
    classification: str
    probability: float
    latency_ms: float


class PredictionHistoryResponse(BaseModel):
    """Prediction history response."""
    predictions: List[PredictionHistoryItem]
    total: int


class CacheStatsResponse(BaseModel):
    """Cache statistics response."""
    size: int
    max_size: int
    hits: int
    misses: int
    hit_rate: float
    ttl_seconds: int


# ============== API Router ==============

router = APIRouter(prefix="/api/v1/monitoring", tags=["Model Monitoring"])


@router.get("/health", response_model=HealthResponse)
async def get_health(
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get model health status.
    
    Returns:
        Health status with any issues and drift detection
    """
    try:
        from model_serving import get_model_health
        return get_model_health()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting health: {str(e)}"
        )


@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics(
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get model performance metrics.
    
    Returns:
        Detailed metrics including latency, throughput, and class distribution
    """
    try:
        from model_serving import get_model_metrics
        
        metrics = get_model_metrics()
        
        return MetricsResponse(
            total_predictions=metrics.total_predictions,
            avg_latency_ms=metrics.avg_latency_ms,
            p95_latency_ms=metrics.p95_latency_ms,
            p99_latency_ms=metrics.p99_latency_ms,
            cache_hit_rate=metrics.cache_hit_rate,
            predictions_per_minute=metrics.predictions_per_minute,
            class_distribution=metrics.class_distribution,
            error_rate=metrics.error_rate,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting metrics: {str(e)}"
        )


@router.get("/drift", response_model=DriftResponse)
async def get_drift(
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get model drift detection status.
    
    Returns:
        Drift status including prediction and feature drift analysis
    """
    try:
        from model_serving import get_model_monitor
        
        monitor = get_model_monitor()
        drift_status = monitor.get_drift_status()
        
        return DriftResponse(**drift_status)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting drift status: {str(e)}"
        )


@router.get("/history", response_model=PredictionHistoryResponse)
async def get_history(
    limit: int = Field(10, ge=1, le=100, description="Number of predictions to return"),
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get prediction history.
    
    Returns:
        Recent predictions with classification and latency
    """
    try:
        from model_serving import get_predictions_history
        
        predictions = get_predictions_history(limit=limit)
        
        return PredictionHistoryResponse(
            predictions=[
                PredictionHistoryItem(**p) for p in predictions
            ],
            total=len(predictions),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting history: {str(e)}"
        )


@router.get("/cache", response_model=CacheStatsResponse)
async def get_cache_stats(
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get prediction cache statistics.
    
    Returns:
        Cache size, hits, misses, and hit rate
    """
    try:
        from model_serving import get_model_monitor
        
        monitor = get_model_monitor()
        cache_stats = monitor.cache.get_stats()
        
        return CacheStatsResponse(**cache_stats)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting cache stats: {str(e)}"
        )


@router.get("/summary")
async def get_summary(
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get comprehensive monitoring summary.
    
    Returns:
        Combined health, metrics, drift, and cache information
    """
    try:
        from model_serving import get_model_health, get_model_metrics, get_model_monitor
        
        health = get_model_health()
        metrics = get_model_metrics()
        monitor = get_model_monitor()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "health": health,
            "metrics": {
                "total_predictions": metrics.total_predictions,
                "avg_latency_ms": round(metrics.avg_latency_ms, 2),
                "p95_latency_ms": round(metrics.p95_latency_ms, 2),
                "p99_latency_ms": round(metrics.p99_latency_ms, 2),
                "predictions_per_minute": round(metrics.predictions_per_minute, 1),
                "error_rate": round(metrics.error_rate * 100, 2),
                "class_distribution": metrics.class_distribution,
            },
            "cache": monitor.cache.get_stats(),
            "drift": monitor.get_drift_status(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting summary: {str(e)}"
        )


@router.post("/reset")
async def reset_metrics(
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Reset monitoring metrics.
    
    Note: This will clear all prediction history and reset baseline.
    """
    try:
        from model_serving import ModelMonitor
        
        global _model_monitor
        _model_monitor = ModelMonitor()
        
        return {
            "message": "Metrics reset successfully",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error resetting metrics: {str(e)}"
        )


# ============== Health Check ==============

@router.get("/status")
async def monitoring_status():
    """Check monitoring service health."""
    try:
        from model_serving import get_model_monitor
        
        monitor = get_model_monitor()
        
        return {
            "status": "healthy",
            "monitoring_active": True,
            "predictions_tracked": len(monitor.predictions),
            "model_version": monitor.model_version,
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }


# Import global monitor for reset
from model_serving import _model_monitor