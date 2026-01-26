"""
Pydantic Schemas for Phishing Detection API

These schemas define the request and response models for the API.
They ensure type safety and automatic validation.
"""

from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from enum import Enum

class ClassificationResult(str, Enum):
    """Possible classification results for URL analysis."""
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    AI_GENERATED_PHISHING = "ai_generated_phishing"
    PHISHING_KIT = "phishing_kit"

class URLAnalysisRequest(BaseModel):
    """Request model for URL analysis."""
    url: str
    force_scan: bool = False  # Force full MLLM analysis

class BatchURLAnalysisRequest(BaseModel):
    """Request model for batch URL analysis."""
    urls: List[str]

class URLAnalysisResponse(BaseModel):
    """Response model for URL analysis."""
    url: str
    classification: ClassificationResult
    confidence: float  # 0.0 to 1.0
    risk_score: float  # 0 to 100
    explanation: str
    features: dict
    recommended_action: str  # "block", "warn", "allow"
    analysis_mode: Optional[str] = None  # "online", "offline", "whitelist"
    scraped: Optional[bool] = False  # Whether web scraping was successful

class BatchURLAnalysisResponse(BaseModel):
    """Response model for batch URL analysis."""
    results: List[URLAnalysisResponse]
    total_urls: int
    phishing_count: int
    legitimate_count: int
    analysis_mode: Optional[str] = None  # Overall analysis mode used

class JobStatus(BaseModel):
    """Status model for async jobs."""
    job_id: str
    status: str  # "pending", "processing", "completed", "failed"
    progress: float
    result: Optional[URLAnalysisResponse] = None

class HealthResponse(BaseModel):
    """Response model for health check endpoint."""
    status: str
    version: str
    model_loaded: bool
    gpu_available: bool
    internet_available: Optional[bool] = None  # Whether internet is available
    analysis_mode: Optional[str] = None  # Current analysis mode

class ConnectivityResponse(BaseModel):
    """Response model for connectivity check endpoint."""
    status: str  # "online" or "offline"
    internet_available: bool
    analysis_mode: str
    analysis_type: str
    message: str
