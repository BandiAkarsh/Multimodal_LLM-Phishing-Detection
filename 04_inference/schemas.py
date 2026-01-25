from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from enum import Enum

class ClassificationResult(str, Enum):
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    AI_GENERATED_PHISHING = "ai_generated_phishing"
    PHISHING_KIT = "phishing_kit"

class URLAnalysisRequest(BaseModel):
    url: str
    force_scan: bool = False
    
class BatchURLAnalysisRequest(BaseModel):
    urls: List[str]

class URLAnalysisResponse(BaseModel):
    url: str
    classification: ClassificationResult
    confidence: float
    risk_score: float  # 0-100
    explanation: str
    features: dict
    recommended_action: str  # "block", "warn", "allow"

class BatchURLAnalysisResponse(BaseModel):
    results: List[URLAnalysisResponse]
    total_urls: int
    phishing_count: int
    legitimate_count: int

class JobStatus(BaseModel):
    job_id: str
    status: str  # "pending", "processing", "completed", "failed"
    progress: float
    result: Optional[URLAnalysisResponse] = None

class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool
    gpu_available: bool
