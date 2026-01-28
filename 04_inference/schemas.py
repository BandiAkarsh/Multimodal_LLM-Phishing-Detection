"""
Pydantic Schemas for Phishing Detection API

These schemas define the request and response models for the API.
They ensure type safety and automatic validation.

Classification Categories:
1. LEGITIMATE - Safe, authentic website
2. PHISHING - Traditional manually-created phishing attack
3. AI_GENERATED_PHISHING - Phishing created using AI tools (ChatGPT, etc.)
4. PHISHING_KIT - Phishing created using toolkits (Gophish, HiddenEye, etc.)
"""

from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class ClassificationResult(str, Enum):
    """
    Possible classification results for URL analysis.
    
    The system uses 4-category classification:
    - LEGITIMATE: Safe website, no threats detected
    - PHISHING: Traditional phishing attack (manually created)
    - AI_GENERATED_PHISHING: Phishing created using AI tools
    - PHISHING_KIT: Phishing created using automated toolkits
    """
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    AI_GENERATED_PHISHING = "ai_generated_phishing"
    PHISHING_KIT = "phishing_kit"


class ThreatSeverity(str, Enum):
    """Threat severity levels for UI coloring."""
    SAFE = "safe"           # Green - legitimate
    LOW = "low"             # Light yellow - minor concerns
    MEDIUM = "medium"       # Yellow/Orange - AI-generated phishing
    HIGH = "high"           # Red - Traditional phishing
    CRITICAL = "critical"   # Dark red - Phishing kit (mass campaign)


class URLAnalysisRequest(BaseModel):
    """Request model for URL analysis."""
    url: str = Field(..., description="The URL to analyze")
    force_scan: bool = Field(False, description="Force full MLLM analysis")


class BatchURLAnalysisRequest(BaseModel):
    """Request model for batch URL analysis."""
    urls: List[str] = Field(..., description="List of URLs to analyze")


class ToolkitSignatures(BaseModel):
    """Information about detected phishing toolkit signatures."""
    detected: bool = Field(False, description="Whether a toolkit was detected")
    toolkit_name: Optional[str] = Field(None, description="Name of detected toolkit")
    confidence: float = Field(0.0, description="Detection confidence 0.0-1.0")
    signatures_found: List[str] = Field(default_factory=list, description="List of signatures found")


class URLAnalysisResponse(BaseModel):
    """
    Response model for URL analysis.
    
    Includes 4-category classification with detailed metadata.
    """
    url: str = Field(..., description="The analyzed URL")
    classification: ClassificationResult = Field(..., description="Threat classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence 0.0 to 1.0")
    risk_score: float = Field(..., ge=0, le=100, description="Risk score 0 to 100")
    explanation: str = Field(..., description="Human-readable explanation")
    features: Dict[str, Any] = Field(default_factory=dict, description="Extracted features")
    recommended_action: str = Field(..., description="Action: block, warn, or allow")
    
    # Analysis metadata
    analysis_mode: Optional[str] = Field(None, description="Mode: online, offline, whitelist")
    scraped: Optional[bool] = Field(False, description="Whether web scraping succeeded")
    
    # Extended classification info
    toolkit_signatures: Optional[ToolkitSignatures] = Field(
        None, description="Toolkit detection results (if PHISHING_KIT)"
    )
    ai_indicators: Optional[List[str]] = Field(
        None, description="AI content indicators (if AI_GENERATED_PHISHING)"
    )
    
    # Model usage
    ml_model_used: Optional[bool] = Field(False, description="Whether ML model was used")
    mllm_used: Optional[bool] = Field(False, description="Whether MLLM was used")
    
    @property
    def severity(self) -> ThreatSeverity:
        """Get threat severity for UI coloring."""
        if self.classification == ClassificationResult.LEGITIMATE:
            return ThreatSeverity.SAFE
        elif self.classification == ClassificationResult.AI_GENERATED_PHISHING:
            return ThreatSeverity.MEDIUM
        elif self.classification == ClassificationResult.PHISHING:
            return ThreatSeverity.HIGH
        elif self.classification == ClassificationResult.PHISHING_KIT:
            return ThreatSeverity.CRITICAL
        return ThreatSeverity.LOW
    
    def get_color_code(self) -> str:
        """Get hex color code for UI display."""
        colors = {
            ThreatSeverity.SAFE: "#22c55e",      # Green
            ThreatSeverity.LOW: "#fbbf24",       # Light yellow
            ThreatSeverity.MEDIUM: "#f97316",    # Orange
            ThreatSeverity.HIGH: "#ef4444",      # Red
            ThreatSeverity.CRITICAL: "#991b1b",  # Dark red
        }
        return colors.get(self.severity, "#6b7280")


class BatchURLAnalysisResponse(BaseModel):
    """Response model for batch URL analysis."""
    results: List[URLAnalysisResponse] = Field(..., description="Analysis results")
    total_urls: int = Field(..., description="Total URLs analyzed")
    legitimate_count: int = Field(..., description="Count of legitimate URLs")
    phishing_count: int = Field(..., description="Count of phishing URLs")
    ai_generated_count: int = Field(0, description="Count of AI-generated phishing")
    toolkit_count: int = Field(0, description="Count of toolkit-based phishing")
    analysis_mode: Optional[str] = Field(None, description="Overall analysis mode")


class JobStatus(BaseModel):
    """Status model for async jobs."""
    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(..., description="Status: pending, processing, completed, failed")
    progress: float = Field(..., ge=0.0, le=1.0, description="Progress 0.0 to 1.0")
    result: Optional[URLAnalysisResponse] = Field(None, description="Analysis result if completed")


class HealthResponse(BaseModel):
    """Response model for health check endpoint."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    model_loaded: bool = Field(..., description="Whether MLLM model is loaded")
    ml_model_loaded: bool = Field(False, description="Whether ML classifier is loaded")
    gpu_available: bool = Field(..., description="Whether GPU is available")
    internet_available: Optional[bool] = Field(None, description="Internet connectivity")
    analysis_mode: Optional[str] = Field(None, description="Current analysis mode")
    classification_categories: List[str] = Field(
        default=["legitimate", "phishing", "ai_generated_phishing", "phishing_kit"],
        description="Available classification categories"
    )


class ConnectivityResponse(BaseModel):
    """Response model for connectivity check endpoint."""
    status: str = Field(..., description="Status: online or offline")
    internet_available: bool = Field(..., description="Internet connectivity")
    analysis_mode: str = Field(..., description="Current analysis mode")
    analysis_type: str = Field(..., description="Type of analysis available")
    message: str = Field(..., description="Human-readable message")
    available_categories: List[str] = Field(
        default_factory=list,
        description="Classification categories available in current mode"
    )


class EmailScanRequest(BaseModel):
    """Request model for email scanning."""
    email_content: str = Field(..., description="Raw email content or path to .eml file")
    scan_attachments: bool = Field(False, description="Whether to scan attachments")


class EmailScanResponse(BaseModel):
    """Response model for email scanning."""
    urls_found: int = Field(..., description="Number of URLs found in email")
    urls_analyzed: List[URLAnalysisResponse] = Field(..., description="Analysis results for each URL")
    highest_threat: ClassificationResult = Field(..., description="Highest threat level found")
    overall_risk_score: float = Field(..., description="Overall email risk score")
    recommended_action: str = Field(..., description="Recommended action for the email")
    sender_suspicious: bool = Field(False, description="Whether sender appears suspicious")
