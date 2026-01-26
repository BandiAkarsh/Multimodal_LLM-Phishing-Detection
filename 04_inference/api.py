"""
Phishing Detection API - FastAPI REST Service

This module provides a REST API for the phishing detection service.
It supports INTERNET-AWARE detection and includes connectivity status
in all responses.

Endpoints:
    GET  /              - API info and version
    GET  /health        - Health check with connectivity status
    POST /api/v1/analyze       - Analyze single URL
    POST /api/v1/batch-analyze - Analyze multiple URLs
    GET  /api/v1/features/{url} - Extract URL features only
    GET  /api/v1/connectivity  - Check connectivity status

Usage:
    uvicorn api:app --host 0.0.0.0 --port 8000
    
    # With MLLM enabled
    LOAD_MLLM=true uvicorn api:app --host 0.0.0.0 --port 8000
"""

import sys
import os
import torch
from contextlib import asynccontextmanager
from typing import Optional

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from schemas import (
    URLAnalysisRequest, 
    URLAnalysisResponse, 
    BatchURLAnalysisRequest,
    BatchURLAnalysisResponse,
    HealthResponse,
    ClassificationResult
)
from service import PhishingDetectionService

# Import connectivity checker
try:
    sys.path.append(os.path.join(project_root, '05_utils'))
    from connectivity import check_internet_connection, get_connectivity_status
except ImportError:
    def check_internet_connection():
        return True
    def get_connectivity_status():
        return {'is_online': True, 'mode': 'online'}

# Global service instance
phishing_service = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for FastAPI app."""
    global phishing_service
    print("Starting Phishing Detection API...")
    
    # Check connectivity
    is_online = check_internet_connection()
    if is_online:
        print("Internet connection: ONLINE - Full multimodal analysis available")
    else:
        print("Internet connection: OFFLINE - Using static analysis fallback")
    
    # Initialize service (set load_mllm=False for faster startup during development)
    load_mllm = os.environ.get("LOAD_MLLM", "false").lower() == "true"
    phishing_service = PhishingDetectionService(load_mllm=load_mllm)
    
    print("API ready to accept requests!")
    yield
    
    print("Shutting down...")

# Create FastAPI app
app = FastAPI(
    title="Phishing Detection API",
    description="""
    Multimodal LLM-based phishing website detection service.
    
    ## Features
    - **Internet-Aware Detection**: Automatically uses web scraping when online
    - **Static Fallback**: Uses URL heuristics when offline
    - **Typosquatting Detection**: Identifies brand impersonation attempts
    - **ML Classification**: 99.8% F1 Score on PhishTank dataset
    
    ## Analysis Modes
    - `online`: Full web scraping + content analysis (most accurate)
    - `offline`: Static URL analysis (fallback when no internet)
    - `whitelist`: Trusted domain detected (instant response)
    """,
    version="2.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint with API info."""
    connectivity = get_connectivity_status()
    return {
        "message": "Phishing Detection API v2.0",
        "docs": "/docs",
        "health": "/health",
        "analysis_mode": connectivity['mode'],
        "internet_available": connectivity['is_online']
    }

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint with connectivity status."""
    connectivity = get_connectivity_status()
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        model_loaded=phishing_service.model_loaded if phishing_service else False,
        gpu_available=torch.cuda.is_available(),
        internet_available=connectivity['is_online'],
        analysis_mode=connectivity['mode']
    )

@app.get("/api/v1/connectivity", tags=["Health"])
async def check_connectivity():
    """
    Check current internet connectivity status.
    
    Returns detailed connectivity information including:
    - Current online/offline status
    - Analysis mode that will be used
    - Last check timestamp
    """
    connectivity = get_connectivity_status()
    
    # Force refresh if requested
    if phishing_service:
        current_status = phishing_service.refresh_connectivity()
        connectivity['is_online'] = current_status
        connectivity['mode'] = 'online' if current_status else 'offline'
    
    return {
        "status": "online" if connectivity['is_online'] else "offline",
        "internet_available": connectivity['is_online'],
        "analysis_mode": connectivity['mode'],
        "analysis_type": connectivity.get('analysis_type', 'Unknown'),
        "message": "Full multimodal scraping available" if connectivity['is_online'] else "Using static URL analysis (less accurate)"
    }

@app.post("/api/v1/analyze", response_model=URLAnalysisResponse, tags=["Analysis"])
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a single URL for phishing indicators.
    
    The API automatically chooses the best analysis method:
    - **Online**: Scrapes the website and analyzes actual content
    - **Offline**: Uses static URL features and heuristics
    
    Parameters:
    - **url**: The URL to analyze
    - **force_scan**: Force full MLLM analysis (requires GPU)
    
    Returns classification, confidence score, risk assessment, and explanation.
    """
    if not phishing_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        # Use async analysis for full multimodal capabilities
        result = await phishing_service.analyze_url_async(request.url, force_mllm=request.force_scan)
        
        return URLAnalysisResponse(
            url=result['url'],
            classification=ClassificationResult(result['classification']),
            confidence=result['confidence'],
            risk_score=result['risk_score'],
            explanation=result['explanation'],
            features=result['features'],
            recommended_action=result['recommended_action'],
            analysis_mode=result.get('analysis_mode', 'unknown'),
            scraped=result.get('scraped', False)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/v1/batch-analyze", response_model=BatchURLAnalysisResponse, tags=["Analysis"])
async def batch_analyze_urls(request: BatchURLAnalysisRequest):
    """
    Analyze multiple URLs for phishing indicators.
    
    Parameters:
    - **urls**: List of URLs to analyze (max 100)
    
    Returns batch results with summary statistics.
    """
    if not phishing_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    if len(request.urls) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 URLs per batch")
    
    results = []
    phishing_count = 0
    legitimate_count = 0
    
    for url in request.urls:
        try:
            # Use async analysis
            result = await phishing_service.analyze_url_async(url)
            response = URLAnalysisResponse(
                url=result['url'],
                classification=ClassificationResult(result['classification']),
                confidence=result['confidence'],
                risk_score=result['risk_score'],
                explanation=result['explanation'],
                features=result['features'],
                recommended_action=result['recommended_action'],
                analysis_mode=result.get('analysis_mode', 'unknown'),
                scraped=result.get('scraped', False)
            )
            results.append(response)
            
            if result['classification'] == 'phishing':
                phishing_count += 1
            else:
                legitimate_count += 1
                
        except Exception as e:
            # Add failed result
            results.append(URLAnalysisResponse(
                url=url,
                classification=ClassificationResult.LEGITIMATE,
                confidence=0.0,
                risk_score=0.0,
                explanation=f"Analysis failed: {str(e)}",
                features={},
                recommended_action="warn",
                analysis_mode="error",
                scraped=False
            ))
    
    return BatchURLAnalysisResponse(
        results=results,
        total_urls=len(request.urls),
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        analysis_mode=phishing_service.analysis_mode if phishing_service else "unknown"
    )

@app.get("/api/v1/features/{url:path}", tags=["Features"])
async def extract_features(url: str):
    """
    Extract URL features without full classification.
    
    Useful for debugging and understanding feature extraction.
    Returns raw URL features and calculated risk score.
    """
    if not phishing_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        features = phishing_service.url_extractor.extract_features(url)
        typosquat = phishing_service.typosquatting_detector.analyze(url)
        risk_score = phishing_service._calculate_risk_score(features, typosquat)
        
        return {
            "url": url,
            "features": features,
            "typosquatting": typosquat,
            "risk_score": risk_score,
            "analysis_mode": phishing_service.analysis_mode
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
