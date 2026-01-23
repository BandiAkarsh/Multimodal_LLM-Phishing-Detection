import sys
import os
import torch
from contextlib import asynccontextmanager

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

# Global service instance
phishing_service = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for FastAPI app."""
    global phishing_service
    print("Starting Phishing Detection API...")
    
    # Initialize service (set load_mllm=False for faster startup during development)
    load_mllm = os.environ.get("LOAD_MLLM", "false").lower() == "true"
    phishing_service = PhishingDetectionService(load_mllm=load_mllm)
    
    print("API ready to accept requests!")
    yield
    
    print("Shutting down...")

# Create FastAPI app
app = FastAPI(
    title="Phishing Detection API",
    description="Multimodal LLM-based phishing website detection service",
    version="1.0.0",
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
    """Root endpoint."""
    return {"message": "Phishing Detection API v1.0", "docs": "/docs"}

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        model_loaded=phishing_service.model_loaded if phishing_service else False,
        gpu_available=torch.cuda.is_available()
    )

@app.post("/api/v1/analyze", response_model=URLAnalysisResponse, tags=["Analysis"])
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a single URL for phishing indicators.
    
    - **url**: The URL to analyze
    
    Returns classification, confidence score, risk assessment, and explanation.
    """
    if not phishing_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        result = phishing_service.analyze_url(request.url)
        return URLAnalysisResponse(
            url=result['url'],
            classification=ClassificationResult(result['classification']),
            confidence=result['confidence'],
            risk_score=result['risk_score'],
            explanation=result['explanation'],
            features=result['features'],
            recommended_action=result['recommended_action']
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/v1/batch-analyze", response_model=BatchURLAnalysisResponse, tags=["Analysis"])
async def batch_analyze_urls(request: BatchURLAnalysisRequest):
    """
    Analyze multiple URLs for phishing indicators.
    
    - **urls**: List of URLs to analyze
    
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
            result = phishing_service.analyze_url(url)
            response = URLAnalysisResponse(
                url=result['url'],
                classification=ClassificationResult(result['classification']),
                confidence=result['confidence'],
                risk_score=result['risk_score'],
                explanation=result['explanation'],
                features=result['features'],
                recommended_action=result['recommended_action']
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
                recommended_action="warn"
            ))
    
    return BatchURLAnalysisResponse(
        results=results,
        total_urls=len(request.urls),
        phishing_count=phishing_count,
        legitimate_count=legitimate_count
    )

@app.get("/api/v1/features/{url:path}", tags=["Features"])
async def extract_features(url: str):
    """
    Extract URL features without full classification.
    Useful for debugging and understanding feature extraction.
    """
    if not phishing_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        features = phishing_service.url_extractor.extract_features(url)
        risk_score = phishing_service._calculate_risk_score(features)
        return {
            "url": url,
            "features": features,
            "risk_score": risk_score
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
