# 04_inference Folder Documentation

## Overview

The `04_inference/` folder contains the core detection logic and API server. This is where all the "magic" happens - incoming URLs are analyzed and classified.

## Folder Structure

```
04_inference/
├── service.py      # Core detection service (MAIN FILE)
├── api.py          # FastAPI REST endpoints
└── schemas.py      # Pydantic request/response models
```

---

## 1. `service.py` - Core Detection Service

This is the **most important file** in the project. It orchestrates all detection logic.

### Class: `PhishingDetectionService`

```python
class PhishingDetectionService:
    """
    Main service for phishing detection using MLLM + ML Classifier.
    
    This service implements 4-CATEGORY classification:
    - LEGITIMATE: Safe websites
    - PHISHING: Generic phishing attempts
    - AI_GENERATED: Phishing content likely from LLMs
    - PHISHING_KIT: Toolkit detected (Gophish, Evilginx2, etc.)
    """
```

### 4-Category Detection Logic

The service analyzes URLs through several specialized layers:

1.  **Whitelist Layer**: Immediate bypass for trusted domains.
2.  **Typosquatting Layer**: Identifies brand impersonation using the TLD database.
3.  **Toolkit Layer**: Detects signatures of popular phishing frameworks.
4.  **AI Layer**: Analyzes text content for AI generation markers.
5.  **ML Layer**: Random Forest classifier for structural URL features.

### Content-Based Override

A key feature of the service is the **Content-Based Override**. If the ML model flags a URL as phishing based on static features (like a long random string), but the `WebScraper` finds a high-quality website with many links and proper navigation, the service will override the ML model and classify it as **LEGITIMATE**. 

This significantly reduces false positives for legitimate but unusually named domains (e.g., content delivery networks or specialized internal portals).

---

## 2. `api.py` - FastAPI REST Server


Provides HTTP endpoints for the detection service.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API info |
| `/health` | GET | Health check with connectivity status |
| `/api/v1/analyze` | POST | Analyze single URL |
| `/api/v1/batch-analyze` | POST | Analyze multiple URLs |
| `/api/v1/features/{url}` | GET | Extract features only |
| `/api/v1/connectivity` | GET | Check connectivity |

### Example: `/api/v1/analyze`

```python
@app.post("/api/v1/analyze", response_model=URLAnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    result = await phishing_service.analyze_url_async(
        request.url, 
        force_mllm=request.force_scan
    )
    
    return URLAnalysisResponse(
        url=result['url'],
        classification=result['classification'],
        confidence=result['confidence'],
        risk_score=result['risk_score'],
        explanation=result['explanation'],
        analysis_mode=result.get('analysis_mode'),
        scraped=result.get('scraped', False)
    )
```

### Running the API

```bash
cd 04_inference
uvicorn api:app --host 0.0.0.0 --port 8000

# Access docs at http://localhost:8000/docs
```

---

## 3. `schemas.py` - Pydantic Models

Defines the 4-category classification schema and response structures.

```python
class ClassificationResult(str, Enum):
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    AI_GENERATED = "ai_generated_phishing"
    PHISHING_KIT = "phishing_kit"

class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ToolkitSignatures(BaseModel):
    detected: bool
    toolkit_name: Optional[str] = None
    confidence: float
    signatures_found: List[str]
```

---

## How Everything Connects

```
User Request (URL)
       │
       ▼
┌──────────────────┐
│     api.py       │ ← REST endpoint
│  /api/v1/analyze │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   service.py     │ ← Core logic
│ PhishingService  │
│ analyze_url_async│
└────────┬─────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌────────┐
│ ONLINE │ │OFFLINE │
│Scraping│ │Static  │
└────────┘ └────────┘
         │
         ▼
┌──────────────────┐
│   schemas.py     │ ← Response format
│ URLAnalysisResp  │
└──────────────────┘
         │
         ▼
    JSON Response
```

---

*This documentation explains the `04_inference/` folder for beginners.*
