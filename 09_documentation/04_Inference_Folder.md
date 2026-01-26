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
    
    This service implements INTERNET-AWARE detection:
    - When online: Scrapes websites and uses content-based analysis
    - When offline: Falls back to static URL heuristics
    """
```

### Key Methods

#### `__init__(self, load_mllm=False, load_ml_model=True)`

Initializes the service and loads models.

```python
def __init__(self, load_mllm=False, load_ml_model=True):
    # Initialize feature extractors
    self.url_extractor = URLFeatureExtractor()
    self.typosquatting_detector = TyposquattingDetector()
    
    # Check internet connectivity
    self.connectivity_monitor = ConnectivityMonitor(check_interval=30)
    self._is_online = self.connectivity_monitor.is_online
    
    # Load ML model
    if load_ml_model:
        self.ml_model = joblib.load('phishing_classifier.joblib')
        self.ml_scaler = joblib.load('feature_scaler.joblib')
        self.ml_feature_cols = joblib.load('feature_columns.joblib')
```

**What happens:**
1. Creates URL feature extractor
2. Creates typosquatting detector
3. Checks internet connectivity
4. Loads trained ML model

---

#### `analyze_url_async(self, url, force_mllm=False)`

The main analysis method. Uses internet-aware detection.

```python
async def analyze_url_async(self, url: str, force_mllm: bool = False) -> dict:
    # Check whitelist first
    if domain_part in self.WHITELISTED_DOMAINS:
        return self._create_whitelist_result(url, domain_part)
    
    # Check connectivity
    if self.is_online:
        # ONLINE: Full web scraping analysis
        return await self._analyze_with_scraping(url, force_mllm)
    else:
        # OFFLINE: Static analysis fallback
        return self._analyze_static_fallback(url, force_mllm)
```

**Decision flow:**
1. Is domain whitelisted? → Return "legitimate" immediately
2. Is internet available? → Use web scraping
3. No internet? → Use static URL analysis

---

#### `_analyze_with_scraping(self, url, force_mllm=False)`

Full multimodal analysis when ONLINE.

```python
async def _analyze_with_scraping(self, url: str, force_mllm: bool = False) -> dict:
    # Check typosquatting first
    typosquat_result = self.typosquatting_detector.analyze(url)
    
    # If obvious TLD typo, skip scraping
    if typosquat_result.get('detection_method') in ['faulty_extension', 'invalid_extension']:
        return self._create_typosquat_result(url, typosquat_result)
    
    # Attempt web scraping
    scraper = WebScraper(headless=True, timeout=30000)
    scrape_result = await scraper.scrape_url(url)
    
    if scrape_result['success']:
        # Analyze based on CONTENT (ignores static URL heuristics!)
        return self._analyze_scraped_content(url, scrape_result, typosquat_result)
    else:
        # Site unreachable
        return self._analyze_unreachable_site(url, typosquat_result)
```

**Key insight:** When scraping succeeds, we IGNORE the vowel/consonant heuristics because we have actual content to analyze.

---

#### `_analyze_scraped_content(self, url, scrape_result, typosquat_result, proof, force_mllm=False)`

Analyzes based on ACTUAL WEBSITE CONTENT.

```python
def _analyze_scraped_content(self, url, scrape_result, typosquat_result, proof, force_mllm=False):
    html_summary = scrape_result.get('dom_structure', {})
    
    risk_score = 0
    risk_factors = []
    
    # Factor 1: Typosquatting (brand impersonation)
    if typosquat_result.get('is_typosquatting'):
        risk_score += 60
        risk_factors.append("Brand impersonation detected")
    
    # Factor 2: Login form detection
    if html_summary.get('has_login_form'):
        if typosquat_result.get('is_typosquatting'):
            risk_score += 30  # Login form + brand impersonation = dangerous!
    
    # Factor 3: Minimal content (phishing landing page)
    if num_links < 3 and num_images < 2 and not title:
        risk_score += 20
    
    # CREDIBILITY BONUS: Valid website with substantial content
    if num_links >= 10 and title:
        risk_score = max(0, risk_score - 40)  # Reduce risk!
```

**Why this is better than static analysis:**
- A URL like "xyzabc123.com" might look suspicious statically
- But if it loads with 50 links, images, and a proper title, it's likely legitimate
- Content validation overrides static heuristics

---

#### `_analyze_static_fallback(self, url, force_mllm=False)`

Fallback when OFFLINE (no internet).

```python
def _analyze_static_fallback(self, url: str, force_mllm: bool = False) -> dict:
    print(f"[OFFLINE MODE] Static analysis for {url}...")
    
    # Extract URL features (includes vowel/consonant analysis)
    url_features = self.url_extractor.extract_features(url)
    typosquat_result = self.typosquatting_detector.analyze(url)
    
    # ML Model prediction
    ml_prediction, ml_confidence = self._predict_with_ml(url_features)
    
    # Calculate risk using ALL static heuristics
    risk_score = self._calculate_risk_score(url_features, typosquat_result, ml_prediction, ml_confidence)
    
    # Mark as offline mode
    explanation = f"[OFFLINE MODE] {explanation}"
```

**This is where vowel/consonant checks are used:**
- `is_random_domain` flag is checked
- High entropy domains are penalized
- Results are marked as less confident

---

#### `_calculate_risk_score(self, features, typosquat, ml_pred, ml_conf)`

Calculates risk score 0-100 based on features.

```python
def _calculate_risk_score(self, features, typosquat, ml_pred, ml_conf):
    score = 0
    
    # ML prediction (strongest signal)
    if ml_pred == 1:
        score += int(ml_conf * 50)  # Up to 50 points
    
    # Typosquatting
    if typosquat.get('is_typosquatting'):
        score += typosquat.get('risk_increase', 50)
    
    # URL length
    if features.get('url_length', 0) > 75:
        score += 10
    
    # Random domain (vowel/consonant check) - ONLY USED OFFLINE
    if features.get('is_random_domain'):
        score += 45  # High penalty
    
    return min(100, score)
```

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

Defines request/response data structures.

```python
class ClassificationResult(str, Enum):
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"

class URLAnalysisRequest(BaseModel):
    url: str
    force_scan: bool = False

class URLAnalysisResponse(BaseModel):
    url: str
    classification: ClassificationResult
    confidence: float  # 0.0 to 1.0
    risk_score: float  # 0 to 100
    explanation: str
    features: dict
    recommended_action: str  # "block", "warn", "allow"
    analysis_mode: Optional[str] = None  # "online", "offline", "whitelist"
    scraped: Optional[bool] = False
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
