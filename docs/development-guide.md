# 👨‍💻 Development Guide

Comprehensive guide for developers working on Phishing Guard.

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Adding New Features](#adding-new-features)
- [Testing Guide](#testing-guide)
- [Debugging Tips](#debugging-tips)
- [Troubleshooting](#troubleshooting)

## 🏗️ Architecture Overview

Phishing Guard uses a **layered architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────┐
│           Presentation Layer                 │
│  (CLI, API, Browser Extension, GUI)         │
├─────────────────────────────────────────────┤
│           Application Layer                  │
│  (Authentication, Rate Limiting, Validation)│
├─────────────────────────────────────────────┤
│           Business Logic Layer               │
│  (Detection Pipeline, Feature Extraction)   │
├─────────────────────────────────────────────┤
│           Data Layer                         │
│  (ML Models, Redis, File System)            │
└─────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose | Location |
|-----------|---------|----------|
| **API** | FastAPI REST endpoints | `04_inference/api.py` |
| **Auth** | JWT & API key management | `04_inference/auth.py` |
| **Service** | Detection orchestration | `04_inference/service.py` |
| **Feature Extractor** | 93-feature extraction | `05_utils/feature_extraction.py` |
| **Security Validator** | SSRF & input validation | `05_utils/security_validator.py` |
| **ML Trainer** | Model training & MLflow | `03_training/train_with_mlflow.py` |
| **Model Manager** | Model loading & registry | `03_training/model_manager.py` |

## 📁 Project Structure

```
phishing_detection_project/
├── 📂 01_data/                    # Datasets and TLD lists
│   ├── phishing_urls.csv
│   ├── legitimate_urls.csv
│   └── tlds.txt
│
├── 📂 02_models/                  # Trained ML models
│   ├── phishing_classifier.joblib
│   ├── scaler.joblib
│   └── feature_columns.json
│
├── 📂 03_training/                # Training scripts
│   ├── train_with_mlflow.py      # Main training script
│   ├── model_manager.py          # Model registry client
│   └── dataset.py                # Data loading utilities
│
├── 📂 04_inference/               # API and inference
│   ├── api.py                    # FastAPI application
│   ├── auth.py                   # Authentication module
│   ├── service.py                # Detection service
│   ├── schemas.py                # Pydantic models
│   └── bentoml_service.py        # BentoML alternative
│
├── 📂 05_utils/                   # Utilities
│   ├── feature_extraction.py     # URL feature extraction
│   ├── security_validator.py     # SSRF protection
│   ├── tls_analyzer.py           # TLS certificate analysis
│   ├── web_scraper.py            # Web scraping
│   ├── typosquatting_detector.py # Typosquatting detection
│   ├── url_extractor.py          # URL parsing utilities
│   ├── mllm_transformer.py       # Multi-modal LLM
│   └── connectivity.py           # Internet connectivity
│
├── 📂 06_notebooks/               # Jupyter notebooks
│   └── analysis.ipynb
│
├── 📂 07_configs/                 # Configuration files
│   └── logging.conf
│
├── 📂 08_logs/                    # Logs and MLflow
│   ├── api.log
│   └── mlruns/
│
├── 📂 09_documentation/           # Architecture documentation
│
├── 📂 browser-extension/          # Chrome/Firefox extension
│   ├── manifest.json
│   ├── content.js
│   ├── popup.html
│   └── popup.js
│
├── 📂 gui-tauri/                  # Desktop application (reference)
│
├── 📂 docs/                       # Project documentation
│   ├── REFERENCE_DOCUMENT.md
│   ├── FINAL_REPORT.md
│   ├── development-guide.md      # This file
│   └── architecture.md           # Technical architecture
│
├── 📂 examples/                   # Example files
│
├── 📂 scripts/                    # Build and utility scripts
│   └── setup_dev.sh
│
├── 📂 tests/                      # Test files
│   ├── send_ai_test.py
│   └── trigger_alert.py
│
├── 🐳 Dockerfile                  # Container definition
├── 📋 docker-compose.yml          # Multi-container orchestration
├── 📋 pyproject.toml              # Tool configurations
├── 📋 Makefile                    # Development commands
├── 📋 requirements.txt            # Production dependencies
├── 📋 requirements-dev.txt        # Development dependencies
├── 📋 .env.example                # Environment template
├── 📋 .pre-commit-config.yaml     # Git hooks
├── 🐍 detect_enhanced.py          # Enhanced CLI
├── 🐍 email_scanner.py            # Email monitoring
├── 🐍 test_security.py            # Security tests
└── 🐍 test_comprehensive.py       # Comprehensive tests
```

## ➕ Adding New Features

### Adding a New API Endpoint

1. **Define the schema** in `04_inference/schemas.py`:

```python
class NewFeatureRequest(BaseModel):
    """Request model for new feature."""
    url: str = Field(..., description="URL to process")
    option: bool = Field(False, description="Optional flag")

class NewFeatureResponse(BaseModel):
    """Response model for new feature."""
    url: str
    result: str
    success: bool
```

2. **Implement the endpoint** in `04_inference/api.py`:

```python
from schemas import NewFeatureRequest, NewFeatureResponse

@app.post("/api/v1/new-feature", response_model=NewFeatureResponse)
async def new_feature(
    request: NewFeatureRequest,
    current_user: str = Depends(get_current_user)
):
    """
    Description of the new feature endpoint.
    
    Args:
        request: NewFeatureRequest with URL and options
        current_user: Authenticated user
        
    Returns:
        NewFeatureResponse with results
    """
    # Validate URL
    is_valid, errors = validate_url_for_analysis(request.url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {errors}")
    
    # Implement feature logic
    result = await process_new_feature(request.url, request.option)
    
    return NewFeatureResponse(
        url=request.url,
        result=result,
        success=True
    )
```

3. **Add tests**:

```python
# tests/test_new_feature.py
import pytest
from fastapi.testclient import TestClient

@pytest.mark.unit
def test_new_feature_success(client: TestClient):
    """Test new feature with valid input."""
    response = client.post(
        "/api/v1/new-feature",
        headers={"Authorization": "Bearer test_token"},
        json={"url": "https://example.com", "option": True}
    )
    assert response.status_code == 200
    assert response.json()["success"] is True

@pytest.mark.unit
def test_new_feature_invalid_url(client: TestClient):
    """Test new feature with invalid URL."""
    response = client.post(
        "/api/v1/new-feature",
        headers={"Authorization": "Bearer test_token"},
        json={"url": "not-a-url"}
    )
    assert response.status_code == 400
```

### Adding a New Feature Extractor

1. **Add feature extraction logic** in `05_utils/feature_extraction.py`:

```python
class URLFeatureExtractor:
    @staticmethod
    def extract_features(url, include_tls=False):
        features = {}
        
        # Existing features...
        
        # NEW: Your custom feature
        features['new_feature'] = URLFeatureExtractor._calculate_new_feature(url)
        
        return features
    
    @staticmethod
    def _calculate_new_feature(url):
        """
        Calculate your new feature.
        
        Args:
            url: URL string
            
        Returns:
            float: Feature value
        """
        # Implement feature calculation
        parsed = urlparse(url)
        # ... your logic here
        return value
```

2. **Update feature columns**:

```python
# In training script or feature extractor
FEATURE_COLUMNS = [
    # ... existing columns
    'new_feature',  # Add your new feature
]
```

3. **Retrain model** to include the new feature:

```bash
python 03_training/train_with_mlflow.py
```

### Adding a New Authentication Method

1. **Add authentication logic** in `04_inference/auth.py`:

```python
class AuthManager:
    def authenticate_oauth(self, provider: str, token: str):
        """
        OAuth authentication.
        
        Args:
            provider: OAuth provider (google, github, etc.)
            token: OAuth access token
            
        Returns:
            dict: User information and JWT token
        """
        if provider == "google":
            user_info = self._verify_google_token(token)
        elif provider == "github":
            user_info = self._verify_github_token(token)
        else:
            raise HTTPException(status_code=400, detail="Unsupported provider")
        
        # Create or get user
        user_id = self._get_or_create_user(user_info)
        
        # Generate JWT
        jwt_token = self.create_token(user_id)
        
        return {
            "access_token": jwt_token,
            "token_type": "bearer",
            "user": user_info
        }
```

2. **Add endpoint**:

```python
@app.post("/auth/oauth/{provider}")
async def oauth_login(provider: str, token: str):
    """OAuth login endpoint."""
    return auth_manager.authenticate_oauth(provider, token)
```

## 🧪 Testing Guide

### Running Tests

```bash
# All tests
make test
# or
pytest tests/ -v

# Specific test file
pytest tests/test_unit.py -v

# Specific test
pytest tests/test_unit.py::test_feature_extraction -v

# With coverage
make coverage
# or
pytest tests/ --cov=04_inference --cov=05_utils --cov-report=html
```

### Writing Tests

#### Unit Tests

```python
# tests/test_feature_extraction.py
import pytest
from 05_utils.feature_extraction import URLFeatureExtractor

@pytest.mark.unit
class TestFeatureExtraction:
    """Test feature extraction functionality."""
    
    def test_url_length_feature(self):
        """Test URL length calculation."""
        url = "https://example.com/path"
        features = URLFeatureExtractor.extract_features(url)
        assert features['url_length'] == len(url)
    
    def test_https_detection(self):
        """Test HTTPS detection."""
        https_url = "https://example.com"
        http_url = "http://example.com"
        
        https_features = URLFeatureExtractor.extract_features(https_url)
        http_features = URLFeatureExtractor.extract_features(http_url)
        
        assert https_features['is_https'] == 1
        assert http_features['is_https'] == 0
    
    @pytest.mark.parametrize("url,expected_entropy", [
        ("https://example.com", 3.12),
        ("https://x.com", 1.58),
    ])
    def test_entropy_calculation(self, url, expected_entropy):
        """Test entropy calculation with various URLs."""
        features = URLFeatureExtractor.extract_features(url)
        assert abs(features['entropy'] - expected_entropy) < 0.1
```

#### Integration Tests

```python
# tests/test_api_integration.py
import pytest
from fastapi.testclient import TestClient
from 04_inference.api import app

@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)

@pytest.mark.integration
class TestAPIIntegration:
    """Test API integration."""
    
    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_analyze_endpoint_with_auth(self, client):
        """Test analyze endpoint with authentication."""
        # Get token
        login_response = client.post(
            "/auth/login",
            json={"username": "test", "password": "test"}
        )
        token = login_response.json()["access_token"]
        
        # Analyze URL
        response = client.post(
            "/api/v1/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={"url": "https://example.com"}
        )
        assert response.status_code == 200
        assert "classification" in response.json()
```

#### Security Tests

```python
# tests/test_security.py
import pytest
from 05_utils.security_validator import URLSecurityValidator

@pytest.mark.security
class TestSecurity:
    """Test security features."""
    
    def test_ssrf_protection_private_ip(self):
        """Test SSRF protection blocks private IPs."""
        validator = URLSecurityValidator()
        
        private_urls = [
            "http://192.168.1.1/admin",
            "http://10.0.0.1/config",
            "http://127.0.0.1/secrets",
        ]
        
        for url in private_urls:
            is_valid, errors = validator.validate(url)
            assert not is_valid
            assert any("private" in e.lower() for e in errors)
    
    def test_blocked_schemes(self):
        """Test dangerous URL schemes are blocked."""
        validator = URLSecurityValidator()
        
        dangerous_urls = [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        
        for url in dangerous_urls:
            is_valid, errors = validator.validate(url)
            assert not is_valid
```

### Mocking External Services

```python
# tests/test_with_mocks.py
import pytest
from unittest.mock import Mock, patch

@pytest.mark.unit
def test_analyze_with_mocked_scraper():
    """Test analysis with mocked web scraper."""
    with patch('05_utils.web_scraper.WebScraper.scrape') as mock_scrape:
        mock_scrape.return_value = {
            "title": "Example Domain",
            "content": "This domain is for use in examples.",
            "status": 200
        }
        
        # Run analysis
        result = analyze_url("https://example.com")
        
        # Verify scraper was called
        mock_scrape.assert_called_once_with("https://example.com")
        
        # Check result
        assert result["scraped"] is True
```

## 🐛 Debugging Tips

### API Debugging

```python
# Enable debug mode
ENVIRONMENT=development DEBUG=true python 04_inference/api.py

# Add logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Use pdb
import pdb; pdb.set_trace()
```

### Common Debugging Commands

```bash
# Check API is running
curl http://localhost:8000/health

# Test with verbose output
curl -v http://localhost:8000/api/v1/analyze \
  -H "Authorization: Bearer <token>" \
  -d '{"url": "https://example.com"}'

# Check logs
docker-compose logs -f api

# View recent errors
grep ERROR 08_logs/api.log | tail -20
```

### Using Python Debugger

```python
# In your code
def analyze_url(url):
    import pdb; pdb.set_trace()  # Breakpoint
    
    # Code continues here after debugging
    features = extract_features(url)
    return features

# Common pdb commands:
# n - next line
# s - step into function
# c - continue
# p variable - print variable
# l - list code
# q - quit
```

### FastAPI Debug Mode

```python
# 04_inference/api.py
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes
        log_level="debug"
    )
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue: Model Not Found

**Symptoms:**
```
FileNotFoundError: [Errno 2] No such file or directory: '02_models/phishing_classifier.joblib'
```

**Solutions:**
```bash
# Train new model
python 03_training/train_with_mlflow.py

# Or download pre-trained model
wget https://models.phishing-guard.com/phishing_classifier.joblib -O 02_models/
```

#### Issue: Redis Connection Failed

**Symptoms:**
```
redis.exceptions.ConnectionError: Error 111 connecting to localhost:6379
```

**Solutions:**
```bash
# Start Redis
docker-compose up -d redis

# Or install Redis locally
sudo apt-get install redis-server
sudo service redis-server start

# Check Redis status
redis-cli ping  # Should return PONG
```

#### Issue: JWT Secret Not Set

**Symptoms:**
```
RuntimeWarning: JWT_SECRET environment variable not set
```

**Solutions:**
```bash
# Generate and set JWT secret
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

# Or add to .env file
echo "JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")" >> .env
```

#### Issue: Port Already in Use

**Symptoms:**
```
OSError: [Errno 98] Address already in use: ('0.0.0.0', 8000)
```

**Solutions:**
```bash
# Find process using port 8000
sudo lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use different port
python 04_inference/api.py --port 8001
```

#### Issue: Import Errors

**Symptoms:**
```
ModuleNotFoundError: No module named '04_inference'
```

**Solutions:**
```bash
# Ensure you're in project root
cd /home/akarsh/college-final-yr-projects/phishing_detection_project

# Check Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Reinstall dependencies
pip install -r requirements.txt
```

#### Issue: Pre-commit Hooks Failing

**Symptoms:**
```
black.............................................................Failed
```

**Solutions:**
```bash
# Run hooks manually to see errors
pre-commit run --all-files

# Fix formatting
make format

# Skip hooks temporarily (not recommended)
git commit -m "message" --no-verify
```

#### Issue: Tests Failing

**Symptoms:**
```
FAILED tests/test_api.py::test_analyze - assert 401 == 200
```

**Solutions:**
```bash
# Run specific test with verbose output
pytest tests/test_api.py::test_analyze -v -s

# Check test environment
python -c "import sys; print(sys.path)"

# Reset test database/cache
rm -rf .pytest_cache
pytest tests/ --cache-clear
```

### Performance Debugging

```python
# Profile code
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Your code here
result = analyze_url("https://example.com")

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)  # Top 20 functions
```

### Memory Debugging

```python
# Check memory usage
import psutil
import os

process = psutil.Process(os.getpid())
print(f"Memory: {process.memory_info().rss / 1024 / 1024:.2f} MB")

# Track memory over time
import tracemalloc
tracemalloc.start()

# Your code here
analyze_url("https://example.com")

current, peak = tracemalloc.get_traced_memory()
print(f"Current: {current / 1024 / 1024:.2f} MB")
print(f"Peak: {peak / 1024 / 1024:.2f} MB")
tracemalloc.stop()
```

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [scikit-learn Documentation](https://scikit-learn.org/)
- [MLflow Documentation](https://mlflow.org/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [pytest Documentation](https://docs.pytest.org/)

---

**Guide Version:** 2.0.0  
**Last Updated:** 2024-01-01
