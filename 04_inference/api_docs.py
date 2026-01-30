"""
API Documentation Generator

Generates OpenAPI/Swagger documentation for the Phishing Detection API.
Can be served at /docs or /openapi.json
"""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi


def generate_api_docs(app: FastAPI) -> dict:
    """
    Generate OpenAPI documentation for the API.
    
    Returns:
        dict: OpenAPI specification
    """
    
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="Phishing Guard API",
        version="2.0.0",
        description="""
# Phishing Guard API

AI-powered phishing detection service with multimodal analysis.

## Features

- **Multimodal Detection**: Combines ML, typosquatting, and MLLM analysis
- **Real-time Protection**: Instant URL scanning with threat classification
- **4-Category Classification**:
  - 🟢 **Legitimate**: Safe websites
  - 🔴 **Phishing**: Traditional attacks  
  - 🟠 **AI-Generated Phishing**: AI-created content
  - 🚨 **Phishing Kit**: Toolkit-based attacks

## Authentication

This API uses JWT Bearer tokens for authentication.

### Getting a Token

1. Use the `/auth/login` endpoint with your credentials
2. Include the token in the Authorization header:
   ```
   Authorization: Bearer <your-jwt-token>
   ```

3. Tokens expire after 24 hours

## Rate Limiting

- **Limit**: 100 requests per minute per IP
- **Headers**: Check `X-RateLimit-Remaining` for remaining requests
- **Error**: HTTP 429 when limit exceeded

## Analysis Modes

The API automatically selects the best analysis method:

- **Online Mode** (when internet available):
  - Full web scraping
  - Content analysis
  - TLS certificate validation
  - Most accurate results

- **Offline Mode** (no internet):
  - Static URL feature analysis
  - Heuristic detection
  - Faster but less accurate

## Security Features

- 🔐 JWT Authentication
- 🛡️ SSRF Protection (private IP blocking)
- 🔒 TLS 1.3 enforcement
- 📊 Certificate Transparency verification
- 🚫 Rate limiting
- 🔍 Input validation

## Quick Start

```bash
# 1. Start the API
python 04_inference/api.py

# 2. Get authentication token
curl -X POST http://localhost:8000/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "user", "password": "pass"}'

# 3. Scan a URL
curl -X POST http://localhost:8000/api/v1/analyze \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com"}'
```

## Error Codes

| Code | Meaning | Resolution |
|------|---------|------------|
| 400 | Bad Request | Check URL format |
| 401 | Unauthorized | Get valid JWT token |
| 429 | Rate Limited | Wait and retry |
| 503 | Service Unavailable | Check if service is running |

## Support

For issues and feature requests, please use GitHub Issues.
        """,
        routes=app.routes,
    )
    
    # Add custom documentation for schemas
    openapi_schema["components"]["schemas"]["URLAnalysisResponse"]["description"] = """
Response from URL analysis containing classification and risk assessment.

**Classification Values:**
- `legitimate`: Safe website
- `phishing`: Traditional phishing attack
- `ai_generated_phishing`: AI-created phishing content
- `phishing_kit`: Phishing toolkit signature detected

**Risk Score Interpretation:**
- 0-30: Low risk (likely legitimate)
- 31-70: Medium risk (suspicious, review recommended)
- 71-100: High risk (likely malicious)
    """
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


# Security schemes
security_schemes = {
    "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "JWT token obtained from /auth/login endpoint"
    }
}

# Example responses
example_responses = {
    "legitimate": {
        "url": "https://google.com",
        "classification": "legitimate",
        "confidence": 0.98,
        "risk_score": 5,
        "explanation": "Well-known legitimate domain with proper HTTPS configuration",
        "features": {
            "url_length": 18,
            "domain_age_days": 9000,
            "uses_https": True
        },
        "recommended_action": "allow",
        "analysis_mode": "online",
        "scraped": True
    },
    "phishing": {
        "url": "https://paypa1-secure.com/login",
        "classification": "phishing",
        "confidence": 0.95,
        "risk_score": 85,
        "explanation": "Typosquatting detected (paypa1 vs paypal). Domain registered recently.",
        "features": {
            "is_typosquatting": True,
            "impersonated_brand": "paypal",
            "domain_age_days": 2
        },
        "recommended_action": "block",
        "analysis_mode": "online",
        "scraped": True
    },
    "ai_generated": {
        "url": "https://login-secure-verify.tk",
        "classification": "ai_generated_phishing",
        "confidence": 0.88,
        "risk_score": 72,
        "explanation": "AI-generated content patterns detected. Generic urgency language found.",
        "features": {
            "ai_content_score": 0.75,
            "urgency_keywords": ["verify", "immediately", "secure"]
        },
        "recommended_action": "warn",
        "analysis_mode": "online",
        "scraped": True
    }
}

# API endpoint examples
endpoint_examples = {
    "/auth/login": {
        "summary": "Authenticate and get JWT token",
        "description": "Obtain a JWT token for API access. Token expires after 24 hours.",
        "request": {
            "username": "user@example.com",
            "password": "your_password"
        },
        "response": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer",
            "expires_in": 86400
        }
    },
    
"/api/v1/analyze": {
        "summary": "Analyze URL for phishing",
        "description": "Comprehensive URL analysis with multimodal detection",
        "security": [{"bearerAuth": []}],
        "request": {
            "url": "https://example.com",
            "force_scan": False
        },
        "responses": example_responses
    },
    
"/api/v1/batch-analyze": {
        "summary": "Analyze multiple URLs",
        "description": "Batch processing for up to 100 URLs",
        "security": [{"bearerAuth": []}],
        "request": {
            "urls": [
                "https://example1.com",
                "https://example2.com"
            ]
        },
        "response": {
            "results": [example_responses["legitimate"]],
            "total_urls": 2,
            "phishing_count": 0,
            "legitimate_count": 1
        }
    },
    
"/health": {
        "summary": "Health check",
        "description": "Check API health and connectivity status",
        "response": {
            "status": "healthy",
            "version": "2.0.0",
            "model_loaded": True,
            "gpu_available": True,
            "internet_available": True,
            "analysis_mode": "online"
        }
    }
}
