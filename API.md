# 📡 API Documentation

Complete API reference for the Phishing Guard REST API.

## 📋 Table of Contents

- [Base URL](#base-url)
- [Authentication](#authentication)
- [Endpoints](#endpoints)
- [Request/Response Examples](#requestresponse-examples)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)

## 🌐 Base URL

```
Development: http://localhost:8000
Production:  https://your-domain.com/api
```

## 🔐 Authentication

The API uses two authentication methods:

### 1. JWT Bearer Token (User Sessions)

**Obtain Token:**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

**Response:**
```json
{
  "access_token": "<JWT_TOKEN_HERE>",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**Use Token:**
```bash
curl http://localhost:8000/api/v1/analyze \
  -H "Authorization: Bearer <JWT_TOKEN_HERE>"
```

### 2. API Key (Service-to-Service)

**Generate API Key:**
```bash
curl -X POST http://localhost:8000/auth/api-key \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "production-service"}'
```

**Response:**
```json
{
  "api_key": "<YOUR_API_KEY>",
  "name": "production-service",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Use API Key:**
```bash
curl http://localhost:8000/api/v1/analyze \
  -H "X-API-Key: <YOUR_API_KEY>"
```

## 📡 Endpoints

### Public Endpoints (No Authentication Required)

#### Health Check

```http
GET /health
```

Check API health and connectivity status.

**Response:**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "model_loaded": true,
  "ml_model_loaded": true,
  "gpu_available": false,
  "internet_available": true,
  "analysis_mode": "online",
  "classification_categories": [
    "legitimate",
    "phishing", 
    "ai_generated_phishing",
    "phishing_kit"
  ]
}
```

#### Root Endpoint

```http
GET /
```

Get API information.

**Response:**
```json
{
  "name": "Phishing Guard API",
  "version": "2.0.0",
  "description": "AI-powered phishing detection",
  "endpoints": {
    "health": "/health",
    "analyze": "/api/v1/analyze",
    "docs": "/docs"
  }
}
```

#### Check Connectivity

```http
GET /api/v1/connectivity
```

Check internet connectivity and available features.

**Response:**
```json
{
  "status": "online",
  "internet_available": true,
  "analysis_mode": "online",
  "analysis_type": "multimodal",
  "message": "Full analysis available with web scraping and MLLM",
  "available_categories": [
    "legitimate",
    "phishing",
    "ai_generated_phishing",
    "phishing_kit"
  ]
}
```

### Protected Endpoints (Authentication Required)

#### Analyze Single URL

```http
POST /api/v1/analyze
```

Analyze a single URL for phishing threats.

**Request Headers:**
```
Content-Type: application/json
Authorization: Bearer <token>
# OR
X-API-Key: <api_key>
```

**Request Body:**
```json
{
  "url": "https://example.com/login",
  "force_scan": false
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | URL to analyze |
| `force_scan` | boolean | No | Force full MLLM analysis (default: false) |

**Response (200 OK):**
```json
{
  "url": "https://example.com/login",
  "classification": "legitimate",
  "confidence": 0.98,
  "risk_score": 5,
  "explanation": "URL appears legitimate. Domain age: 15 years, valid SSL certificate, no suspicious patterns detected.",
  "features": {
    "url_length": 30,
    "domain_length": 11,
    "is_https": 1,
    "entropy": 3.5,
    "domain_entropy": 2.8,
    "subdomain_count": 0,
    "has_suspicious_words": 0
  },
  "recommended_action": "allow",
  "analysis_mode": "online",
  "scraped": true,
  "toolkit_signatures": null,
  "ai_indicators": null,
  "ml_model_used": true,
  "mllm_used": false
}
```

**Response (Phishing Detected):**
```json
{
  "url": "http://evil-login.example.com",
  "classification": "phishing",
  "confidence": 0.95,
  "risk_score": 92,
  "explanation": "High-risk URL detected. Suspicious domain pattern, recent registration, typosquatting similarity to legitimate domain.",
  "features": {
    "url_length": 45,
    "domain_length": 25,
    "is_https": 0,
    "entropy": 5.2,
    "has_suspicious_words": 1,
    "typosquatting_detected": true
  },
  "recommended_action": "block",
  "analysis_mode": "online",
  "scraped": true,
  "toolkit_signatures": null,
  "ai_indicators": null,
  "ml_model_used": true,
  "mllm_used": false
}
```

#### Batch URL Analysis

```http
POST /api/v1/batch-analyze
```

Analyze multiple URLs in a single request.

**Request Body:**
```json
{
  "urls": [
    "https://example.com",
    "http://suspicious-site.com",
    "https://google.com"
  ]
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `urls` | array | Yes | List of URLs to analyze (max: 100) |

**Response:**
```json
{
  "results": [
    {
      "url": "https://example.com",
      "classification": "legitimate",
      "confidence": 0.98,
      "risk_score": 5,
      "recommended_action": "allow"
    },
    {
      "url": "http://suspicious-site.com",
      "classification": "phishing",
      "confidence": 0.92,
      "risk_score": 88,
      "recommended_action": "block"
    },
    {
      "url": "https://google.com",
      "classification": "legitimate",
      "confidence": 0.99,
      "risk_score": 2,
      "recommended_action": "allow"
    }
  ],
  "total_urls": 3,
  "legitimate_count": 2,
  "phishing_count": 1,
  "ai_generated_count": 0,
  "toolkit_count": 0,
  "analysis_mode": "online"
}
```

#### Extract URL Features

```http
GET /api/v1/features/{url}
```

Extract features from a URL without full classification.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | URL-encoded URL to analyze |

**Example:**
```bash
curl "http://localhost:8000/api/v1/features/https%3A%2F%2Fexample.com" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "url": "https://example.com",
  "features": {
    "url_length": 19,
    "domain_length": 11,
    "path_length": 0,
    "hostname_length": 15,
    "num_dots": 1,
    "num_hyphens": 0,
    "num_slashes": 2,
    "is_https": 1,
    "is_ip_address": 0,
    "subdomain_count": 0,
    "has_suspicious_words": 0,
    "entropy": 3.12,
    "domain_entropy": 2.85
  }
}
```

## 📊 Classification Results

### Classification Categories

| Category | Description | Severity | Color |
|----------|-------------|----------|-------|
| `legitimate` | Safe, authentic website | Safe | 🟢 Green |
| `phishing` | Traditional phishing attack | High | 🔴 Red |
| `ai_generated_phishing` | AI-created phishing (ChatGPT, etc.) | Medium | 🟠 Orange |
| `phishing_kit` | Toolkit-based phishing (Gophish, etc.) | Critical | 🔴 Dark Red |

### Risk Score Interpretation

| Score Range | Level | Action |
|-------------|-------|--------|
| 0-25 | Safe | ✅ Allow |
| 26-50 | Low Risk | ⚠️ Monitor |
| 51-75 | Medium Risk | ⚠️ Warn |
| 76-90 | High Risk | 🚫 Block |
| 91-100 | Critical | 🚫 Block Immediately |

### Recommended Actions

| Action | Description |
|--------|-------------|
| `allow` | URL is safe, proceed |
| `warn` | Suspicious elements detected, user discretion |
| `block` | Phishing detected, prevent access |

## ❌ Error Codes

### HTTP Status Codes

| Status Code | Description | Common Causes |
|-------------|-------------|---------------|
| `200` | OK | Request successful |
| `400` | Bad Request | Invalid URL format, missing parameters |
| `401` | Unauthorized | Missing or invalid authentication |
| `403` | Forbidden | Valid auth but insufficient permissions |
| `404` | Not Found | Endpoint doesn't exist |
| `422` | Validation Error | Request body validation failed |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server error, try again later |

### Error Response Format

```json
{
  "detail": "Error description"
}
```

**Example - Invalid URL:**
```json
{
  "detail": "URL validation failed: Scheme 'file' is not allowed"
}
```

**Example - Rate Limited:**
```json
{
  "detail": "Rate limit exceeded. Try again in 60 seconds."
}
```

**Example - Authentication Required:**
```json
{
  "detail": "Not authenticated"
}
```

## ⏱️ Rate Limiting

Rate limits are enforced per IP address and authentication token.

### Default Limits

| Type | Limit | Window |
|------|-------|--------|
| Public endpoints | 100 requests | Per minute |
| Authenticated endpoints | 100 requests | Per minute |
| Batch analysis | 10 requests | Per minute |

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

### Rate Limit Response

When limit exceeded:
```json
{
  "detail": "Rate limit exceeded",
  "retry_after": 45
}
```

Status code: `429 Too Many Requests`

## 💻 Code Examples

### Python

```python
import requests

# Configuration
BASE_URL = "http://localhost:8000"
API_KEY = "<YOUR_API_KEY>"

# Analyze single URL
response = requests.post(
    f"{BASE_URL}/api/v1/analyze",
    headers={"X-API-Key": API_KEY},
    json={"url": "https://example.com"}
)

result = response.json()
print(f"Classification: {result['classification']}")
print(f"Risk Score: {result['risk_score']}")
print(f"Action: {result['recommended_action']}")

# Batch analysis
urls = ["https://site1.com", "https://site2.com"]
response = requests.post(
    f"{BASE_URL}/api/v1/batch-analyze",
    headers={"X-API-Key": API_KEY},
    json={"urls": urls}
)

results = response.json()
for item in results['results']:
    print(f"{item['url']}: {item['classification']}")
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:8000';
const API_KEY = '<YOUR_API_KEY>';

// Analyze single URL
async function analyzeURL(url) {
  try {
    const response = await axios.post(
      `${BASE_URL}/api/v1/analyze`,
      { url },
      { headers: { 'X-API-Key': API_KEY } }
    );
    
    console.log('Classification:', response.data.classification);
    console.log('Risk Score:', response.data.risk_score);
    return response.data;
  } catch (error) {
    console.error('Error:', error.response?.data?.detail || error.message);
  }
}

// Batch analysis
async function analyzeBatch(urls) {
  try {
    const response = await axios.post(
      `${BASE_URL}/api/v1/batch-analyze`,
      { urls },
      { headers: { 'X-API-Key': API_KEY } }
    );
    
    response.data.results.forEach(item => {
      console.log(`${item.url}: ${item.classification}`);
    });
  } catch (error) {
    console.error('Error:', error.response?.data?.detail || error.message);
  }
}

// Usage
analyzeURL('https://example.com');
```

### cURL

```bash
#!/bin/bash

API_KEY="<YOUR_API_KEY>"
BASE_URL="http://localhost:8000"

# Health check
curl -s "$BASE_URL/health" | jq

# Analyze URL
curl -s -X POST "$BASE_URL/api/v1/analyze" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}' | jq

# Batch analysis
curl -s -X POST "$BASE_URL/api/v1/batch-analyze" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://example.com",
      "https://google.com"
    ]
  }' | jq
```

### PowerShell

```powershell
$ApiKey = "<YOUR_API_KEY>"
$BaseUrl = "http://localhost:8000"

# Analyze URL
$Headers = @{
    "X-API-Key" = $ApiKey
    "Content-Type" = "application/json"
}

$Body = @{
    url = "https://example.com"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "$BaseUrl/api/v1/analyze" -Method Post -Headers $Headers -Body $Body
Write-Output "Classification: $($response.classification)"
Write-Output "Risk Score: $($response.risk_score)"
```

## 📚 Additional Resources

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI Spec:** http://localhost:8000/openapi.json

## 🔗 Browser Extension Integration

The browser extension uses the same API:

```javascript
// browser-extension/content.js
async function checkURL(url) {
  const API_URL = 'http://localhost:8000/api/v1/analyze';
  
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': '<YOUR_API_KEY>'
    },
    body: JSON.stringify({ url })
  });
  
  return await response.json();
}
```

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/BandiAkarsh/phishing_detection_project/issues)
- **Email:** akarshbandi82@gmail.com

---

**API Version:** 2.0.0  
**Last Updated:** 2024-01-01
