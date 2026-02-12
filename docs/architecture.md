# 🏗️ Architecture Documentation

Technical architecture and design documentation for Phishing Guard.

## 📋 Table of Contents

- [System Architecture](#system-architecture)
- [Component Interactions](#component-interactions)
- [Data Flow](#data-flow)
- [ML Pipeline](#ml-pipeline)
- [Security Architecture](#security-architecture)

## 🏛️ System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   CLI Tool   │  │   Web API    │  │   Browser    │  │    Email     │ │
│  │              │  │   (REST)     │  │  Extension   │  │   Scanner    │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
└─────────┼────────────────┼────────────────┼────────────────┼─────────┘
          │                │                │                │
          └────────────────┴────────────────┴────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   LOAD BALANCER     │
                    │     (Nginx)         │
                    └──────────┬──────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                         API LAYER                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    FastAPI Application                           │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │   │
│  │  │  Rate Limiter│  │  Auth Manager│  │   Request Validator  │   │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                      DETECTION PIPELINE                                  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  TIER 1: STATIC ANALYSIS (Fast, < 10ms)                          │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   URL Parser    │  │  Typosquatting  │  │   IDN/Honograph │   │   │
│  │  │   Validation    │  │    Detection    │  │    Detection    │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  └──────────────────────────────┬───────────────────────────────────┘   │
│                                 │                                       │
│  ┌──────────────────────────────▼──────────────────────────────────┐   │
│  │  TIER 2: ML CLASSIFICATION (Medium, ~100ms)                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │   │
│  │  │ Feature Extraction│ │ ML Model        │ │ Post-Processing │  │   │
│  │  │  (93 Features)  │  │ (Random Forest) │  │                 │  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │   │
│  └──────────────────────────────┬───────────────────────────────────┘   │
│                                 │                                       │
│  ┌──────────────────────────────▼──────────────────────────────────┐   │
│  │  TIER 3: MLLM ANALYSIS (Slow, ~2s, Optional)                    │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │   │
│  │  │  Web Scraping   │  │  Content        │  │  MLLM           │  │   │
│  │  │  (Playwright)   │  │  Analysis       │  │  (Qwen)         │  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                         DATA LAYER                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐      │
│  │   ML Models      │  │     Redis        │  │   MLflow         │      │
│  │   (joblib)       │  │   (Cache/Queue)  │  │   (Registry)     │      │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      API Gateway (Nginx)                        │
│              SSL/TLS, Rate Limiting, Load Balancing             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Application                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │   Routers   │ │ Middleware  │ │  Services   │ │  Models   │ │
│  │             │ │             │ │             │ │           │ │
│  │ /health     │ │ CORS        │ │ Detection   │ │ Pydantic  │ │
│  │ /auth/*     │ │ Rate Limit  │ │ Auth        │ │ Schemas   │ │
│  │ /api/v1/*   │ │ Logging     │ │ ML Pipeline │ │           │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Detection Service                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │   Preprocessor│ │  Classifier │ │ Postprocessor│ │ Response  │ │
│  │             │ │             │ │             │ │ Builder   │ │
│  │ - Validate  │ │ - ML Model  │ │ - Risk Score │ │ - Format  │ │
│  │ - Sanitize  │ │ - MLLM      │ │ - Severity   │ │ - Enrich  │ │
│  │ - Enrich    │ │ - Ensemble  │ │ - Action     │ │ - Return  │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 🔗 Component Interactions

### Authentication Flow

```
User                        API                        Auth Manager
  │                           │                              │
  │  POST /auth/login         │                              │
  │  {username, password}     │                              │
  │──────────────────────────>│                              │
  │                           │  validate_credentials()      │
  │                           │─────────────────────────────>│
  │                           │                              │
  │                           │  {valid: true, user_id}      │
  │                           │<─────────────────────────────│
  │                           │                              │
  │                           │  create_token(user_id)       │
  │                           │─────────────────────────────>│
  │                           │                              │
  │  {access_token}           │  JWT Token                   │
  │<──────────────────────────│<─────────────────────────────│
  │                           │                              │
  │                           │                              │
  │  POST /api/v1/analyze     │                              │
  │  Authorization: Bearer    │                              │
  │──────────────────────────>│                              │
  │                           │  verify_token()              │
  │                           │─────────────────────────────>│
  │                           │                              │
  │                           │  {user_id, valid}            │
  │                           │<─────────────────────────────│
  │                           │                              │
  │  {classification}         │                              │
  │<──────────────────────────│                              │
```

### Detection Pipeline Flow

```
Request                        Processing                    Response
   │                               │                            │
   │  POST /api/v1/analyze         │                            │
   │  {url: "..."}                 │                            │
   ├──────────────────────────────>│                            │
   │                               │                            │
   │                          ┌────┴────┐                       │
   │                          │ Validate│                       │
   │                          │  URL    │                       │
   │                          └────┬────┘                       │
   │                               │                            │
   │                          ┌────┴────┐                       │
   │                          │  Check  │                       │
   │                          │ Whitelist                       │
   │                          └────┬────┘                       │
   │                               │                            │
   │                          ┌────┴────┐                       │
   │                          │ Tier 1: │                       │
   │                          │ Static  │                       │
   │                          │ Analysis│                       │
   │                          └────┬────┘                       │
   │                               │                            │
   │                          ┌────┴────┐                       │
   │                          │ Tier 2: │                       │
   │                          │   ML    │                       │
   │                          │ Classify│                       │
   │                          └────┬────┘                       │
   │                               │                            │
   │                          ┌────┴────┐                       │
   │                          │ Tier 3: │                       │
   │                          │  MLLM   │                       │
   │                          │(Optional)                       │
   │                          └────┬────┘                       │
   │                               │                            │
   │                               │                            │
   │                          ┌────┴────┐                       │
   │                          │Aggregate│                       │
   │                          │ Results │                       │
   │                          └────┬────┘                       │
   │                               │                            │
   │  {classification,             │                            │
   │   confidence,                 │                            │
   │   risk_score}                 │                            │
   │<──────────────────────────────┤                            │
```

### Service Dependencies

```
┌─────────────────────────────────────────────────────────────┐
│                      Detection Service                      │
└─────────────────────────────────────────────────────────────┘
     │               │                │               │
     ▼               ▼                ▼               ▼
┌─────────┐  ┌────────────┐  ┌──────────────┐  ┌───────────┐
│ Feature │  │  Security  │  │  Web Scraper │  │  Typosqt  │
│ Extract │  │  Validator │  │              │  │  Detector │
└────┬────┘  └────────────┘  └──────────────┘  └─────┬─────┘
      │                                               │
      │                                               │
      ▼                                               ▼
┌─────────────────────────────────────────────────────────────┐
│                         ML Model                            │
│              (Random Forest / Gradient Boosting)            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         MLLM (Optional)                     │
│                    (Qwen2.5-VL-7B-Instruct)                 │
└─────────────────────────────────────────────────────────────┘
```

## 🌊 Data Flow

### URL Analysis Data Flow

```
Input URL
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ 1. INPUT VALIDATION                                          │
│    ├── Check URL format (RFC 3986)                           │
│    ├── Validate scheme (http/https only)                     │
│    ├── Check for SSRF (private IPs blocked)                  │
│    └── IDN normalization                                     │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. PREPROCESSING                                             │
│    ├── URL parsing (urlparse)                                │
│    ├── Domain extraction (tldextract)                        │
│    ├── Query parameter parsing                               │
│    └── Path analysis                                         │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. FEATURE EXTRACTION (93 features)                          │
│    ├── Length features (url, domain, path lengths)           │
│    ├── Character features (dots, hyphens, digits)            │
│    ├── Domain features (subdomains, entropy)                 │
│    ├── Security features (HTTPS, TLS, port)                  │
│    ├── Suspicious patterns (words, typosquatting)            │
│    └── Web scraping (title, forms, external links)           │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. ML CLASSIFICATION                                         │
│    ├── Feature scaling (StandardScaler)                      │
│    ├── Random Forest prediction                              │
│    ├── Probability calculation                               │
│    └── Feature importance logging                            │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ 5. MLLM ANALYSIS (Optional, if enabled)                      │
│    ├── Web scraping with Playwright                          │
│    ├── Screenshot capture                                    │
│    ├── Content extraction                                    │
│    ├── AI analysis (Qwen)                                    │
│    └── Confidence adjustment                                 │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ 6. POST-PROCESSING                                           │
│    ├── Risk score calculation (0-100)                        │
│    ├── Severity assignment (safe/critical)                   │
│    ├── Action recommendation (allow/block)                   │
│    ├── Explanation generation                                │
│    └── Toolkit/AI-generated detection                        │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ 7. RESPONSE GENERATION                                       │
│    ├── Format JSON response                                  │
│    ├── Add metadata (analysis mode, timestamps)              │
│    ├── Cache result (Redis)                                  │
│    └── Log to MLflow (if training mode)                      │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
JSON Response
```

### Feature Extraction Pipeline

```
Raw URL: "https://sub.domain.com/path?param=value"
    │
    ├─────────────────────────────────────────────────────────┐
    │                                                         │
    ▼                                                         ▼
┌──────────────────────┐                           ┌──────────────────────┐
│  URL-Level Features  │                           │ Domain-Level Features│
├──────────────────────┤                           ├──────────────────────┤
│ • url_length: 45     │                           │ • domain_length: 12  │
│ • path_length: 5     │                           │ • subdomain_count: 1 │
│ • num_dots: 3        │                           │ • is_https: 1        │
│ • num_slashes: 3     │                           │ • domain_entropy: 3.2│
│ • num_params: 1      │                           │ • tld: "com"         │
└──────────────────────┘                           └──────────────────────┘
    │                                                         │
    └─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│              Feature Vector (93 dimensions)                  │
│  [url_len, dom_len, path_len, dots, ..., entropy, https]    │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                  StandardScaler Transform                    │
│              (Normalization & Standardization)               │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    ML Model Prediction                       │
└──────────────────────────────────────────────────────────────┘
```

## 🤖 ML Pipeline

### Model Training Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. DATA INGESTION                                               │
│    ├── Load phishing URLs (01_data/phishing_urls.csv)           │
│    ├── Load legitimate URLs (01_data/legitimate_urls.csv)       │
│    └── Data validation & cleaning                               │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. FEATURE ENGINEERING                                          │
│    ├── Extract 93 features per URL                              │
│    ├── Handle missing values                                    │
│    ├── Feature scaling (StandardScaler)                         │
│    └── Feature selection (optional)                             │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. MODEL TRAINING                                               │
│    ├── Train/test split (80/20)                                 │
│    ├── Cross-validation (5-fold)                                │
│    ├── Train Random Forest                                      │
│    │   ├── n_estimators: 200                                    │
│    │   ├── max_depth: 20                                        │
│    │   ├── min_samples_split: 5                                 │
│    │   └── class_weight: 'balanced'                             │
│    ├── Train Gradient Boosting (comparison)                     │
│    └── Hyperparameter tuning (GridSearchCV)                     │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. MODEL EVALUATION                                             │
│    ├── Calculate metrics:                                       │
│    │   ├── Accuracy                                             │
│    │   ├── Precision                                            │
│    │   ├── Recall                                               │
│    │   ├── F1 Score (primary)                                   │
│    │   └── AUC-ROC                                              │
│    ├── Confusion matrix                                         │
│    ├── Feature importance analysis                              │
│    └── Error analysis                                           │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. MODEL REGISTRATION (MLflow)                                  │
│    ├── Log model with signature                                 │
│    ├── Log parameters & metrics                                 │
│    ├── Log artifacts (scaler, feature columns)                  │
│    ├── Register model version                                   │
│    └── Auto-promote to Production (if F1 >= 0.90)              │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. MODEL DEPLOYMENT                                             │
│    ├── Save model (02_models/phishing_classifier.joblib)        │
│    ├── Save scaler (02_models/scaler.joblib)                    │
│    ├── Save feature columns                                     │
│    └── Update API with new model                                │
└─────────────────────────────────────────────────────────────────┘
```

### Model Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    RANDOM FOREST CLASSIFIER                     │
│                    (n_estimators=200)                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Input: Feature Vector (93 dimensions)                         │
│       │                                                         │
│       ▼                                                         │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              200 Decision Trees                         │   │
│   │                                                         │   │
│   │  Tree 1    Tree 2    Tree 3    ...    Tree 200         │   │
│   │    │         │         │              │                │   │
│   │    ▼         ▼         ▼              ▼                │   │
│   │  [Vote]   [Vote]   [Vote]          [Vote]              │   │
│   │    │         │         │              │                │   │
│   │    └─────────┴─────────┴──────┬───────┘                │   │
│   │                               ▼                        │   │
│   │                        Majority Voting                 │   │
│   └─────────────────────────────────────────────────────────┘   │
│       │                                                         │
│       ▼                                                         │
│   Output: Class Probability [Phishing, Legitimate]             │
│                                                                 │
│   Classification Categories:                                    │
│   • LEGITIMATE (0)                                              │
│   • PHISHING (1)                                                │
│   • AI_GENERATED_PHISHING (2)                                   │
│   • PHISHING_KIT (3)                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### MLflow Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                      MLflow Tracking                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Experiment: "phishing_detection"                              │
│   │                                                             │
│   ├── Run 1: Random Forest v1                                   │
│   │   ├── Parameters:                                           │
│   │   │   ├── n_estimators: 100                                 │
│   │   │   ├── max_depth: 10                                     │
│   │   │   └── ...                                               │
│   │   ├── Metrics:                                              │
│   │   │   ├── f1_score: 0.95                                    │
│   │   │   ├── accuracy: 0.96                                    │
│   │   │   └── ...                                               │
│   │   └── Artifacts:                                            │
│   │       ├── model/                                            │
│   │       ├── scaler.joblib                                     │
│   │       └── feature_columns.json                              │
│   │                                                             │
│   ├── Run 2: Random Forest v2 (optimized)                       │
│   │   └── f1_score: 0.98                                        │
│   │                                                             │
│   └── Run 3: Gradient Boosting                                  │
│       └── f1_score: 0.97                                        │
│                                                                 │
│   Model Registry:                                               │
│   ├── phishing_classifier                                       │
│   │   ├── Version 1: Staging                                    │
│   │   └── Version 2: Production (F1: 0.98)                     │
│   │                                                             │
└─────────────────────────────────────────────────────────────────┘
```

## 🔒 Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: PERIMETER SECURITY                                     │
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │    WAF      │  │    DDoS     │  │   CDN       │            │
│   │   (Rules)   │  │  Protection │  │  (Caching)  │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: NETWORK SECURITY                                       │
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │   HTTPS/    │  │    VPN      │  │   Private   │            │
│   │   TLS 1.3   │  │   Access    │  │   Subnets   │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: APPLICATION SECURITY                                   │
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │     JWT     │  │    Rate     │  │   Input     │            │
│   │     Auth    │  │   Limiting  │  │  Validation │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: DATA SECURITY                                          │
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │  Encrypted  │  │   Secure    │  │   Access    │            │
│   │  Storage    │  │   Secrets   │  │   Controls  │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Architecture                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Users/API Clients                                             │
│       │                                                         │
│       ├───(JWT Token)──────────────────────┐                   │
│       │                                    │                   │
│       └───(API Key)─────────────────────┐  │                   │
│                                         │  │                   │
│       ┌─────────────────────────────────┼──┼───────────┐       │
│       │         Auth Manager            │  │           │       │
│       │                                 │  │           │       │
│       │  ┌──────────────┐  ┌──────────┐ │  │           │       │
│       │  │ JWT Handler  │  │ API Key  │◄─┘  │           │       │
│       │  │              │  │ Handler  │◄────┘           │       │
│       │  └──────┬───────┘  └────┬─────┘                │       │
│       │         │               │                      │       │
│       │         └───────┬───────┘                      │       │
│       │                 │                              │       │
│       │         ┌───────▼───────┐                      │       │
│       │         │   Identity    │                      │       │
│       │         │   Provider    │                      │       │
│       │         │   (Verify)    │                      │       │
│       │         └───────┬───────┘                      │       │
│       │                 │                              │       │
│       └─────────────────┼──────────────────────────────┘       │
│                         │                                      │
│       ┌─────────────────▼──────────────────┐                  │
│       │      Protected Resources           │                  │
│       │  • /api/v1/analyze                 │                  │
│       │  • /api/v1/batch-analyze           │                  │
│       │  • /api/v1/features/{url}          │                  │
│       └────────────────────────────────────┘                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### SSRF Protection

```
┌─────────────────────────────────────────────────────────────────┐
│              SSRF Protection Mechanisms                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input URL                                                      │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  1. URL Parsing & Validation                            │   │
│  │     ├── Parse with urlparse                             │   │
│  │     ├── Extract scheme, host, port                      │   │
│  │     └── Validate against RFC 3986                       │   │
│  └─────────────────────────────────────────────────────────┘   │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  2. Scheme Validation                                   │   │
│  │     ├── Allow: http, https                              │   │
│  │     └── Block: file, ftp, javascript, data, blob...     │   │
│  └─────────────────────────────────────────────────────────┘   │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  3. IP Address Resolution                               │   │
│  │     ├── DNS resolution of hostname                      │   │
│  │     └── Check resolved IP against blocklists            │   │
│  └─────────────────────────────────────────────────────────┘   │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  4. IP Blocklist Check                                  │   │
│  │     ├── Private: 10.0.0.0/8, 172.16.0.0/12, etc.       │   │
│  │     ├── Loopback: 127.0.0.0/8, ::1/128                  │   │
│  │     └── Link-local: 169.254.0.0/16, fe80::/10          │   │
│  └─────────────────────────────────────────────────────────┘   │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  5. Port Restriction                                    │   │
│  │     ├── Allow: 80, 443, 8080, 8443 (common web)        │   │
│  │     └── Block: 22, 25, 3306, 6379, etc. (services)     │   │
│  └─────────────────────────────────────────────────────────┘   │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  6. Pattern Detection                                   │   │
│  │     ├── Path traversal (../, ..%2f)                     │   │
│  │     ├── Null bytes (%00)                                │   │
│  │     └── Userinfo with IP (user@1.2.3.4)                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│     │                                                           │
│     ▼                                                           │
│  Allowed ────────────────────────────────► Web Scraping         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

**Architecture Version:** 2.0.0  
**Last Updated:** 2024-01-01  
**Author:** Akarsh Bandi
