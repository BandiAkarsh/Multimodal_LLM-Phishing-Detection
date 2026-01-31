# PHISHING GUARD - COMPREHENSIVE REFERENCE DOCUMENT
# Project Refactor, Critical Upgrades & Security Hardening
# Created: January 30, 2026
# For: Final Year IEEE Project - Production Hardening

## EXECUTIVE SUMMARY

**Current State:** IEEE-level college project (functional prototype)
**Target:** Production-ready system meeting 2026 security standards
**Timeline:** 8 weeks (bandwidth-optimized for 1.5GB/day limit)
**Student Setup:** Dell G15 5520, LMDE 7, 16GB RAM, QEMU, Docker installed

## PROJECT ARCHITECTURE

**Phishing Guard** is a multimodal AI-based phishing detection system:

### Detection Pipeline (4 Tiers)
1. **Tier 1:** Typosquatting detection (brand impersonation)
2. **Tier 2:** ML Classifier (Random Forest, 99.8% F1 score)
3. **Tier 3:** MLLM (Qwen2.5-3B for advanced analysis)
4. **Tier 4:** Web scraping (Playwright) with toolkit fingerprinting

### Current Components
- FastAPI REST service (`04_inference/api.py`)
- CustomTkinter GUI (`gui.py`)
- CLI tool (`detect.py`)
- Email IMAP monitor (`email_scanner.py`)
- Docker deployment (`Dockerfile`)
- Desktop notifications

## UPGRADE CATEGORIES (70+ Items)

### 🔴 TIER 1: SECURITY & COMPLIANCE (18 upgrades)
**Goal:** Prevent exploitation, ensure legal compliance
**Aspects:** Email scanner, API layer, Web scraper, Configuration

| # | Upgrade | File(s) | Current Issue | 2026 Standard |
|---|---------|---------|---------------|---------------|
| 1 | **Encrypt email_config.json** | `setup_wizard.py`, `email_scanner.py`, `05_utils/secure_config.py` | Plaintext passwords stored in JSON | Fernet encryption with keyring fallback |
| 2 | **JWT/API Key authentication** | `04_inference/api.py`, `04_inference/auth.py` | No auth - open API endpoints | JWT tokens + API keys |
| 3 | **Rate limiting** | `04_inference/api.py` | No request throttling | 100 req/min per IP (in-memory) |
| 4 | **CORS restrictions** | `04_inference/api.py` | `allow_origins=["*"]` - any website can call API | Specific origin whitelist |
| 5 | **URL input validation** | `04_inference/schemas.py`, `05_utils/security_validator.py` | Minimal validation, accepts malicious URLs | Strict RFC 3986 validation |
| 6 | **Security headers** | `04_inference/api.py` | No security headers | HSTS, CSP, X-Frame-Options, X-XSS-Protection |
| 7 | **Request size limits** | `05_utils/web_scraper.py` | No limits - can crash on large responses | 10MB max response size |
| 8 | **Private IP blocking** | `05_utils/security_validator.py` | SSRF vulnerability - can access localhost/internal IPs | Block 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1 |
| 9 | **Data anonymization** | `05_utils/privacy_manager.py` | URLs stored with full query strings (may contain PII) | Hash query params, keep only domain |
| 10 | **Data retention policies** | `05_utils/privacy_manager.py` | Data stored indefinitely | Auto-delete after 30 days |
| 11 | **Audit logging** | `04_inference/service.py` | No tracking of who scanned what | Log all requests with timestamps |
| 12 | **HTTPS enforcement** | `05_utils/feature_extraction.py` | No penalty for HTTP sites | Risk score boost for HTTP |
| 13 | **Certificate validation** | `05_utils/tls_analyzer.py` | No TLS checks | Full certificate analysis |
| 14 | **TLS version checking** | `05_utils/tls_analyzer.py` | Accepts any TLS version | Reject TLS 1.0/1.1, require TLS 1.2+ |
| 15 | **Threat intelligence correlation** | `05_utils/threat_intel.py` | No real-time threat data | PhishTank, GSB, VirusTotal integration |
| 16 | **Secure session management** | `04_inference/auth.py` | No session tracking | Secure JWT with expiration |
| 17 | **User consent management** | `05_utils/privacy_manager.py` | No GDPR consent flow | Explicit user consent for data processing |
| 18 | **Automated data purging** | `05_utils/privacy_manager.py` | Manual cleanup only | Scheduled auto-delete of old data |

**Deliverables Phase 1:**
- ✅ No plaintext passwords
- ✅ API requires authentication
- ✅ SSRF attacks blocked
- ✅ Rate limiting active
- ✅ Security headers present
- ✅ GDPR compliance features

---

### 🟡 TIER 2: CORE DETECTION ENGINE (24 upgrades)
**Goal:** Improve accuracy, detect modern threats
**Aspects:** Feature extraction, Typosquatting, ML Classifier, MLLM, Web scraping

| # | Upgrade | File(s) | Current Issue | 2026 Standard |
|---|---------|---------|---------------|---------------|
| 19 | **IDN/Homograph detection** | `05_utils/feature_extraction.py`, `05_utils/typosquatting_detector.py` | No punycode detection | Full IDNA2008 support |
| 20 | **Full Unicode confusable mapping** | `05_utils/typosquatting_detector.py` | Only 39 homoglyphs | UTS 39 compliance - 500+ confusable characters |
| 21 | **Phonetic similarity detection** | `05_utils/typosquatting_detector.py` | No sound-alike detection | Soundex, Metaphone, NYSIIS algorithms |
| 22 | **Combo-squatting detection** | `05_utils/typosquatting_detector.py` | No brand+keyword detection | Detect paypal-login, secure-bankofamerica, etc. |
| 23 | **100+ ML features** | `05_utils/feature_extraction.py` | Only 20 basic features | 100+ features including temporal, reputation, structural |
| 24 | **Temporal features** | `05_utils/feature_extraction.py` | No time-based features | Domain age, cert age, registration date |
| 25 | **Reputation features** | `05_utils/feature_extraction.py` | No external reputation | Alexa rank, VirusTotal, PhishTank scores |
| 26 | **TLS security analysis** | `05_utils/tls_analyzer.py` | No TLS inspection | Cipher suite analysis, HSTS, HPKP |
| 27 | **Certificate transparency** | `05_utils/tls_analyzer.py` | No CT log checking | Query crt.sh for cert history |
| 28 | **DNSSEC validation** | `05_utils/feature_extraction.py` | No DNS security check | Validate DNSSEC signatures |
| 29 | **HTTP/2 & HTTP/3 detection** | `05_utils/feature_extraction.py` | Only HTTP/1.1 | Detect modern protocols |
| 30 | **QUIC protocol support** | `05_utils/feature_extraction.py` | No QUIC detection | Google/Cloudflare use QUIC |
| 31 | **ESNI/ECH detection** | `05_utils/feature_extraction.py` | No encrypted SNI detection | Privacy feature validation |
| 32 | **Certificate pinning detection** | `05_utils/tls_analyzer.py` | No pinning check | Mobile app security validation |
| 33 | **OCSP stapling verification** | `05_utils/tls_analyzer.py` | No revocation check | Real-time cert status |
| 34 | **Host-based features** | `05_utils/feature_extraction.py` | Limited host analysis | Ports, subdomains, SLD analysis |
| 35 | **Content-based features** | `05_utils/feature_extraction.py` | No NLP on content | Text analysis, readability, sentiment |
| 36 | **Interaction features** | `05_utils/feature_extraction.py` | No feature combinations | HTTPS × entropy, brand × login, etc. |
| 37 | **WebSocket security analysis** | `05_utils/web_scraper.py` | No WebSocket detection | Modern web app support |
| 38 | **Response size limits** | `05_utils/web_scraper.py` | Can download huge files | 10MB limit with streaming |
| 39 | **Content-type validation** | `05_utils/web_scraper.py` | Accepts any content type | Whitelist: text/html, application/xhtml+xml |
| 40 | **Malicious content detection** | `05_utils/web_scraper.py` | No exploit detection | Detect eval(), document.write(), etc. |
| 41 | **Redirect validation** | `05_utils/web_scraper.py` | Follows all redirects | Limit redirects, validate chains |
| 42 | **Sandbox isolation** | `05_utils/web_scraper.py` | No isolation | Sandboxed scraping environment |

**Decision (Bandwidth-Saver Mode):**
- Using Option B: Keep current ML model (saves 800MB)
- Add all new features to extractor
- Retrain model AFTER project submission (when bandwidth unlimited)

**Deliverables Phase 2:**
- ✅ IDN/homograph attacks detected
- ✅ 50+ total features (vs current 20)
- ✅ TLS security scoring
- ✅ Real-time threat checking
- ✅ Modern protocol detection

---

### 🟢 TIER 3: GUI & UX MODERNIZATION (16 upgrades)
**Goal:** Professional, modern interface
**Aspects:** Desktop GUI, Browser extension, CLI, Mobile

| # | Upgrade | File(s) | Current Issue | 2026 Standard |
|---|---------|---------|---------------|---------------|
| 43 | **Redis caching layer** | `05_utils/cache_manager.py` | No caching - re-analyzes same URLs | In-memory cache (skip Redis for laptop) |
| 44 | **Celery/RQ async queue** | `04_inference/celery_worker.py` | Synchronous only | Python asyncio (built-in, no extra deps) |
| 45 | **Prometheus metrics** | `04_inference/metrics.py` | No observability | Basic metrics collection |
| 46 | **Grafana dashboards** | `docker-compose.yml` | No visualization | Skip for laptop (use logs instead) |
| 47 | **OpenTelemetry tracing** | `04_inference/tracing.py` | No distributed tracing | Basic request tracking |
| 48 | **Kubernetes deployment** | `k8s/` | Not applicable | Skip (single laptop) |
| 49 | **Terraform cloud infra** | `terraform/` | Not applicable | Skip (use Docker only) |
| 50 | **Auto-scaling policies** | N/A | Not applicable | Skip |
| 51 | **Health check endpoints** | `04_inference/api.py` | No health checks | `/health` endpoint |
| 52 | **Circuit breaker patterns** | `04_inference/service.py` | No failure handling | Graceful degradation |
| 53 | **Tauri GUI framework** | `gui-tauri/` | CustomTkinter (dated) | Tauri (Rust + React) - modern native app |
| 54 | **Browser extension** | `browser-extension/` | No browser protection | Chrome/Firefox/Brave extension |
| 55 | **Mobile app** | `mobile/` | No mobile support | Skip (optional for project) |
| 56 | **Web dashboard** | `dashboard/` | No web interface | Optional - Tauri covers this |
| 57 | **MLflow model versioning** | `03_training/train_ml.py` | Static joblib files | MLflow registry (after submission) |
| 58 | **BentoML model serving** | `04_inference/service.py` | Direct model loading | BentoML optimization (future) |

**Decision (Laptop-Optimized):**
- Using Tauri for GUI (modern, justifies Rust learning)
- Skip Redis/Celery (use in-memory/asyncio)
- Skip Kubernetes (not applicable)
- Focus on: Tauri GUI + Browser extension + Docker

**Deliverables Phase 3:**
- ✅ Modern Tauri desktop application
- ✅ Brave/Chrome browser extension
- ✅ Professional CLI with colors
- ✅ Health check endpoint
- ✅ Docker deployment

---

### 🔵 TIER 4: THREAT INTELLIGENCE & ML MODERNIZATION (12 upgrades)
**Goal:** Real-time threat detection, model management
**Aspects:** Threat feeds, Model registry, Training pipeline

| # | Upgrade | File(s) | Current Issue | 2026 Standard |
|---|---------|---------|---------------|---------------|
| 59 | **PhishTank API integration** | `05_utils/threat_intel.py` | CSV download only | Real-time API with caching |
| 60 | **Google Safe Browsing API** | `05_utils/threat_intel.py` | No GSB integration | Industry standard threat intel |
| 61 | **VirusTotal reputation checks** | `05_utils/threat_intel.py` | No multi-engine scan | 70+ antivirus engines |
| 62 | **URLhaus integration** | `05_utils/threat_intel.py` | No malware site data | Abuse.ch feed |
| 63 | **DNSBL/RBL checking** | `05_utils/threat_intel.py` | No email reputation | Spamhaus, Barracuda checks |
| 64 | **Real-time feed aggregation** | `05_utils/threat_intel.py` | Single source | Unified threat intelligence API |
| 65 | **MLflow model registry** | `03_training/train_ml.py` | No versioning | Model versioning (after submission) |
| 66 | **DVC data versioning** | `dvc.yaml` | No dataset versioning | Data version control (after submission) |
| 67 | **A/B testing framework** | `04_inference/ab_testing.py` | No model comparison | Shadow mode deployment (future) |
| 68 | **Shadow mode deployment** | `04_inference/service.py` | No safe rollout | Test new models safely (future) |
| 69 | **Automated model retraining** | `retrain_pipeline.py` | Manual training only | Scheduled retraining (future) |
| 70 | **Federated learning support** | `05_utils/federated_client.py` | Centralized only | Privacy-preserving training (future) |

**Decision (Post-Submission):**
- Phase 1-3: Basic threat intel integration (PhishTank, GSB)
- Phase 4 (optional): MLflow, DVC, automated retraining (bandwidth permitting)

**Deliverables Phase 4:**
- ✅ Basic threat intelligence integration
- ✅ Cached threat feeds (offline capable)
- ✅ Model versioning setup (if time permits)

---

## CRITICAL SECURITY VULNERABILITIES (Current System)

### 🔴 CRITICAL (Exploitable Now - Must Fix in Phase 1)

1. **Plaintext Passwords in email_config.json**
   - File: `setup_wizard.py:63-70`
   - Risk: GDPR violation, credential theft
   - Fix: Fernet encryption + keyring

2. **No API Authentication**
   - File: `04_inference/api.py:103-110`
   - Risk: Anyone can access API, abuse detection service
   - Fix: JWT tokens + API keys

3. **Wildcard CORS Policy**
   - File: `04_inference/api.py:104-110`
   - Risk: Any malicious website can call your API
   - Fix: Origin whitelist

4. **No Rate Limiting**
   - File: `04_inference/api.py` (entire file)
   - Risk: DoS attacks, resource exhaustion
   - Fix: Request throttling

5. **SSRF Vulnerabilities in Web Scraper**
   - File: `05_utils/web_scraper.py:582-651`
   - Risk: Access internal services, cloud metadata
   - Fix: URL validation, IP blocking

6. **No Input Validation**
   - File: `04_inference/schemas.py:44-48`
   - Risk: Malicious URLs accepted, injection attacks
   - Fix: Strict URL validation

7. **No Request Size Limits**
   - File: `05_utils/web_scraper.py`
   - Risk: Memory exhaustion, DoS
   - Fix: 10MB response limit

8. **Missing TLS Checks**
   - File: `05_utils/feature_extraction.py`
   - Risk: Can't detect SSL stripping, weak ciphers
   - Fix: TLS analyzer module

### 🟡 HIGH (Detection Bypass - Fix in Phase 2)

9. **No IDN/Homograph Detection**
   - File: `05_utils/typosquatting_detector.py`
   - Risk: Cyrillic spoofing attacks (paypаl.com)
   - Fix: Punycode detection

10. **39 Unicode Confusables Only**
    - File: `05_utils/typosquatting_detector.py:123-139`
    - Risk: Missing 460+ attack vectors
    - Fix: Full UTS 39 mapping

11. **No Phonetic Detection**
    - File: `05_utils/typosquatting_detector.py`
    - Risk: Sound-alike domains bypass (pay-pal.com)
    - Fix: Soundex/Metaphone algorithms

12. **No Combo-Squatting Detection**
    - File: `05_utils/typosquatting_detector.py`
    - Risk: Brand+keyword attacks (paypallogin.com)
    - Fix: Combo pattern detection

13. **Only 20 ML Features**
    - File: `05_utils/feature_extraction.py`
    - Risk: Modern attackers easily bypass
    - Fix: 100+ comprehensive features

14. **No Temporal Features**
    - File: `05_utils/feature_extraction.py`
    - Risk: Can't detect newly registered domains
    - Fix: Domain age, cert age features

15. **Static Model (No Updates)**
    - File: `02_models/phishing_classifier.joblib`
    - Risk: Model becomes stale
    - Fix: Threat intel integration, retraining pipeline

---

## 2026 STANDARDS COMPLIANCE GAPS

| Standard/Protocol | Current | Required | Impact | Priority |
|-------------------|---------|----------|--------|----------|
| **GDPR** | ❌ Plaintext PII | ✅ Encrypt, anonymize, retention | Legal liability | 🔴 Critical |
| **CCPA** | ❌ No retention policy | ✅ 30-day auto-delete | Legal liability | 🔴 Critical |
| **TLS 1.3** | ❌ Not checking | ✅ Enforce TLS 1.2+ | Downgrade attacks | 🔴 Critical |
| **Certificate Transparency** | ❌ No CT logs | ✅ crt.sh verification | Fraudulent certs | 🔴 Critical |
| **IDN 2008** | ❌ Partial support | ✅ Full UTS 39 | Visual spoofing | 🔴 Critical |
| **SSRF Protection** | ❌ None | ✅ URL validation, IP whitelist | Server compromise | 🔴 Critical |
| **Rate Limiting** | ❌ None | ✅ 100 req/min/IP | DoS protection | 🔴 Critical |
| **Input Sanitization** | ❌ Minimal | ✅ Strict RFC 3986 | Injection attacks | 🔴 Critical |
| **HSTS** | ❌ No checking | ✅ Verify HSTS header | SSL stripping | 🟡 High |
| **DNSSEC** | ❌ No validation | ✅ DNSSEC verification | DNS poisoning | 🟡 High |
| **HTTP/2** | ❌ Not detected | ✅ Protocol detection | Modern web | 🟢 Medium |
| **QUIC** | ❌ Not detected | ✅ QUIC detection | Google/CF traffic | 🟢 Medium |
| **ESNI/ECH** | ❌ Not detected | ✅ ECH support | Privacy features | 🟢 Medium |
| **AI Phishing Detection** | ✅ Partial | ✅ Enhanced patterns | AI-generated attacks | 🟡 High |
| **Phishing Kit Detection** | ✅ Implemented | ✅ Maintain | Toolkit fingerprinting | 🟡 High |

---

## IMPLEMENTATION PLAN (Bandwidth-Optimized)

### Phase 1: Security Critical (Weeks 1-2)
**Bandwidth:** ~200MB total
**Goal:** Production security hardening

#### Week 1: Credential & API Security
- **Day 1-2:** Credential encryption (`setup_wizard.py`, `email_scanner.py`)
  - Create `05_utils/secure_config.py`
  - Implement Fernet encryption
  - Add keyring integration
  - Test migration from plaintext

- **Day 3-4:** API authentication (`04_inference/api.py`, `auth.py`)
  - Create `04_inference/auth.py`
  - Implement JWT token generation
  - Add login/register endpoints
  - Protect all analysis endpoints

- **Day 5-7:** Input validation & CORS
  - Create `05_utils/security_validator.py`
  - Strict URL validation (RFC 3986)
  - Private IP blocking (SSRF protection)
  - CORS origin whitelist

#### Week 2: Rate Limiting & Data Protection
- **Day 8-10:** Rate limiting & headers
  - In-memory rate limiting (no Redis)
  - Security headers middleware
  - Request size limits

- **Day 11-14:** Privacy & audit
  - Create `05_utils/privacy_manager.py`
  - Data anonymization
  - Audit logging
  - Retention policy setup

**Deliverables:**
- ✅ Encrypted credentials
- ✅ Authenticated API
- ✅ SSRF protection
- ✅ Rate limiting
- ✅ Security headers

---

### Phase 2: Core Detection Engine (Weeks 3-4)
**Bandwidth:** ~200MB (skip model retraining - Option B)
**Goal:** Improve detection accuracy

#### Week 3: Advanced URL Analysis
- **Day 15-17:** IDN & homograph detection
  - Modify `typosquatting_detector.py`
  - Add Punycode decoding
  - Unicode confusable mapping (extended)
  - Mixed-script detection

- **Day 18-21:** Enhanced feature extraction
  - 30+ new features
  - Temporal features
  - Host-based features
  - Reputation features

#### Week 4: TLS & Threat Intel
- **Day 22-24:** TLS security analyzer
  - Create `05_utils/tls_analyzer.py`
  - Version detection (TLS 1.0/1.1/1.2/1.3)
  - Cipher suite analysis
  - Certificate transparency

- **Day 25-28:** Threat intelligence
  - Create `05_utils/threat_intel.py`
  - Google Safe Browsing API
  - PhishTank API
  - Local caching for offline use

**Deliverables:**
- ✅ IDN attack detection
- ✅ 50+ total features
- ✅ TLS security scoring
- ✅ Threat intelligence

---

### Phase 3: GUI & UX Modernization (Weeks 5-6)
**Bandwidth:** ~600MB (Tauri setup - one heavy day)
**Goal:** Modern, professional interface

#### Week 5: Tauri Desktop App
- **Day 29:** **TAURI SETUP DAY** (use 1.5GB wisely)
  - Install Rust toolchain
  - Install Node.js dependencies
  - Initialize Tauri project

- **Day 30-32:** Tauri development
  - Build React frontend
  - Integrate with Python API
  - URL scanner interface
  - Results dashboard

#### Week 6: Browser Extension & CLI
- **Day 33-35:** Browser extension
  - Create `browser-extension/` directory
  - Manifest v3 setup
  - Content script for link highlighting
  - Popup UI
  - Test with Brave

- **Day 36-38:** Enhanced CLI
  - Improve `detect.py`
  - Add progress bars (tqdm)
  - Colored output (colorama)
  - JSON export

**Deliverables:**
- ✅ Tauri GUI application
- ✅ Browser extension
- ✅ Professional CLI

---

### Phase 4: Deployment & Polish (Weeks 7-8)
**Bandwidth:** ~300MB (Docker optimization)
**Goal:** Production deployment ready

#### Week 7: Docker & Monitoring
- **Day 39-41:** Docker optimization
  - Multi-stage Dockerfile (slim base)
  - docker-compose.yml
  - Health checks
  - Environment configuration

- **Day 42-44:** Basic monitoring
  - Metrics collection
  - Request logging
  - Simple status dashboard

#### Week 8: Documentation & Testing
- **Day 45-47:** Documentation
  - API documentation (OpenAPI/Swagger)
  - README updates
  - Setup instructions
  - Security hardening guide

- **Day 48-50:** Testing & demo prep
  - Unit tests for security features
  - Integration tests
  - QEMU VM demo setup
  - Presentation preparation

**Deliverables:**
- ✅ Optimized Docker deployment
- ✅ API documentation
- ✅ Test coverage
- ✅ Demo ready

---

## BANDWIDTH MANAGEMENT STRATEGY

### Heavy Download Days (Plan Ahead)

**Day 7 (~800MB):** Model/Training Data
- Download PhishTank dataset
- Download legitimate URL dataset
- (Skip if using Option B)

**Day 9 (~600MB):** Tauri/Rust Setup
- Rust toolchain (rustup)
- Cargo dependencies
- Node.js packages
- Tauri CLI

**Day 15 (~400MB):** Docker Images
- python:3.11-slim
- Playwright browsers
- System dependencies

### Low/No Bandwidth Days (Code Work)

**Days 1-6, 8, 10-14, 16-28, 30-38, 39-50:**
- Feature implementation
- Bug fixes
- Testing
- Documentation
- Refactoring

### Total Bandwidth Budget

| Phase | Bandwidth | Cumulative |
|-------|-----------|------------|
| Phase 1 | 200MB | 200MB |
| Phase 2 | 200MB | 400MB |
| Phase 3 | 600MB | 1.0GB |
| Phase 4 | 300MB | 1.3GB |
| **Total** | **1.3GB** | **Well under 1.5GB/day limit** |

---

## TECHNOLOGY STACK DECISIONS

### ✅ SELECTED (Laptop-Optimized)

| Component | Selected | Alternative | Reason |
|-----------|----------|-------------|--------|
| **GUI Framework** | Tauri | CustomTkinter | Modern, native, fast, justifies Rust learning |
| **Authentication** | JWT + API Keys | OAuth2 | Simpler, no external deps |
| **Caching** | In-memory dict | Redis | Zero installation, sufficient for demo |
| **Async Queue** | Python asyncio | Celery | Built-in, no extra dependencies |
| **ML Model** | Keep current | Retrain | Saves 800MB bandwidth, faster completion |
| **Database** | JSON files | PostgreSQL | No installation, simple |
| **Docker** | Slim + Multi-stage | Standard | Saves 300MB, faster builds |
| **Monitoring** | File logging | Prometheus/Grafana | No infrastructure needed |
| **Threat Intel** | API-based | Local DB | Always current, less storage |

### ❌ SKIPPED (Not Practical for Setup)

| Component | Reason |
|-----------|--------|
| **Kubernetes** | Single laptop, no cluster |
| **Terraform** | No cloud resources |
| **Redis** | In-memory sufficient |
| **Celery** | Asyncio is enough |
| **PostgreSQL** | Overkill for demo |
| **ELK Stack** | Too resource-heavy |
| **Mobile App** | Optional, can skip |
| **MLflow (now)** | Add after submission |

---

## Tauri + Python Integration

### Architecture

```
┌─────────────────────────────────────────────┐
│  Tauri Desktop Application                  │
│  (Rust + React Frontend)                    │
│  ├─ Window management                       │
│  ├─ System tray                             │
│  ├─ Native menus                            │
│  ├─ Secure storage                          │
│  └─ HTTP client calls Python API            │
└──────────────┬──────────────────────────────┘
               │ HTTP requests to localhost:8000
               ▼
┌─────────────────────────────────────────────┐
│  Python FastAPI Backend                     │
│  ├─ Phishing detection logic                │
│  ├─ ML model inference                      │
│  ├─ MLLM processing                         │
│  ├─ Web scraping                            │
│  └─ Authentication & rate limiting          │
└─────────────────────────────────────────────┘
```

### Communication

```javascript
// Tauri frontend calls Python API
const scanUrl = async (url) => {
  const response = await fetch('http://localhost:8000/api/v1/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ url })
  });
  return await response.json();
};
```

### Bundle Distribution

- Tauri creates standalone `.AppImage` (Linux)
- Includes Python backend as sidecar binary
- Single executable for distribution
- Perfect for IEEE project submission

---

## QEMU VM DEMO SETUP

### Recommended VM Configuration

```bash
# Create VM disk
qemu-img create -f qcow2 phishing_demo.img 20G

# Start VM with port forwarding
qemu-system-x86_64 \
  -m 4096 \
  -smp 2 \
  -hda phishing_demo.img \
  -net user,hostfwd=tcp::8080-:80,hostfwd=tcp::8000-:8000 \
  -net nic \
  -display gtk
```

### Port Mapping

| Host Port | Guest Port | Service |
|-----------|------------|---------|
| 8080 | 80 | Web interface (if any) |
| 8000 | 8000 | FastAPI backend |

### Demo Flow (15-minute IEEE presentation)

1. **Security Before/After (2 min)**
   - Show old plaintext config
   - Show new encrypted config
   - Demo SSRF attack blocked

2. **Detection Improvements (4 min)**
   - IDN attack detection (paypаl.com)
   - TLS security analysis
   - Threat intelligence lookup

3. **Modern GUI (3 min)**
   - Tauri application walkthrough
   - Browser extension live demo
   - CLI with colors/progress

4. **Deployment (3 min)**
   - Docker build
   - Container run
   - Health check

5. **Q&A (3 min)**

---

## FILE STRUCTURE (Post-Upgrade)

```
phishing_detection_project/
├── 01_data/
│   ├── external/
│   │   └── tld_list.json
│   ├── processed/
│   └── raw/
├── 02_models/
│   ├── phishing_classifier.joblib
│   ├── feature_scaler.joblib
│   └── feature_columns.joblib
├── 03_training/
│   └── train_ml.py
├── 04_inference/
│   ├── api.py                    [MODIFIED - Add auth, rate limiting]
│   ├── auth.py                   [NEW - JWT authentication]
│   ├── service.py                [MODIFIED - Add caching, audit]
│   ├── schemas.py                [MODIFIED - Enhanced validation]
│   ├── celery_worker.py          [NEW - If needed, optional]
│   └── metrics.py                [NEW - Basic metrics]
├── 05_utils/
│   ├── feature_extraction.py     [MODIFIED - 50+ features]
│   ├── typosquatting_detector.py [MODIFIED - Unicode confusables]
│   ├── web_scraper.py            [MODIFIED - SSRF protection]
│   ├── mllm_transformer.py       [EXISTING]
│   ├── url_extractor.py          [EXISTING]
│   ├── connectivity.py           [EXISTING]
│   ├── text_feature_generator.py [EXISTING]
│   ├── data_preparation.py       [EXISTING]
│   ├── secure_config.py          [NEW - Credential encryption]
│   ├── security_validator.py     [NEW - URL validation]
│   ├── tls_analyzer.py           [NEW - TLS security analysis]
│   ├── threat_intel.py           [NEW - Threat intelligence]
│   ├── privacy_manager.py        [NEW - GDPR compliance]
│   ├── cache_manager.py          [NEW - In-memory caching]
│   └── common_words.py           [EXISTING]
├── 06_tests/
│   ├── test_security.py          [NEW - Security tests]
│   ├── test_api.py               [NEW - API tests]
│   └── test_features.py          [NEW - Feature tests]
├── 07_configs/
│   └── config.yaml
├── browser-extension/            [NEW - Brave/Chrome extension]
│   ├── manifest.json
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   └── styles.css
├── gui-tauri/                    [NEW - Tauri desktop app]
│   ├── src-tauri/
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── App.tsx
│   └── package.json
├── docker/
│   ├── Dockerfile                [MODIFIED - Optimized]
│   └── docker-compose.yml        [NEW - Orchestration]
├── detect.py                     [MODIFIED - Enhanced CLI]
├── email_scanner.py              [MODIFIED - Use secure config]
├── setup_wizard.py               [MODIFIED - Encrypt credentials]
├── gui.py                        [EXISTING - Keep as fallback]
├── requirements.txt              [MODIFIED - Add new deps]
├── README.md                     [MODIFIED - Updated docs]
├── API_DOCUMENTATION.md          [NEW - API docs]
├── SECURITY_HARDENING.md         [NEW - Security guide]
└── REFERENCE_DOCUMENT.md         [THIS FILE]
```

---

## REMAINING QUESTIONS (If Any)

1. **Tauri vs CustomTkinter:** Confirm Tauri (uses ~600MB bandwidth day)
2. **Model retraining:** Confirm Option B (keep current model, add features)
3. **Docker:** Confirm minimal setup (saves 300MB)
4. **Start date:** Confirm today (January 30, 2026)
5. **Heavy download days:** What time does Jio data reset? (Schedule Day 7, 9, 15)

---

## SUCCESS CRITERIA

### Phase 1 Complete When:
- [ ] No plaintext passwords anywhere
- [ ] API requires valid JWT token
- [ ] SSRF attacks blocked (tested)
- [ ] Rate limiting active (100 req/min)
- [ ] Security headers present
- [ ] All security tests pass

### Phase 2 Complete When:
- [ ] IDN detection working (test with Cyrillic)
- [ ] 50+ total features extracted
- [ ] TLS analyzer functional
- [ ] Threat intelligence integrated
- [ ] Feature extraction tests pass

### Phase 3 Complete When:
- [ ] Tauri GUI builds successfully
- [ ] Browser extension installs in Brave
- [ ] CLI has colors and progress bars
- [ ] GUI tests pass

### Phase 4 Complete When:
- [ ] Docker container builds (< 5 min)
- [ ] Health check endpoint works
- [ ] API documentation complete
- [ ] Demo VM runs successfully
- [ ] Project submission ready

---

## STARTING PHASE 1 NOW

**Status:** Ready to begin
**Current Day:** Day 1 of Phase 1
**Branch:** phase1-security-upgrades
**Bandwidth Available:** 1.5GB for today (use ~50MB)

**First Tasks:**
1. Create secure_config.py
2. Modify setup_wizard.py for encryption
3. Modify email_scanner.py to use encryption
4. Test credential encryption/decryption

---

**END OF REFERENCE DOCUMENT**
