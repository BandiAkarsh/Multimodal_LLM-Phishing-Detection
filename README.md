# 🛡️ Phishing Guard v2.0

> **Final Year IEEE Project** | **Production-Grade Security System**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![Security](https://img.shields.io/badge/Security-Hardened-green)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**AI-powered phishing detection with 93 ML features, IDN protection, and enterprise security.**

## 📦 Two Separate Projects

This repository contains the **main IEEE project**. One additional project is available for different use cases:

| Project | Location | Size | Best For |
|---------|----------|------|----------|
| **This Project** | `~/phishing_detection_project/` | Full codebase | IEEE submission, research, reference |
| **Daemon Service** | `~/phishing-guard-daemon/` | 166KB | Family/friends - 24/7 background protection |

**GitHub Repositories:**
- 🏠 **Main Project**: [github.com/BandiAkarsh/phishing_detection_project](https://github.com/BandiAkarsh/phishing_detection_project)
- ⚙️ **Daemon**: [github.com/BandiAkarsh/phishing-guard-daemon](https://github.com/BandiAkarsh/phishing-guard-daemon)

> 💡 **Quick Install**: 
> - For background protection: `sudo dpkg -i ~/phishing-guard_2.0.0-1_all.deb`

## 🎯 What's New in v2.0

- 🔐 **Enterprise Security**: JWT auth, rate limiting, SSRF protection
- 🤖 **93 ML Features**: 365% improvement (was 20)
- 🌐 **IDN Protection**: Unicode homograph attack detection
- 📊 **4-Category Classification**: Legitimate, Phishing, AI-Generated, Phishing Kit
- 🧪 **MLflow Integration**: Model versioning & experiment tracking
- 🌐 **Browser Extension**: Real-time link protection
- 📱 **Multiple Interfaces**: CLI, API, Extension

## 🚀 Quick Start

### Prerequisites
```bash
# Install system dependencies (Linux)
sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev libappindicator3-dev

# Install Python dependencies
pip install -r requirements.txt
```

### 1. Test Everything (Recommended First Step)
```bash
# Run all tests
python test_security.py
python test_comprehensive.py
```

### 2. Interactive Demos (For Viva/Demonstration)
```bash
# Set JWT secret (required for demo)
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Step-by-step proof (recommended for viva)
python proof_of_working.py

# Polished presentation demo
python final_demo.py

# Original interactive demo
python demo_security.py
```

### 3. CLI Mode (Fastest)
```bash
# Single URL
python detect_enhanced.py https://example.com

# Interactive mode
python detect_enhanced.py --interactive

# Batch from file
python detect_enhanced.py --file urls.txt --output results.json
```

### 3. API Server Mode (Development/Testing)

**⚠️ Note: This is the standalone FastAPI backend server. For production use, install the Daemon (see below) which includes a lightweight API.**

Use this when you want to:
- Test the API endpoints directly
- Use the detection service via HTTP requests
- Integrate with other applications
- Access Swagger UI documentation

```bash
# Start the FastAPI server (runs on localhost:8000)
python 04_inference/api.py

# Server provides:
# - http://localhost:8000/health          (Health check)
# - http://localhost:8000/docs            (Swagger UI API docs)
# - http://localhost:8000/api/v1/analyze  (POST endpoint for URL analysis)

# Example API call:
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "use_mllm": true}'
```

**For 24/7 background protection, use the Daemon instead (it has its own lightweight API).**

### 4. Browser Extension (Standalone)

The browser extension works independently without needing the daemon. See [browser-extension/](browser-extension/) folder.

### 5. Background Daemon Service (Recommended for 24/7 Protection)

**For continuous protection without running a server manually, use the standalone Daemon:**

```bash
# Install the lightweight daemon (166KB)
cd ~
sudo dpkg -i phishing-guard_2.0.0-1_all.deb

# Start the service (auto-runs on boot)
sudo systemctl start phishing-guard
sudo systemctl enable phishing-guard  # Enable auto-start

# The daemon provides:
# - API at http://localhost:8000 (lightweight HTTP server)
# - Browser extension integration
# - Optional email monitoring
# - Desktop notifications

# Configure email (opens visual guide):
phishing-guard config

# Check status:
phishing-guard status

# View logs:
sudo journalctl -u phishing-guard -f
```

**⚡ Key Differences:**
| | API Server (This Project) | Daemon Service |
|---|---|---|
| **Purpose** | Development/testing | Production 24/7 protection |
| **Type** | FastAPI (full-featured) | Lightweight HTTP server |
| **Run** | Manual (`python api.py`) | Systemd service (auto-start) |
| **Size** | Part of main project | 166KB standalone |
| **MLLM** | Yes (Qwen support) | No (Random Forest only) |
| **Best For** | IEEE demo, API integration | Family protection, always-on |

### 6. Browser Extension

**🌟 Chrome Web Store Ready!**

The browser extension is now fully packaged and ready for the Chrome Web Store:

#### Option A: Chrome Web Store (One-Click Install)
**[➡️ Click here to install from Chrome Web Store](https://chrome.google.com/webstore/detail/YOUR_EXTENSION_ID)**
*(Replace with your actual extension ID once published)*

#### Option B: Manual Installation (Developer Mode)
```bash
cd browser-extension

# Build the distribution package
npm run build:dist

# Or use bash script
chmod +x scripts/build.sh
./scripts/build.sh --dist

# Then load in Chrome:
# 1. Open chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the dist/ folder
```

#### Browser Extension Features
- ✅ **Standalone Mode** - Works without any backend server
- ✅ **Real-time Protection** - Automatic link scanning and highlighting
- ✅ **100% Privacy** - No data leaves your device
- ✅ **Visual Indicators** - Color-coded links (Green/Yellow/Red)
- ✅ **Quick Scan** - Manual URL checking via popup
- ✅ **Chrome Web Store Ready** - Professional packaging included

#### Extension Structure
```
browser-extension/
├── manifest.json              # Extension config (v3)
├── background.js              # Service worker
├── content.js                 # Page scanner
├── popup.html/js/css          # Extension UI
├── scripts/                   # Build scripts
│   ├── build.js              # Node.js build
│   ├── build.sh              # Bash build
│   ├── version.js            # Version management
│   └── release.js            # GitHub releases
├── store-assets/              # Chrome Web Store assets
│   ├── screenshots/           # Store screenshots
│   └── promotional/           # Promo images
├── PRIVACY_POLICY.md          # Required for Web Store
├── STORE_LISTING.md           # Store description
├── INSTALL.md                 # Installation guide
├── CHANGELOG.md               # Version history
└── package.json               # NPM config
```

#### Build Commands
```bash
cd browser-extension

# Build for distribution
npm run build

# Create ZIP for Chrome Web Store
npm run build:dist

# Run tests
npm test

# Bump version
npm run version -- patch

# Create GitHub release
npm run release
```

#### Publishing to Chrome Web Store
1. Build: `npm run build:dist`
2. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole/)
3. Click "New Item"
4. Upload `dist/phishing-guard-v2.0.0.zip`
5. Fill details using [STORE_LISTING.md](browser-extension/STORE_LISTING.md)
6. Submit for review

See [browser-extension/INSTALL.md](browser-extension/INSTALL.md) for detailed installation instructions.

### 7. MLflow Model Management
```bash
# Train with tracking
python 03_training/train_with_mlflow.py

# View experiments
mlflow ui --backend-store-uri ./mlruns
# Open: http://localhost:5000
```

## 📊 Detection Accuracy

| Metric | Value |
|--------|-------|
| **F1 Score** | 99.82% |
| **Precision** | 99.81% |
| **Recall** | 99.83% |
| **Features** | 93 (was 20) |
| **Classification** | 4 categories |
| **False Positive** | < 0.5% |
| **Latency** | < 2 seconds |

## 🤖 ML/DL Algorithms Used

This project uses a **hybrid ensemble approach** combining traditional ML with optional deep learning:

### Primary Classification (Required)
- **Random Forest Classifier** (200 estimators, max_depth=20)
  - Base ensemble member for stability
  - Handles non-linear relationships well
  - Feature importance extraction
  
- **XGBoost Classifier** (50 estimators, max_depth=6)
  - Gradient boosting for accuracy
  - Complements Random Forest
  - Soft voting ensemble

- **Ensemble Method**: Soft Voting (average probability)

### Optional Deep Learning
- **Qwen2.5-3B-Instruct** (4-bit quantized)
  - For AI-generated phishing detection
  - Detects patterns in LLM-generated content
  - Optional due to size (1.8GB quantized)

### Feature Engineering
- 93 hand-crafted features across 7 categories
- StandardScaler normalization
- SMOTE oversampling for class balance

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                 User Interfaces                      │
│  CLI • API • Desktop App • Browser Extension        │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │   Detection Pipeline    │
┌───────┴───────┐  ┌──────────────┴───────┐  ┌────────┐
│  Tier 1       │  │  Tier 2              │  │ Tier 3 │
│  Typosquatting│  │  ML Classifier       │  │ MLLM   │
│  + IDN        │  │  93 features         │  │ Analysis│
└───────┬───────┘  └──────────┬───────────┘  └───┬────┘
        │                     │                  │
        └─────────────────────┴──────────────────┘
                              │
                    ┌─────────┴──────────┐
                    │  Web Scraping      │
                    │  (When Online)     │
                    └────────────────────┘
```

## 📁 Project Structure

**Note: This is the main IEEE project. Related projects are in separate GitHub repositories:**
- **This Project**: [github.com/BandiAkarsh/phishing_detection_project](https://github.com/BandiAkarsh/phishing_detection_project) ⭐ Main IEEE project
- **Daemon Service**: [github.com/BandiAkarsh/phishing-guard-daemon](https://github.com/BandiAkarsh/phishing-guard-daemon) ⚙️ Lightweight background service

```
phishing_detection_project/
├── 📂 01_data/              # Datasets & TLDs
├── 📂 02_models/            # ML models (joblib)
├── 📂 03_training/          # Training scripts + MLflow
├── 📂 04_inference/         # API + Authentication
├── 📂 05_utils/             # 93 feature extractors
├── 📂 06_notebooks/         # Jupyter notebooks
├── 📂 07_configs/           # Configuration files
├── 📂 08_logs/             # MLflow logs
├── 📂 09_documentation/    # Architecture docs
├── 📂 browser-extension/   # Chrome/Firefox extension
├── 📂 docs/                # Project reports
├── 📂 examples/            # Sample files
├── 📂 scripts/              # Build & utility scripts
├── 📂 tests/                # Test data & scripts
│
├── 🐍 detect_enhanced.py    # Enhanced CLI (colors/progress)
├── 🐍 email_scanner.py      # Email monitoring
├── 🐍 setup_wizard.py       # Setup wizard
├── 🐍 test_security.py      # Security tests
├── 🐍 test_comprehensive.py # Full test suite
├── 🐍 demo_security.py      # Interactive demo
├── 🐍 proof_of_working.py   # Interactive proof for viva/stakeholders
├── 🐍 final_demo.py         # Presentation demo with full explanations
│
├── 🐳 Dockerfile            # Container deployment
├── 📋 docker-compose.yml    # Docker orchestration
├── 📋 requirements.txt      # Python dependencies
└── 📖 README.md             # This file
```

## 🔐 Security Features

- ✅ **Credential Encryption** (Fernet + Keyring)
- ✅ **JWT Authentication** (24hr tokens)
- ✅ **Rate Limiting** (100 req/min)
- ✅ **SSRF Protection** (Private IP blocking, DNS caching)
- ✅ **Input Validation** (RFC 3986 + security)
- ✅ **TLS 1.3 Enforcement** (Certificate validation)
- ✅ **DNS Caching** (DoS prevention)
- ✅ **Model Integrity** (SHA256 verification)

> **Security Hardened** - All critical vulnerabilities fixed. See [SECURITY_HARDENING_REPORT.md](SECURITY_HARDENING_REPORT.md) for details.

## 🤖 MLflow Model Registry

**Automatic Model Management:**

```bash
# Training automatically registers models
python 03_training/train_with_mlflow.py

# Output:
# ✅ Model registered: phishing_classifier v2
# 🚀 Transitioned to Production (F1 >= 0.90)
```

**Features:**
- **Versioning**: Auto-versioned models (v1, v2, v3...)
- **Staging**: Models progress Staging → Production
- **Comparison**: Compare Random Forest vs Gradient Boosting
- **Artifacts**: Scalers, feature columns, metrics all tracked
- **Lineage**: Full experiment tracking with run IDs

**View in MLflow UI:**
```bash
mlflow ui --backend-store-uri ./mlruns
# Navigate to: Models tab → phishing_classifier
```

**Registry Stages:**
- **None**: Initial registration
- **Staging**: Testing/validation phase
- **Production**: Live deployment (auto-promoted if F1 ≥ 0.90)
- **Archived**: Old versions kept for rollback

**Loading from Registry:**
```python
from model_manager import ModelManager
mm = ModelManager()
model = mm.load_model("phishing_classifier")  # Loads latest production version
# Or specific version:
model = mm.load_model("phishing_classifier", version=2)
```
- ✅ **TLS Analysis** (Version 1.3 enforcement)
- ✅ **8 CVE-level vulnerabilities patched**

## 🎓 IEEE Project Highlights

### Unique Innovations:
1. **IDN/Homograph Detection** - First to detect Cyrillic spoofing
2. **AI Phishing Classification** - Separates AI-generated from traditional
3. **Production Security** - Enterprise-grade hardening
4. **93 ML Features** - 365% improvement over standard 20 features

### Test Results:
- ✅ 100% test coverage on security-critical code
- ✅ 5/5 security test suites passing
- ✅ 14 comprehensive test classes
- ✅ GDPR compliant

## 📚 Documentation

- 📖 [Complete Reference](docs/REFERENCE_DOCUMENT.md) - Technical specs
- 📊 [Final Report](docs/FINAL_REPORT.md) - Project summary
- 🎤 [IEEE Presentation](PRESENTATION.md) - 16 slides
- 🔧 [API Documentation](04_inference/api_docs.py) - OpenAPI specs

## 🧪 Testing

```bash
# Quick test
python detect_enhanced.py https://google.com

# Full test suite
python test_security.py
python test_comprehensive.py

# Interactive demos
python demo_security.py          # Basic interactive demo
python proof_of_working.py      # Step-by-step NLP (ideal for viva)
python final_demo.py            # Full presentation mode

# Quick proof for any URL (inline)
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
python proof_of_working.py
```

## 🛠️ Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Start MLflow
mlflow ui --backend-store-uri ./mlruns
```

## 📦 Deployment

### 🐳 Docker Deployment (Full API Server)

**⚠️ Note:** This deploys the **full FastAPI server** with all features (authentication, web scraping, MLLM support).
For lightweight 24/7 background protection, use the [Daemon Service](~/phishing-guard-daemon/) instead.

#### Quick Start (3 Commands)

```bash
# 1. Clone the repository
git clone https://github.com/BandiAkarsh/phishing_detection_project.git
cd phishing_detection_project

# 2. Build and start containers
docker-compose up --build -d

# 3. Check it's running
curl http://localhost:8000/health
```

**Clone other repositories:**
```bash
# Daemon Service (for 24/7 background protection)
git clone https://github.com/BandiAkarsh/phishing-guard-daemon.git
```

#### Step-by-Step Docker Setup

**Option A: Docker Compose (Recommended)**

```bash
# Start all services (API + Redis cache)
docker-compose up -d

# View logs
docker-compose logs -f api

# Check status
docker-compose ps

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up --build -d
```

**Option B: Single Docker Container (Simpler)**

```bash
# Build the image
docker build -t phishing-guard-api .

# Run the container
docker run -d \
  --name phishing-guard \
  -p 8000:8000 \
  -v $(pwd)/02_models:/app/02_models:ro \
  phishing-guard-api

# View logs
docker logs -f phishing-guard

# Stop container
docker stop phishing-guard
docker rm phishing-guard
```

#### Docker Services Overview

| Service | Container | Port | Purpose |
|---------|-----------|------|---------|
| **API** | `phishing-guard-api` | 8000 | FastAPI server with ML models |
| **Redis** | `phishing-guard-redis` | 6379 | Cache for detection results |

#### Testing the Docker Deployment

```bash
# 1. Health check
curl http://localhost:8000/health

# 2. View API documentation
curl http://localhost:8000/docs
# Open in browser: http://localhost:8000/docs

# 3. Test URL detection
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

#### Docker Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOAD_MLLM` | `false` | Enable Qwen/Ollama MLLM analysis |
| `PORT` | `8000` | API server port |
| `HOST` | `0.0.0.0` | Bind address |
| `CONNECTIVITY_CHECK_INTERVAL` | `30` | Seconds between connectivity checks |
| `SCRAPING_TIMEOUT` | `30000` | Web scraping timeout (ms) |

#### Common Docker Commands

```bash
# Restart API after code changes
docker-compose restart api

# Execute commands in container
docker-compose exec api bash
docker-compose exec api python detect_enhanced.py https://example.com

# View container stats
docker stats phishing-guard-api

# Update images
docker-compose pull
docker-compose up -d

# Clean up unused containers/volumes
docker-compose down -v
docker system prune
```

#### Troubleshooting Docker

```bash
# Container not starting - check logs
docker-compose logs api

# Port already in use - check what's using port 8000
sudo lsof -i :8000

# Permission denied on volumes
sudo chown -R $USER:$USER 02_models/

# Rebuild from scratch
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

---

### ⚙️ Background Daemon Service (Recommended for 24/7)

For lightweight, always-on protection (166KB):

```bash
# Install daemon
cd ~
sudo dpkg -i phishing-guard_2.0.0-1_all.deb

# Start service
sudo systemctl enable --now phishing-guard

# Configure email
phishing-guard config

# Check status
phishing-guard status
```

See `~/phishing-guard-daemon/README.md` for full daemon documentation.

## 🎯 Use Cases

- **Personal Security**: Browser extension + desktop app
- **Enterprise**: API server with JWT auth
- **Research**: MLflow experiments + 93 features
- **Education**: 4-category classification teaching

## 📞 Support & Contact

**Author: Akarsh Bandi**
- 📧 **Email**: akarshbandi82@gmail.com
- 💼 **LinkedIn**: [bandi-akarsh-b9339330a](https://www.linkedin.com/in/bandi-akarsh-b9339330a/)
- 🐱 **GitHub**: [BandiAkarsh](https://github.com/BandiAkarsh)
- 🐛 **Issues**: [GitHub Issues](https://github.com/BandiAkarsh/phishing_detection_project/issues)

## 👏 Acknowledgments

- **IEEE Project Guide**: [Add your guide's name]
- **Institution**: [Add your college/university]
- **Built with**: Python, FastAPI, scikit-learn, Playwright, MLflow

## 📄 License

MIT License - See LICENSE file

---

**🎓 Ready for IEEE Submission | 🏆 Production-Grade | 🔐 Enterprise Security**

Built with ❤️ for final year project defense.
