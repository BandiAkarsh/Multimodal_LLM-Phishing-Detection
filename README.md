# 🛡️ Phishing Guard v2.0

> **Final Year IEEE Project** | **Production-Grade Security System**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![Security](https://img.shields.io/badge/Security-Hardened-green)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**AI-powered phishing detection with 93 ML features, IDN protection, and enterprise security.**

## 📦 Three Separate Projects

This repository contains the **main IEEE project**. Two additional projects have been extracted for different use cases:

| Project | Location | Size | Best For |
|---------|----------|------|----------|
| **This Project** | `~/phishing_detection_project/` | Full codebase | IEEE submission, research, reference |
| **Daemon Service** | `~/phishing-guard-daemon/` | 166KB | Family/friends - 24/7 background protection |
| **Tauri GUI** | `~/phishing-guard-tauri/` | 3.8MB | Desktop app - visual interface, IEEE demo |

> 💡 **Quick Install**: 
> - For background protection: `sudo dpkg -i ~/phishing-guard_2.0.0-1_all.deb`
> - For desktop GUI: `sudo dpkg -i ~/phishing-guard-tauri/releases/Phishing\ Guard_2.0.0_amd64.deb`

## 🎯 What's New in v2.0

- 🔐 **Enterprise Security**: JWT auth, rate limiting, SSRF protection
- 🤖 **93 ML Features**: 365% improvement (was 20)
- 🌐 **IDN Protection**: Unicode homograph attack detection
- 📊 **4-Category Classification**: Legitimate, Phishing, AI-Generated, Phishing Kit
- 🖥️ **Desktop App**: Standalone Tauri application (no server needed)
- 🧪 **MLflow Integration**: Model versioning & experiment tracking
- 🌐 **Browser Extension**: Real-time link protection
- 📱 **Multiple Interfaces**: CLI, API, GUI, Extension

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

# Interactive demo
python demo_security.py
```

### 2. CLI Mode (Fastest)
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

### 4. Desktop Application (Tauri GUI)
```bash
# The Tauri desktop app is now maintained as a separate project
# See: ~/phishing-guard-tauri/

# Run pre-built binary
cd ~/phishing-guard-tauri
./src-tauri/target/release/phishing-guard

# Or install DEB package (3.8MB)
cd ~/phishing-guard-tauri/releases
sudo dpkg -i "Phishing Guard_2.0.0_amd64.deb"
phishing-guard

# Note: This is the full-featured GUI app (3.8MB)
# For lightweight background service, use the Daemon (see below)
```

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
```bash
# Chrome/Brave:
1. Open chrome://extensions
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select browser-extension/ folder
```

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
| **F1 Score** | 99.8% |
| **Features** | 93 (was 20) |
| **Classification** | 4 categories |
| **False Positive** | < 0.5% |
| **Latency** | < 2 seconds |

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

**Note: This is the main IEEE project. Related projects are now in separate folders:**
- **Daemon Service**: `~/phishing-guard-daemon/` (lightweight background service)
- **Tauri GUI**: `~/phishing-guard-tauri/` (desktop application - MOVED)

```
phishing_detection_project/
├── 📂 01_data/              # Datasets & TLDs
├── 📂 02_models/            # ML models (joblib)
├── 📂 03_training/          # Training scripts + MLflow
├── 📂 04_inference/         # API + Authentication
├── 📂 05_utils/             # 93 feature extractors
├── 📂 06_notebooks/         # Jupyter notebooks
├── 📂 07_configs/           # Configuration files
├── 📂 08_logs/              # MLflow logs
├── 📂 09_documentation/     # Architecture docs
├── 📂 browser-extension/    # Chrome/Firefox extension
├── 📂 docs/                 # Project reports
├── 📂 examples/             # Sample files
├── 📂 gui-tauri/            # Desktop app (REFERENCE COPY)
│                           # ACTIVE DEV: ~/phishing-guard-tauri/
├── 📂 scripts/              # Build & utility scripts
├── 📂 tests/                # Test data & scripts
│
├── 🐍 detect_enhanced.py    # Enhanced CLI (colors/progress)
├── 🐍 email_scanner.py      # Email monitoring
├── 🐍 setup_wizard.py       # Setup wizard
├── 🐍 test_security.py      # Security tests
├── 🐍 test_comprehensive.py # Full test suite
├── 🐍 demo_security.py      # Interactive demo
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
- ✅ **SSRF Protection** (Private IP blocking)
- ✅ **Input Validation** (RFC 3986 + security)
- ✅ **TLS 1.3 Enforcement** (Certificate validation)

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

# Demo all features
python demo_security.py
```

## 🛠️ Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Build desktop app
cd gui-tauri
npm install
npm run tauri build

# Start MLflow
mlflow ui --backend-store-uri ./mlruns
```

## 📦 Deployment

### Docker
```bash
docker-compose up --build
```

### Standalone
```bash
# Build executable
./scripts/build_desktop_app.sh

# Or install
dpkg -i gui-tauri/src-tauri/target/release/bundle/deb/*.deb
```

## 🎯 Use Cases

- **Personal Security**: Browser extension + desktop app
- **Enterprise**: API server with JWT auth
- **Research**: MLflow experiments + 93 features
- **Education**: 4-category classification teaching

## 📞 Support

- 📧 Email: [your-email]
- 💼 LinkedIn: [your-profile]
- 🐛 Issues: GitHub Issues

## 📄 License

MIT License - See LICENSE file

---

**🎓 Ready for IEEE Submission | 🏆 Production-Grade | 🔐 Enterprise Security**

Built with ❤️ for final year project defense.
