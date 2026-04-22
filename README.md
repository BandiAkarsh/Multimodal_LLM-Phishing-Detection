# 🛡️ Phishing Guard v2.0

> **Final Year IEEE Project** | **AI-Powered Phishing Detection System**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

AI-powered phishing detection with 93 ML features, IDN protection, and enterprise security.

## 🚀 Quick Start

### Prerequisites
```bash
# Install Python dependencies
pip install -r requirements.txt
```

### Run Detection
```bash
# CLI mode
python 04_inference/service.py https://example.com

# API server
python 04_inference/api.py

# Run tests
pytest tests/
```

## 📦 Project Structure

```
phishing_detection_project/
├── 01_data/              # Datasets & TLDs
├── 02_models/            # ML models (joblib)
├── 03_training/          # Training scripts + MLflow
├── 04_inference/         # API + Service
├── 05_utils/             # 93 feature extractors
├── 06_notebooks/         # Jupyter notebooks
├── 07_configs/           # Configuration files
├── browser-extension/    # Chrome/Firefox extension
├── tests/                # Test suite
│
├── Dockerfile            # Container deployment
├── docker-compose.yml    # Docker orchestration
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## 🎯 Features

- **93 ML Features** - Advanced feature engineering
- **4-Category Classification** - Legitimate, Phishing, AI-Generated, Phishing Kit
- **IDN Protection** - Unicode homograph attack detection
- **Browser Extension** - Real-time link protection
- **MLflow Integration** - Model versioning & experiment tracking
- **API Server** - RESTful endpoints with JWT authentication

## 🧪 Testing

```bash
# Run test suite
pytest tests/ -v

# Run specific tests
python -m pytest tests/test_security.py
python -m pytest tests/test_comprehensive.py
```

## 📊 Detection Accuracy

| Metric | Value |
|--------|-------|
| **F1 Score** | 99.82% |
| **Precision** | 99.81% |
| **Recall** | 99.83% |
| **Features** | 93 |
| **Classification** | 4 categories |

## 🔐 Security Features

- JWT Authentication (24hr tokens)
- Rate Limiting (100 req/min)
- SSRF Protection
- TLS 1.3 Enforcement
- Input Validation

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         User Interfaces                 │
│    CLI • API • Browser Extension        │
└─────────────────┬───────────────────────┘
                  │
        ┌────────┴────────┐
        │ Detection Core │
        │  93 Features   │
        └────────┬────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───┴───┐   ┌────┴────┐   ┌────┴────┐
│ Tier 1│   │ Tier 2  │   │ Tier 3  │
│ ML    │   │ Typosquat│   │ MLLM   │
└───────┘   └─────────┘   └─────────┘
```

## 🤖 ML Models

- **Random Forest Classifier** (200 estimators)
- **XGBoost Classifier** (50 estimators)
- **Ensemble Method**: Soft Voting
- **Optional**: Qwen2.5-3B for AI-generated phishing detection

## 🌐 Browser Extension

See [browser-extension/](browser-extension/) for installation instructions.

```bash
cd browser-extension
npm install
npm run build
```

## 📚 Documentation

- [API Documentation](API.md) - API endpoints
- [Security Policy](SECURITY.md) - Security details
- [Deployment Guide](DEPLOYMENT.md) - Docker deployment
- [Browser Extension](browser-extension/README.md) - Extension setup

## 📞 Support

- **Author**: Akarsh Bandi
- **Email**: akarshbandi82@gmail.com
- **GitHub**: [BandiAkarsh](https://github.com/BandiAkarsh)

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

**🎓 Final Year IEEE Project**
