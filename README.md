# 🛡️ Phishing Website Detection System using Multimodal MLLM

> **Final Year Project (IEEE Standard)**  
> **Status:** Production Ready ✅

A comprehensive cybersecurity system that detects phishing websites using a **Multi-Tiered Approach**:
1.  **Typosquatting & Brand Impersonation Detection** (Tier 1)
2.  **Machine Learning Classifier** (Random Forest, 99.8% Accuracy) (Tier 2)
3.  **Multimodal Large Language Model** (Qwen2.5-3B) for explainable analysis (Tier 3)

---

## 🚀 Key Features

*   **Multimodal Analysis**: Analyzes URL structure, HTML content, and Screenshot metadata.
*   **Real-Time Email Scanning**: Automatically scans your inbox (IMAP) or `.eml` files.
*   **Explainable AI**: Provides human-readable reasons for flagging a site (e.g., "This site mimics PayPal's login page...").
*   **Dockerized**: Fully containerized for easy deployment.
*   **API-First**: FastAPI-based REST API for integration with security gateways.

---

## 🛠️ Installation

### Prerequisites
*   Python 3.10+
*   Docker (Optional, for containerized run)
*   NVIDIA GPU (Recommended for MLLM features)

### Local Setup

1.  **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/phishing-detection-project.git
    cd phishing-detection-project
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

---

## 💻 Usage

### 1. Interactive URL Scanner (CLI)
Quickly test a single URL.
```bash
python detect.py https://paypa1.com
```

### 2. Automated Email Scanner (IMAP)
Connects to your email and scans the inbox for phishing links.
```bash
python imap_scanner.py
```
*   Follow the prompts to enter your IMAP server (e.g., `imap.gmail.com`), email, and App Password.

### 3. File Scanner (.eml)
Scan a specific email file saved from Thunderbird/Outlook.
```bash
python scan_email.py sample_phishing.eml
```

### 4. Run as a Web Service (API)
Start the FastAPI server.
```bash
cd 04_inference
uvicorn api:app --host 0.0.0.0 --port 8000
```
*   **Swagger Docs**: http://localhost:8000/docs

---

## 🐳 Docker Deployment

Build and run the entire system with one command:

```bash
docker-compose up --build
```

The API will be available at `http://localhost:8000`.

---

## 🧠 System Architecture

The system uses a **Tiered Detection Logic** to optimize resources:

| Tier | Component | Function | Speed |
|------|-----------|----------|-------|
| **1** | **Typosquatting** | Checks for faulty extensions (.pom, .corn) and brand impersonation (b1inkit). | Instant |
| **2** | **ML Classifier** | Random Forest model trained on 46k+ URLs. | < 50ms |
| **3** | **MLLM (Qwen)** | Generates detailed explanation if the site is suspicious or ambiguous. | 2-5s |

---

## 📊 Performance

*   **F1 Score**: 99.8% (on PhishTank dataset)
*   **Brand Protection**: Covers 50+ Global & Indian brands (Flipkart, SBI, HDFC, PayPal, Google, etc.)

---

## 📂 Project Structure

```
├── 01_data/          # Datasets (PhishTank, OpenPhish)
├── 02_models/        # Trained ML models (.joblib)
├── 03_training/      # Training scripts
├── 04_inference/     # FastAPI Service code
├── 05_utils/         # Feature extraction & Detectors
├── detect.py         # CLI Entry point
├── imap_scanner.py   # Email Automation
└── scan_email.py     # EML Parser
```
