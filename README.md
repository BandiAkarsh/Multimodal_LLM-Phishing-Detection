# 🛡️ Phishing Guard Unified Suite

> **Final Year Project (IEEE Standard)**  
> **Status:** Production Ready ✅ | **Classification**: 4-Category AI (Legit, Phish, AI-Gen, Toolkit)

Phishing Guard is a professional-grade security ecosystem that provides 24/7 background protection for your email. It monitors your inbox at the protocol level, making it compatible with every browser (Chrome, Firefox) and every mail app (Thunderbird, Outlook).

---

## 🚀 Key Features

*   **Multimodal Analysis**: Analyzes URL structure, HTML content, and Screenshot metadata.
*   **Universal Protection**: Monitors IMAP services directly (Gmail, Outlook, Yahoo).
*   **Silent Background Guard**: Runs as a system daemon (service) on Linux.
*   **Native Desktop Alerts**: Instant system notifications when threats are detected.
*   **Explainable AI**: Provides human-readable reasons for flagging a site.

---

## 🛠️ Quick Start (Unified Suite)

The **Unified Suite** is the recommended way to use Phishing Guard. It includes a guided setup wizard and automated system service installation.

1.  **Navigate to the project**
    ```bash
    cd ~/phishing_detection_project
    ```

2.  **Run the Guided Setup**
    ```bash
    python3 setup_wizard.py
    ```
    *Follow the on-screen instructions to link your email (OTP-style for Gmail) and enable background protection.*

3.  **Enjoy 24/7 Protection**
    You can close the terminal. Phishing Guard will now send you a desktop notification whenever a threat is found.

---

## 💻 Developer Entry Points

If you want to use individual components:

### 1. Interactive URL Scanner (CLI)
```bash
python detect.py https://paypa1.com
```

### 2. File Scanner (.eml)
```bash
python scan_email.py sample_phishing.eml
```

### 3. Run as a Web Service (API)
```bash
cd 04_inference
uvicorn api:app --host 0.0.0.0 --port 8000
```

---

## 🧠 System Architecture

The system uses a **Tiered Detection Logic** to optimize resources:

| Tier | Component | Function |
|------|-----------|----------|
| **1** | **Typosquatting** | Checks for faulty extensions and brand impersonation using 1592 TLDs. |
| **2** | **ML Classifier** | Random Forest model trained on 46k+ URLs (99.8% F1 Score). |
| **3** | **Toolkit Detect** | Detects Gophish, Evilginx2, and other phishing frameworks. |
| **4** | **AI Content** | Linguistic analysis for AI-generated phishing content. |
| **5** | **Scraping** | Real-time Playwright-based content verification (Overrides static risk). |

---

## 📂 Project Structure

```
├── 01_data/          # Datasets and TLD Database
├── 02_models/        # Trained ML models (.joblib)
├── 03_training/      # Training scripts
├── 04_inference/     # FastAPI Service code
├── 05_utils/         # Core Scrapers & Detectors
├── setup_wizard.py   # NEW: Professional Onboarding Wizard
├── imap_scanner.py   # NEW: Background Daemon Watchdog
├── detect.py         # CLI Tool
└── scan_email.py     # EML Parser
```
