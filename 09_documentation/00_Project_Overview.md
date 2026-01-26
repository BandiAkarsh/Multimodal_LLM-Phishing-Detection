# Phishing Detection Project - Complete Documentation

## Project Overview

This documentation provides a comprehensive guide to the **Multimodal LLM-based Phishing Detection System**. The project is designed to detect phishing websites using a combination of:

1. **Machine Learning** - Random Forest classifier trained on 46,000+ URLs
2. **Web Scraping** - Real-time analysis of website content
3. **Typosquatting Detection** - Identifies brand impersonation attempts
4. **Large Language Models** - Provides human-readable explanations

## Key Feature: Internet-Aware Detection

The system automatically adapts to network conditions:

### Online Mode (Internet Available)
- Scrapes the actual website content
- Analyzes DOM structure (forms, inputs, links)
- Validates page content for credibility
- **More accurate** - ignores false positives from URL heuristics

### Offline Mode (No Internet)
- Uses static URL feature analysis
- Applies vowel/consonant patterns, entropy checks
- Relies on ML model predictions
- Results marked with "[OFFLINE MODE]" warning

## Documentation Structure

| Document | Description |
|----------|-------------|
| `00_Project_Overview.md` | This file - project introduction |
| `01_Data_Folder.md` | Datasets, data structure, preprocessing |
| `02_Models_Folder.md` | Trained models, how to use them |
| `03_Training_Folder.md` | Training scripts with line-by-line explanations |
| `04_Inference_Folder.md` | API, service, and schemas documentation |
| `05_Utils_Folder.md` | Utility modules (feature extraction, scraping, etc.) |
| `06_Entry_Points.md` | Main scripts (detect.py, scan_email.py, etc.) |
| `07_Docker_Deployment.md` | Docker setup and deployment guide |
| `08_GUI_Guide.md` | How to use the desktop GUI application |

## Quick Start

### 1. Installation
```bash
pip install -r requirements.txt
playwright install chromium  # For web scraping
```

### 2. Run CLI Tool
```bash
python detect.py                    # Interactive mode
python detect.py https://example.com  # Single URL
```

### 3. Run GUI
```bash
python gui.py
```

### 4. Run API
```bash
cd 04_inference
uvicorn api:app --host 0.0.0.0 --port 8000
```

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER INTERFACES                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ detect.py│  │  gui.py  │  │  api.py  │  │ imap_scanner.py  │ │
│  │   (CLI)  │  │  (GUI)   │  │  (REST)  │  │  (Email Monitor) │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
└───────┼─────────────┼─────────────┼─────────────────┼───────────┘
        │             │             │                 │
        └─────────────┴──────┬──────┴─────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                    DETECTION SERVICE                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              PhishingDetectionService                     │   │
│  │  ┌─────────────────┐  ┌─────────────────────────────────┐│   │
│  │  │ Connectivity    │  │ analyze_url_async()             ││   │
│  │  │ Monitor         │  │                                 ││   │
│  │  └────────┬────────┘  │  ┌──────────┐ ┌──────────────┐ ││   │
│  │           │           │  │ Online   │ │ Offline      │ ││   │
│  │           │           │  │ Analysis │ │ Fallback     │ ││   │
│  │           │           │  └──────────┘ └──────────────┘ ││   │
│  │           │           └─────────────────────────────────┘│   │
│  └───────────┼──────────────────────────────────────────────┘   │
└──────────────┼──────────────────────────────────────────────────┘
               │
┌──────────────┴──────────────────────────────────────────────────┐
│                    UTILITY MODULES (05_utils/)                   │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────┐ │
│  │ URLFeature     │ │ WebScraper     │ │ TyposquattingDetector│ │
│  │ Extractor      │ │ (Playwright)   │ │                      │ │
│  └────────────────┘ └────────────────┘ └──────────────────────┘ │
│  ┌────────────────┐ ┌────────────────┐                          │
│  │ Connectivity   │ │ MLLM           │                          │
│  │ Checker        │ │ Transformer    │                          │
│  └────────────────┘ └────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

## Detection Logic Flow

```
URL Input
    │
    ▼
┌─────────────────────────────────────────┐
│ CHECK INTERNET CONNECTION               │
│   - Ping DNS servers (1.1.1.1, 8.8.8.8)│
│   - Cache result for 30 seconds         │
└─────────────────────────────────────────┘
    │
    ├── ONLINE ──────────────────────────────┐
    │                                        │
    ▼                                        ▼
┌─────────────────────┐          ┌─────────────────────┐
│ ONLINE ANALYSIS     │          │ OFFLINE FALLBACK    │
│                     │          │                     │
│ 1. Check whitelist  │          │ 1. Extract URL      │
│ 2. Typosquatting    │          │    features         │
│ 3. Web scraping     │          │ 2. Vowel/consonant  │
│ 4. DOM analysis     │          │    analysis         │
│ 5. Content-based    │          │ 3. ML prediction    │
│    risk score       │          │ 4. Static risk      │
│                     │          │    score            │
│ IGNORES static      │          │                     │
│ URL heuristics!     │          │ Add "[OFFLINE]"     │
│                     │          │ warning             │
└─────────────────────┘          └─────────────────────┘
    │                                        │
    └────────────────────┬───────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ FINAL CLASSIFICATION│
              │                     │
              │ - legitimate        │
              │ - phishing          │
              │ - Confidence %      │
              │ - Risk Score 0-100  │
              │ - Explanation       │
              └─────────────────────┘
```

## Key Files Changed for Internet-Aware Detection

| File | Change |
|------|--------|
| `05_utils/connectivity.py` | **NEW** - Internet connectivity checker |
| `04_inference/service.py` | Dual-mode analysis (online/offline) |
| `detect.py` | Connectivity status display, --offline flag |
| `scan_email.py` | Async support, connectivity fallback |
| `imap_scanner.py` | Periodic connectivity check |
| `04_inference/api.py` | Connectivity endpoint, status in responses |
| `gui.py` | **NEW** - Beautiful desktop application |
| `Dockerfile` | Playwright dependencies |
| `docker-compose.yml` | Connectivity settings |

## Contact & Support

For issues or questions, please open an issue on GitHub.

---

*Documentation generated for Phishing Detection Project v2.0*
