# 05_utils Folder Documentation

## Overview

The `05_utils/` folder contains utility modules used throughout the project. These are the "building blocks" that extract features, detect patterns, and scrape websites.

## Folder Structure

```
05_utils/
├── url_extractor.py             # Shared URL extraction (Regex-based)
├── feature_extraction.py       # ML feature extraction (Handcrafted)
├── typosquatting_detector.py   # TLD-aware brand impersonation
├── web_scraper.py              # Toolkit-fingerprinting scraper
├── connectivity.py             # Internet connectivity checker
├── mllm_transformer.py         # AI detection & 4-way classification
├── text_feature_generator.py   # Batch MLLM processing
├── data_preparation.py         # Dataset preprocessing
└── common_words.py             # Dictionary for gibberish detection
```

---

## 1. `url_extractor.py` - Shared Extraction Utility

A robust, shared utility used by the Thunderbird add-on backend and the IMAP scanner to extract URLs from plain text and HTML emails.

```python
def extract_urls(text: str) -> List[str]:
    # Uses advanced regex to identify URLs while 
    # filtering out common noise and tracking pixels.
```

---

## 2. `typosquatting_detector.py` - TLD-Aware Detection

**MAJOR UPDATE**: Now integrates with a database of 1,592 valid TLDs.

### Improvements:
- **TLD Verification**: No longer flags `.bank`, `.google`, or `.apple` as suspicious extensions.
- **Content Verification**: In ONLINE mode, the detector can verify if a site's content matches the impersonated brand. If `kotaksalesianschool.com` is actually a school and not a bank, it is marked as LEGITIMATE.
- **Subdomain Analysis**: Correctly identifies subdomains by recognizing multi-part TLDs like `.co.uk` and `.bank.in`.

---

## 3. `web_scraper.py` - Toolkit Fingerprinting

**NEW**: Now includes `ToolkitSignatureDetector` to identify phishing frameworks.

### Detected Toolkits:
| Toolkit | Signatures |
|---------|------------|
| **Gophish** | `?rid=` parameter, `X-Gophish-Contact` header |
| **Evilginx2** | Proxy redirect patterns, session cookie structures |
| **HiddenEye** | Specific CSS classes, `pish.js` patterns |
| **King Phisher** | Campaign IDs, tracking headers |
| **SocialFish** | Unique form field combinations |

### Logic:
- Analyzes HTTP headers, cookies, and DOM patterns.
- Requires multiple indicators for high-confidence toolkit detection to avoid false positives on legitimate complex domains.

---

## 5. `mllm_transformer.py` - AI & 4-Way Classification

**NEW**: Now includes logic for advanced classification beyond binary phishing/legitimate.

### Class: `MLLMFeatureTransformer`

This module uses semantic analysis to categorize threats:

1.  **AI Detection**: Identifies linguistic markers common in AI-generated phishing content (e.g., overly formal tone, repetitive structures, specific GPT-like phrasing).
2.  **4-Way Logic**:
    - **LEGITIMATE**: High content credibility, verified brand match.
    - **PHISHING**: Brand impersonation or high static risk without toolkit signatures.
    - **AI_GENERATED_PHISHING**: Phishing content identified as LLM-generated.
    - **PHISHING_KIT**: Site identified as using a known framework (Gophish, etc.).

---

## 6. `common_words.py` - Dictionary


Contains common English words to distinguish real words from gibberish.

```python
COMMON_WORDS = {
    'the', 'of', 'and', 'a', 'to', 'in', 'is', 'you',
    'google', 'facebook', 'amazon', 'paypal',
    'login', 'account', 'verify', 'secure',
    # ... 600+ words
}
```

**Usage:** If a domain is a real word (like "apple"), it's not flagged as random even if it has unusual letter patterns.

---

## How Utils Connect to Service

```
PhishingDetectionService
         │
         ├── URLFeatureExtractor (feature_extraction.py)
         │   └── Extracts 17+ features from URL
         │
         ├── TyposquattingDetector (typosquatting_detector.py)
         │   └── Detects brand impersonation
         │
         ├── WebScraper (web_scraper.py)
         │   └── Scrapes website content
         │
         ├── ConnectivityMonitor (connectivity.py)
         │   └── Checks internet availability
         │
         └── MLLMFeatureTransformer (mllm_transformer.py)
             └── Generates explanations
```

---

*This documentation explains the `05_utils/` folder for beginners.*
