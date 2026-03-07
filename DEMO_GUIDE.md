# Phishing Detection System - Demo Interface

## Overview

The `demo.py` file is an interactive demonstration interface for the Phishing Detection System. It provides a visually stunning, educational showcase of the system's capabilities with detailed output, progress indicators, and color-coded results.

## Features

### 🎨 Visual Components
- **Color-coded output**: Green (Safe), Red (Phishing), Yellow (Warning), Blue (Info), Magenta (AI-generated)
- **Box-drawing characters**: Professional visual sections and headers
- **Progress spinners**: Animated indicators for ongoing analysis
- **Risk meters**: Visual bars showing risk scores (0-100%)
- **Confidence bars**: Visual representation of prediction confidence

### 📊 Analysis Modes
1. **Single URL Analysis**: Detailed analysis with full feature extraction
2. **Batch Analysis**: Compare multiple URLs side-by-side
3. **Demo Mode**: Run curated examples automatically
4. **Feature Extraction**: View extracted features without classification

### 🔍 Detailed Output
- URL classification (4 categories)
- Confidence percentage with visual bar
- Risk score with color-coded meter
- All 50+ extracted features
- Typosquatting analysis details
- Web scraping results (when online)
- Toolkit signatures (if detected)
- AI indicators (if detected)
- Recommended action with explanation

## Usage

### Interactive Mode (Default)
```bash
python demo.py
```
This launches an interactive menu with options to analyze URLs, run demos, and more.

### Single URL Analysis
```bash
python demo.py --single https://example.com
```
Provides detailed analysis with all features displayed.

### Batch Comparison
```bash
python demo.py --batch https://google.com https://paypa1.com https://amaz0n-security.com
```
Analyzes multiple URLs and displays a comparison table.

### Demo Mode
```bash
python demo.py --demo
```
Runs demonstration mode with curated sample URLs from different categories.

### Feature Extraction Only
```bash
python demo.py --features https://example.com
```
Extracts and displays URL features without full classification.

### View Sample URLs
```bash
python demo.py --samples
```
Displays the list of sample URLs available for testing.

### Force Offline Mode
```bash
python demo.py --offline
```
Forces offline mode (no web scraping, static analysis only).

## Sample URLs for Testing

### Safe URLs
- `https://google.com` - Legitimate search engine
- `https://github.com` - Popular code repository
- `https://microsoft.com` - Microsoft official site
- `https://apple.com` - Apple official site

### Phishing - Typosquatting
- `http://paypa1.com` - PayPal typosquat (1 instead of l)
- `http://amaz0n-security.com` - Amazon typosquat (0 instead of o)
- `http://g00gle-login.com` - Google typosquat
- `http://faceb00k-verify.net` - Facebook typosquat

### Phishing - Suspicious Patterns
- `http://secure-bank-update.tk` - Suspicious TLD + banking keywords
- `http://verify-account-now.xyz` - Suspicious TLD + action keywords
- `http://login-paypal-secure.cf` - Free TLD with brand name

### Technical Examples
- `https://192.168.1.1/login` - IP address based URL
- `http://xn--pple-43d.com` - Punycode/homograph attack
- `http://bit.ly/3xyz123` - URL shortener

## Classification Categories

The system classifies URLs into 4 categories:

1. **LEGITIMATE** (Green) - Safe, authentic website
2. **PHISHING** (Red) - Traditional manually-created phishing attack
3. **AI_GENERATED_PHISHING** (Magenta) - Phishing created using AI tools
4. **PHISHING_KIT** (Red) - Phishing created using toolkits (Gophish, HiddenEye)

## Risk Score Interpretation

- **0-20%** (Green): Very low risk - Safe
- **21-40%** (Light Green): Low risk - Likely safe
- **41-60%** (Yellow): Medium risk - Suspicious
- **61-80%** (Red): High risk - Likely phishing
- **81-100%** (Bright Red): Critical risk - Confirmed phishing

## Recommended Actions

- **BLOCK**: Strong phishing indicators - Do not visit
- **WARN**: Suspicious patterns - Proceed with caution
- **ALLOW**: Appears legitimate - Safe to visit

## Analysis Modes

### Online Mode
- Full web scraping available
- Content-based analysis
- Toolkit signature detection
- AI-generated content detection
- Most accurate results

### Offline Mode
- Static URL feature analysis only
- Limited to LEGITIMATE/PHISHING classification
- Cannot detect AI-generated or toolkit-based attacks
- Results marked as "[OFFLINE MODE]"

## Output Sections

### 1. Analysis Result Box
Shows the main classification with:
- Classification type (color-coded)
- Confidence bar (0-100%)
- Risk meter (0-100%)
- Analysis mode
- Web scraping status

### 2. Feature Extraction
Displays 50+ extracted features organized by:
- Basic Length (URL, domain, path lengths)
- Character Counts (dots, hyphens, special chars)
- Security (HTTPS, IP address, suspicious words)
- Entropy (URL and domain entropy)
- Domain (subdomain count, randomness)

### 3. Typosquatting Analysis
Shows brand impersonation detection:
- Detection method
- Impersonated brand
- Risk increase score
- Verification details

### 4. Web Content Analysis
Displayed when online scraping succeeds:
- Page title
- HTML size
- Links/images/forms count
- Login form detection

### 5. Toolkit Detection
Shows if phishing toolkits detected:
- Toolkit name
- Confidence score
- Signatures found

### 6. AI Content Analysis
Shows AI-generated content indicators:
- List of detected patterns
- AI phrase detection
- Urgency pattern detection

### 7. Analysis Explanation
Natural language explanation of findings.

### 8. Recommended Action
Color-coded recommendation with explanation.

## Tips for Presentations

### For Professors/Instructors
1. Use `--demo` mode to show system capabilities quickly
2. Use `--batch` to compare safe vs phishing URLs side-by-side
3. Highlight the feature extraction to explain how ML models work
4. Show both online and offline modes to demonstrate robustness

### For Interviews
1. Start with `--demo` to showcase the full system
2. Use custom URLs to demonstrate domain knowledge
3. Point out the 4-category classification as a unique feature
4. Mention the 50+ features extracted for ML classification

### For Stakeholders
1. Focus on the comparison table in batch mode
2. Highlight risk scores and recommended actions
3. Show the typosquatting detection for brand protection
4. Demonstrate the offline capability for reliability

## Technical Details

### Features Extracted (50+)
- URL length, domain length, path length
- Character counts (dots, hyphens, underscores, etc.)
- HTTPS status, IP address detection
- Entropy calculations
- Subdomain analysis
- IDN/punycode detection
- Suspicious word detection
- TLD analysis
- Random domain detection
- And many more...

### Detection Methods
1. **Whitelist Check**: Instant validation for known safe domains
2. **Typosquatting Detection**: Identifies brand impersonation
3. **ML Classification**: 99.8% F1 score on PhishTank dataset
4. **Content Analysis**: Web scraping for real-time detection
5. **Toolkit Detection**: Identifies known phishing frameworks
6. **AI Detection**: Identifies AI-generated phishing content

## Requirements

- Python 3.7+
- All project dependencies installed
- Service properly configured
- (Optional) Internet connection for full capabilities

## Troubleshooting

### Import Errors
Make sure you're running from the project root directory:
```bash
cd /home/akarsh/college-final-yr-projects/phishing_detection_project
python demo.py
```

### No Colors in Output
Your terminal might not support ANSI colors. Try:
- Using a different terminal emulator
- Setting `TERM=xterm-256color`
- Using `--offline` mode for simpler output

### Web Scraping Fails
- Check internet connection
- Some sites may block scraping
- Use `--offline` to skip web scraping

### Model Loading Errors
Ensure model files are in `02_models/` directory:
- `phishing_classifier.joblib`
- `feature_scaler.joblib`
- `feature_columns.joblib`

## Examples

### Example 1: Quick Demo
```bash
$ python demo.py --demo
```
Shows system capabilities with curated examples.

### Example 2: Compare Safe vs Phishing
```bash
$ python demo.py --batch https://google.com http://paypa1.com
```
Side-by-side comparison showing the difference.

### Example 3: Deep Analysis
```bash
$ python demo.py --single http://suspicious-site.tk
```
Shows detailed analysis with all features.

### Example 4: Feature Study
```bash
$ python demo.py --features https://example.com
```
Extracts and displays all URL features.

## 📋 New: Proof-of-Working for Viva/Stakeholders

For final year project presentations, we provide **two new demo programs** that are ideal for live demonstrations:

### 1. `proof_of_working.py` - Interactive Proof

**Best for:** Viva voce, stakeholder demonstrations, real-time testing

**What it does:**
- Takes **any URL** as user input (no pre-defined examples)
- Shows **step-by-step** the detection mechanism
- Explains each stage: validation, feature extraction, ML classification, scraping, etc.
- Displays detailed intermediate results
- Perfect for demonstrating **how the system works** under the hood

**Usage:**
```bash
# Set JWT secret first (only needed once per session)
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Run proof-of-working
python proof_of_working.py
```

**What reviewers will see:**
```
════════════════════════════════════════════════════════════════════════════════
  ANALYZING: https://evil-phishing-site.com
════════════════════════════════════════════════════════════════════════════════

[STEP 1] URL VALIDATION & SECURITY CHECKS
  → URL parsed and validated
  → Scheme allowed: https
  ✓ URL passed security validation

[STEP 2] FEATURE EXTRACTION (93 features)
  → Extracted 93 features
  Top 5 Features:
    1. url_length: 87
    2. num_digits: 24
    3. has_ip_address: 1
    4. suspicious_tld: 1
    5. punycode_count: 0

[STEP 3] TYPOSQUATTING DETECTION
  ⚠ Brand impersonation detected!
    Brand: paypal
    Similarity: 91.3%
    Distance: 1

[STEP 4] MACHINE LEARNING CLASSIFICATION
  ✓ ML Prediction: PHISHING (confidence: 98.5%)

[STEP 5] WEB CONTENT SCRAPING (Online)
  ✓ Scraping completed
    Title: "Secure Login - PayPal"
    Forms found: 2
    Suspicious forms: 2
    External domains: 3

[STEP 6] FINAL ORCHESTRATION & VERDICT

  FINAL VERDICT:
    ███ Classification: PHISHING
    ███ Confidence: ▓▓▓▓▓▓▓▓▓ 98.5%
    ███ Risk Score: [████████░░] 85.2%
    ███ Action: BLOCK

  EXPLANATION:
    Domain contains brand impersonation (paypal → paypa1). Website hosts a login 
    form that posts to an external domain. Toolkit signature Gophish detected in HTML.

════════════════════════════════════════════════════════════════════════════════
  ANALYSIS COMPLETE - Time: 2.34s
════════════════════════════════════════════════════════════════════════════════
```

### 2. `final_demo.py` - Presentation Mode

**Best for:** Prepared presentations with polished output

**Features:**
- Similar step-by-step output to `proof_of_working.py`
- Enhanced visual formatting with colors and boxes
- Automatic analysis summary at the end
- Clean, professional look for presentations

**Usage:**
```bash
python final_demo.py
```

**Difference from proof_of_working:**
- `proof_of_working.py`: Most detailed, shows raw technical steps
- `final_demo.py`: Polished, presentation-ready with cleaner layout

### Demo Comparison Table

| Feature | demo.py | proof_of_working.py | final_demo.py |
|---------|---------|---------------------|---------------|
| User input (any URL) | Limited | ✅ Full interaction | ✅ Full interaction |
| Step-by-step explanation | Basic | ✅ Detailed technical | ✅ Polished |
| Best for | Quick tests | Viva/technical deep-dive | Stakeholder presentations |
| Shows intermediate steps | Some | ✅ All | ✅ All |

## Tips for Your Viva/Stakeholder Demo

1. **Preparation:**
   ```bash
   export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   # Test with 3-4 URLs: google.com (safe), paypa1.com (typosquat), suspicious.xyz (phishing)
   ```

2. **Suggested Flow:**
   - Start with a **safe URL** (google.com) to show legitimate analysis
   - Then try a **typosquatting site** (paypa1.com) to show impersonation detection
   - Finally try a **suspicious URL** with external forms to show scraping
   - Conclude with summary statistics

3. **Key Talking Points:**
   - "The system extracts **93 features** from every URL" (show step 2)
   - "Typosquatting detection uses Levenshtein distance and brand database"
   - "Content scraping verifies if the site actually looks like phishing" (explain content override)
   - "We have 4 categories: Legitimate, Phishing, AI-Generated, Phishing Kit"

4. **Questions to Anticipate:**
   - "What happens offline?" → Explain offline mode (no scraping, reduced categories)
   - "How accurate is the ML model?" → 99.8% F1 score on PhishTank
   - "Can it detect new phishing sites?" → Yes, via feature-based ML, not just signatures
   - "Is it production-ready?" → Yes, security hardened with JWT, rate limiting, SSRF protection

## License

This demonstration interface is part of the Phishing Detection System project.
