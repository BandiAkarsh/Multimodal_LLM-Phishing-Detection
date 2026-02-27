# 🧪 Testing Phishing Detection with Custom Input

## Quick Start - Test with Your Own URLs

### Option 1: Interactive Testing (Recommended)

```bash
# Navigate to the project
cd ~/phishing_detection_project

# Install dependencies (if not already done)
pip install -r requirements.txt

# Run interactive tester
python tests/test_interactive.py
```

**What you can do:**
- Type any URL to analyze it
- Run example phishing tests
- Batch analyze URLs from a file
- See detailed risk scores and explanations

### Option 2: API Server + curl

```bash
# Terminal 1: Start the API server
python 04_inference/api.py

# Terminal 2: Test with curl
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-url-here.com"}'
```

### Option 3: Direct Python Script

```python
# test_custom.py
import sys
sys.path.insert(0, '04_inference')
from service import PhishingDetectionService

service = PhishingDetectionService(load_mllm=False)

# Test your URL
result = service.detect_phishing("https://your-url.com")
print(f"Classification: {result['classification']}")
print(f"Risk Score: {result['risk_score']}")
```

## Example URLs to Test

### Legitimate Sites (Should be SAFE)
- `https://google.com`
- `https://github.com`
- `https://amazon.com`
- `https://microsoft.com`

### Suspicious Patterns (Should be FLAGGED)
- `http://192.168.1.1/login` - IP address instead of domain
- `https://paypal-login-secure.com` - Suspicious keywords
- `https://paypa1.com` - Typosquatting (numeric substitution)
- `https://xn--pypal-4ve.com` - Punycode/homograph attack
- `https://login-secure-update.verify.com` - Multiple suspicious keywords

## Batch Testing

Create a file `my_urls.txt`:
```
https://google.com
https://suspicious-site.com/login
http://192.168.1.1/admin
https://xn--pypal-4ve.com
```

Then run:
```bash
python tests/test_interactive.py
# Type: batch my_urls.txt
```

## Understanding Results

**Classification Categories:**
- ✅ **LEGITIMATE** - Safe website
- 🚨 **PHISHING** - Traditional phishing attack
- 🤖 **AI_GENERATED_PHISHING** - AI-created phishing
- 🛠️ **PHISHING_KIT** - Toolkit-based phishing

**Risk Score:**
- 0-30: Low risk
- 31-50: Medium risk
- 51-70: High risk
- 71-100: Critical risk

**Key Features Analyzed:**
- URL structure and length
- Domain entropy (randomness)
- HTTPS status
- Suspicious keywords
- IDN/punycode detection
- Typosquatting patterns
