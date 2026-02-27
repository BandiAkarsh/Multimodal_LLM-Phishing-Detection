# 🧪 How to Test the Phishing Detection System

## Quick Start

### Method 1: Interactive Testing (Easiest)

```bash
# Navigate to the inference directory
cd ~/college-final-yr-projects/phishing_detection_project/04_inference

# Run the simple interactive tester
python ../tests/test_interactive_simple.py
```

**Then type any URL:**
```
🔍 Enter URL (or command): https://google.com
🔍 Enter URL (or command): https://suspicious-site.com
🔍 Enter URL (or command): examples
```

### Method 2: Using the API Server

**Terminal 1 - Start the server:**
```bash
cd ~/college-final-yr-projects/phishing_detection_project
python 04_inference/api.py
```

**Terminal 2 - Test with curl:**
```bash
# Check if server is running
curl http://localhost:8000/health

# Test a URL (no auth needed for testing)
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

### Method 3: Direct Python Script

Create a test file:
```python
# test_my_url.py
import sys
sys.path.insert(0, '04_inference')
sys.path.insert(0, '05_utils')

from service import PhishingDetectionService

# Load service (takes 10-30 seconds first time)
service = PhishingDetectionService(load_mllm=False)

# Test your URL
result = service.detect_phishing("https://your-url.com")
print(f"Classification: {result['classification']}")
print(f"Risk Score: {result['risk_score']}")
```

Run it:
```bash
cd ~/college-final-yr-projects/phishing_detection_project
python test_my_url.py
```

---

## Example URLs to Test

### ✅ Legitimate (Should be SAFE):
- `https://google.com`
- `https://github.com`
- `https://amazon.com`

### 🚨 Suspicious (Should be FLAGGED):
- `http://192.168.1.1/login` - IP address
- `https://login-paypal-secure.com` - Typosquatting
- `https://paypa1.com` - Numeric substitution

---

## Troubleshooting

### Error: "attempted relative import with no known parent package"

**Solution:** Run from the correct directory:
```bash
cd ~/college-final-yr-projects/phishing_detection_project/04_inference
python ../tests/test_interactive_simple.py
```

### Error: "No module named 'service'"

**Solution:** Make sure you're in the 04_inference directory and paths are set:
```bash
cd ~/college-final-yr-projects/phishing_detection_project/04_inference
export PYTHONPATH="..:$PYTHONPATH"
python ../tests/test_interactive_simple.py
```

### Loading Takes Too Long

**Normal!** First run loads ML models (10-30 seconds).
Subsequent runs are faster.

---

## Understanding Results

**Classification:**
- ✅ `LEGITIMATE` - Safe website
- 🚨 `PHISHING` - Phishing detected
- 🤖 `AI_GENERATED_PHISHING` - AI-created phishing
- 🛠️ `PHISHING_KIT` - Toolkit-based phishing

**Risk Score:**
- 0-30: Low risk
- 31-50: Medium risk  
- 51-70: High risk
- 71-100: Critical risk

---

## Testing the Daemon

The daemon has the same detection capability but lighter weight:

```bash
cd ~/college-final-yr-projects/phishing-guard-daemon

# Start the daemon API
python src/api_server.py

# Test it
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

---

## Need Help?

1. Check that all dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```

2. Make sure model files exist:
   ```bash
   ls 02_models/
   ```

3. Try the examples command in interactive mode to see it working
