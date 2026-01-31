#!/bin/bash
# Comprehensive Testing Guide for Phishing Guard v2.0
# This script demonstrates all ways to test/run the project

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           PHISHING GUARD v2.0 - TESTING GUIDE                    ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

echo "📍 Project Location: $PROJECT_ROOT"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print section headers
print_section() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# Function to print test result
print_result() {
    if [ $1 -eq 0 ]; then
        echo "  ✅ $2"
    else
        echo "  ❌ $2"
    fi
}

print_section "1. ENVIRONMENT CHECK"

echo "Checking Python..."
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    echo "  ✅ $PYTHON_VERSION"
else
    echo "  ❌ Python3 not found"
    exit 1
fi

echo ""
echo "Checking dependencies..."
python3 -c "import sklearn, colorama, mlflow" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  ✅ All core dependencies installed"
else
    echo "  ⚠️  Some dependencies missing"
    echo "  Install: pip install -r requirements.txt"
fi

echo ""
echo "Checking models..."
if [ -f "02_models/phishing_classifier.joblib" ]; then
    echo "  ✅ ML model found"
else
    echo "  ⚠️  Model not trained yet"
    echo "  Train: python 03_training/train_ml.py"
fi

print_section "2. TEST 1: Run Security Tests"
echo "Command: python test_security.py"
echo ""
python3 test_security.py 2>&1 | head -50
print_result $? "Security tests"

print_section "3. TEST 2: Run Comprehensive Tests"
echo "Command: python test_comprehensive.py"
echo ""
python3 test_comprehensive.py 2>&1 | head -50
print_result $? "Comprehensive tests"

print_section "4. TEST 3: Interactive Demo"
echo "Command: python demo_security.py"
echo ""
echo "This runs an interactive demonstration of all security features."
echo "Press Ctrl+C to skip..."
sleep 3

print_section "5. TEST 4: Enhanced CLI (Single URL)"
echo "Command: python detect_enhanced.py <URL>"
echo ""
TEST_URL="https://google.com"
echo "Testing with: $TEST_URL"
python3 detect_enhanced.py --json "$TEST_URL" 2>&1 | python3 -m json.tool 2>/dev/null || python3 detect_enhanced.py --json "$TEST_URL" 2>&1 | head -30
print_result $? "CLI single URL scan"

print_section "6. TEST 5: Enhanced CLI (Interactive Mode)"
echo "Command: python detect_enhanced.py --interactive"
echo ""
echo "This starts an interactive session where you can scan multiple URLs."
echo "To test manually, run: python detect_enhanced.py --interactive"

print_section "7. TEST 6: API Server Mode"
echo "Command: python 04_inference/api.py"
echo ""
echo "This starts the REST API server on http://localhost:8000"
echo "Test endpoints:"
echo "  • http://localhost:8000/ (API info)"
echo "  • http://localhost:8000/health (Health check)"
echo "  • http://localhost:8000/docs (API documentation - if running)"
echo ""
echo "To test manually:"
echo "  1. Terminal 1: python 04_inference/api.py"
echo "  2. Terminal 2: curl http://localhost:8000/health"

print_section "8. TEST 7: MLflow Model Management"
echo "Command: python 03_training/model_manager.py"
echo ""
echo "This demonstrates MLflow model tracking."
echo "To view MLflow UI: mlflow ui --backend-store-uri ./mlruns"
echo "Then open: http://localhost:5000"

print_section "9. TEST 8: Desktop Application (Tauri)"
echo "Location: gui-tauri/"
echo ""
if [ -f "gui-tauri/src-tauri/target/release/phishing-guard" ]; then
    echo "  ✅ Desktop app built"
    echo "  Run: ./gui-tauri/src-tauri/target/release/phishing-guard"
    echo "  Or install: sudo dpkg -i gui-tauri/src-tauri/target/release/bundle/deb/*.deb"
else
    echo "  ⚠️  Desktop app not built yet"
    echo "  Build: cd gui-tauri && npm install && npm run tauri build"
fi

print_section "10. TEST 9: Browser Extension"
echo "Location: browser-extension/"
echo ""
echo "To test in Chrome/Brave:"
echo "  1. Open: chrome://extensions"
echo "  2. Enable 'Developer mode'"
echo "  3. Click 'Load unpacked'"
echo "  4. Select: browser-extension/ folder"
echo "  5. Visit any website to see link scanning"

print_section "11. TEST 10: Email Scanner"
echo "Command: python email_scanner.py --file <email.eml>"
echo ""
echo "Scans email files for phishing links."
echo "Requires: IMAP configuration in ~/.phishing_guard/config.enc"

print_section "12. MANUAL TESTING CHECKLIST"

cat << 'EOF'
✅ Basic Functionality Tests:
  □ Run: python test_security.py (should show all tests passing)
  □ Run: python test_comprehensive.py (should show 14 test classes)
  □ Run: python detect_enhanced.py https://google.com (should classify as legitimate)
  □ Run: python detect_enhanced.py https://paypa1-secure.tk (should detect as phishing)

✅ API Tests:
  □ Start: python 04_inference/api.py
  □ Check: curl http://localhost:8000/health
  □ Login: curl -X POST http://localhost:8000/auth/login -d '{"username":"test","password":"test"}'
  □ Scan: curl -X POST http://localhost:8000/api/v1/analyze -H "Authorization: Bearer <token>" -d '{"url":"https://example.com"}'

✅ MLflow Tests:
  □ Run: python 03_training/model_manager.py
  □ Check: ls -la mlruns/ (should exist)
  □ View: mlflow ui --backend-store-uri ./mlruns

✅ Desktop App Tests:
  □ Run: ./gui-tauri/src-tauri/target/release/phishing-guard
  □ Try scanning: https://google.com (should be green)
  □ Try scanning: http://192.168.1.1 (should be blocked - SSRF)
  □ Try batch scanning multiple URLs

✅ Browser Extension Tests:
  □ Load extension in Chrome
  □ Visit: https://google.com (links should have green underline)
  □ Visit suspicious site (if available) - should show red/orange

✅ Feature-Specific Tests:
  □ IDN Detection: python -c "from feature_extraction import URLFeatureExtractor; f = URLFeatureExtractor.extract_features('https://раураl.com'); print('Has punycode:', f['has_punycode'])"
  □ TLS Analysis: python -c "from tls_analyzer import extract_tls_features; print(extract_tls_features('https://google.com'))"
  □ Security Validation: python -c "from security_validator import validate_url_for_analysis; print(validate_url_for_analysis('http://127.0.0.1'))"

EOF

print_section "13. QUICK REFERENCE"

cat << 'EOF'
🚀 FASTEST WAY TO TEST:

1. Test Core Detection:
   python detect_enhanced.py https://example.com

2. Run All Tests:
   python test_security.py && python test_comprehensive.py

3. Start API Server:
   python 04_inference/api.py

4. Interactive Mode:
   python detect_enhanced.py --interactive

5. View MLflow:
   mlflow ui --backend-store-uri ./mlruns

6. Run Desktop App:
   ./gui-tauri/src-tauri/target/release/phishing-guard

🎯 EXPECTED RESULTS:

✅ Legitimate URLs (google.com, github.com):
   - Classification: legitimate
   - Risk Score: < 30
   - Color: Green

⚠️  Suspicious URLs (new domains, http sites):
   - Classification: phishing or warning
   - Risk Score: 30-70
   - Color: Orange

❌ Phishing URLs (paypa1.com, bit.ly/xxx):
   - Classification: phishing
   - Risk Score: > 70
   - Color: Red

🔒 Security Features:
   - SSRF attempts (localhost, 192.168.x.x) should be blocked
   - Invalid URLs should return 400 error
   - API should require authentication

EOF

print_section "14. TROUBLESHOOTING"

cat << 'EOF'
❌ "Module not found":
   → pip install -r requirements.txt

❌ "Model not found":
   → python 03_training/train_ml.py

❌ "Permission denied":
   → chmod +x gui-tauri/src-tauri/target/release/phishing-guard

❌ "Port already in use":
   → kill $(lsof -t -i:8000)  # Kill process on port 8000

❌ "MLflow not found":
   → pip install mlflow

❌ "Tauri not built":
   → cd gui-tauri && npm install && npm run tauri build

EOF

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                  TESTING GUIDE COMPLETE                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "🎓 For IEEE Presentation:"
echo "   1. Run: python demo_security.py (shows all features)"
echo "   2. Run: python detect_enhanced.py --interactive (live demo)"
echo "   3. Show: Browser extension highlighting links"
echo "   4. Show: MLflow UI with model versions"
echo ""
echo "🚀 Quick Start:"
echo "   python detect_enhanced.py https://google.com"
echo ""
