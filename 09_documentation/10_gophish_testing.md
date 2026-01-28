# Gophish Testing Guide

This document provides step-by-step instructions for testing the phishing detection system against Gophish, a popular open-source phishing toolkit.

## Overview

Gophish is used by security professionals to test phishing awareness. Our system should detect Gophish campaigns with high confidence due to its distinctive signatures.

### Gophish Signatures We Detect

| Signature | Description | Detection Weight |
|-----------|-------------|------------------|
| `?rid=` URL parameter | Recipient tracking ID | High (0.5) |
| `X-Gophish-Contact` header | Gophish identification header | High (0.6) |
| Standard form structure | `username`/`password` input names | Medium (0.4) |
| Minimal page content | Single form, few links | Medium (0.3) |

## Prerequisites

### System Requirements (LMDE 7 / Debian-based)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y wget curl unzip golang-go

# Create test directory
mkdir -p ~/gophish-test
cd ~/gophish-test
```

### Download Gophish

```bash
# Download latest release
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip

# Extract
unzip gophish-v0.12.1-linux-64bit.zip

# Make executable
chmod +x gophish

# View default config
cat config.json
```

## Setting Up Gophish

### 1. Configure Gophish

Edit `config.json`:

```json
{
    "admin_server": {
        "listen_url": "127.0.0.1:3333",
        "use_tls": false,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:8080",
        "use_tls": false,
        "cert_path": "example.crt",
        "key_path": "example.key"
    },
    "db_name": "sqlite3",
    "db_path": "gophish.db",
    "migrations_prefix": "db/db_",
    "contact_address": ""
}
```

### 2. Start Gophish

```bash
# Start Gophish (note the admin password printed on first run)
./gophish
```

The admin password will be displayed:
```
Please login with the username admin and the password XXXXXXXXXX
```

### 3. Access Admin Panel

Open browser: `http://localhost:3333`
- Username: `admin`
- Password: (from console output)

## Creating Test Campaigns

### Step 1: Create Sending Profile

1. Navigate to "Sending Profiles"
2. Click "New Profile"
3. Configure:
   - Name: `Test SMTP`
   - From: `security@test-company.com`
   - Host: `localhost:25` (or your SMTP server)

### Step 2: Create Landing Page

1. Navigate to "Landing Pages"
2. Click "New Page"
3. Use this template:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Account Verification Required</title>
</head>
<body>
    <h1>Verify Your Account</h1>
    <p>Dear User, please verify your account details below.</p>
    <form method="post" action="">
        <input type="text" name="username" placeholder="Username"><br><br>
        <input type="password" name="password" placeholder="Password"><br><br>
        <button type="submit">Verify Account</button>
    </form>
</body>
</html>
```

4. Check "Capture Submitted Data"
5. Check "Capture Passwords"

### Step 3: Create Email Template

1. Navigate to "Email Templates"
2. Click "New Template"
3. Use this template:

```html
Subject: Urgent: Account Security Verification Required

<html>
<body>
<p>Dear {{.FirstName}},</p>

<p>We have detected unusual activity on your account. Please verify your identity immediately to prevent account suspension.</p>

<p><a href="{{.URL}}">Click here to verify your account</a></p>

<p>If you do not verify within 24 hours, your account will be permanently locked.</p>

<p>Best regards,<br>
Security Team</p>
</body>
</html>
```

### Step 4: Create User Group

1. Navigate to "Users & Groups"
2. Click "New Group"
3. Add test email addresses

### Step 5: Launch Campaign

1. Navigate to "Campaigns"
2. Click "New Campaign"
3. Fill in:
   - Name: `Test Detection Campaign`
   - Email Template: (select created template)
   - Landing Page: (select created page)
   - URL: `http://YOUR_IP:8080` (Gophish phishing server)
   - Sending Profile: (select created profile)
   - Groups: (select created group)
4. Click "Launch Campaign"

## Testing Detection

### Test 1: Direct URL Analysis

```bash
# Navigate to main project
cd ~/phishing_detection_project

# Test Gophish landing page URL
python detect.py "http://localhost:8080/?rid=abc123def"
```

**Expected Output:**
```
Classification: PHISHING_KIT
Confidence: 90%+
Toolkit: Gophish
Signatures Found:
  - URL parameter: ?rid=
  - Standard Gophish form structure
```

### Test 2: API Analysis

```bash
# Start API server
cd 04_inference
uvicorn api:app --host 0.0.0.0 --port 8000 &

# Test via curl
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://localhost:8080/?rid=test123"}'
```

**Expected Response:**
```json
{
  "url": "http://localhost:8080/?rid=test123",
  "classification": "phishing_kit",
  "confidence": 0.92,
  "risk_score": 95,
  "explanation": "PHISHING KIT DETECTED: Gophish. Found signatures: URL parameter: ?rid=, Standard Gophish form structure",
  "recommended_action": "block",
  "toolkit_signatures": {
    "detected": true,
    "toolkit_name": "Gophish",
    "confidence": 0.92,
    "signatures_found": ["URL parameter: ?rid="]
  }
}
```

### Test 3: Email Scanning

```bash
# Create test email file
cat > test_gophish_email.eml << 'EOF'
From: security@fake-company.com
To: target@example.com
Subject: Urgent: Verify Your Account
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html>
<body>
<p>Dear User,</p>
<p>Your account needs verification.</p>
<p><a href="http://localhost:8080/?rid=abc123">Click here to verify</a></p>
</body>
</html>
EOF

# Scan the email
python scan_email.py test_gophish_email.eml
```

### Test 4: Thunderbird Add-on

1. Install the Phishing Guard add-on in Thunderbird
2. Configure backend URL: `http://localhost:8000`
3. Send the Gophish phishing email to your test account
4. Open the email in Thunderbird
5. Verify the warning banner appears

## Detection Verification Checklist

| Test Case | Expected Result | Status |
|-----------|-----------------|--------|
| URL with `?rid=` parameter | PHISHING_KIT | |
| Landing page with username/password form | PHISHING_KIT | |
| Email with Gophish tracking link | PHISHING_KIT | |
| Modified Gophish (no rid param) | PHISHING or AI_GENERATED | |
| Legitimate URL (google.com) | LEGITIMATE | |

## Troubleshooting

### Gophish Won't Start

```bash
# Check if port is in use
sudo lsof -i :3333
sudo lsof -i :8080

# Kill conflicting processes
sudo kill -9 <PID>
```

### Detection Not Working

```bash
# Check scraper can reach page
cd ~/phishing_detection_project
python -c "
import asyncio
from 05_utils.web_scraper import WebScraper

async def test():
    s = WebScraper()
    result = await s.scrape_url('http://localhost:8080/?rid=test')
    print('Scraped:', result['success'])
    print('Toolkit:', result.get('toolkit_signatures'))
    await s.close()

asyncio.run(test())
"
```

### API Not Responding

```bash
# Check if API is running
curl http://localhost:8000/health

# Check logs
cd 04_inference
uvicorn api:app --reload --log-level debug
```

## Advanced Testing

### Testing Other Toolkits

The system also detects:

| Toolkit | Key Signatures |
|---------|---------------|
| HiddenEye | `/login.php`, meta tags |
| King Phisher | `<!-- KingPhisher -->` comments |
| SocialFish | `/social.php` endpoints |
| Evilginx2 | Deep subdomain chains |

### Creating Custom Test Pages

```html
<!-- Test HiddenEye-style page -->
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <meta content="hiddeneye" name="generator">
</head>
<body>
    <div class="login-container">
        <form action="/login.php" method="post">
            <input name="login" type="text">
            <input name="passwd" type="password">
            <button>Login</button>
        </form>
    </div>
</body>
</html>
```

## Reporting Results

After testing, document results:

```markdown
## Test Results - [Date]

### Environment
- OS: LMDE 7
- Gophish: v0.12.1
- Phishing Detection: v1.0.0

### Results
| Test | Classification | Confidence | Notes |
|------|---------------|------------|-------|
| Basic Gophish | PHISHING_KIT | 92% | Detected via ?rid= |
| Custom Landing | PHISHING_KIT | 85% | Detected via form structure |
| Email Link | PHISHING_KIT | 90% | Full detection |

### Issues Found
- None / [List any issues]
```

## Security Notes

- Only test on systems you own or have explicit permission to test
- Never use real email addresses in phishing tests without consent
- Keep Gophish campaigns internal (don't expose to internet)
- Delete test data after testing

## References

- [Gophish Documentation](https://docs.getgophish.com/)
- [Gophish GitHub](https://github.com/gophish/gophish)
- [Phishing Detection Project](../README.md)
