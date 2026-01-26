# Entry Points Documentation

## Overview

This document explains the main entry point scripts that users interact with directly. These are the "front doors" to the phishing detection system.

## Entry Point Files

| File | Purpose | Interface |
|------|---------|-----------|
| `detect.py` | Main CLI tool | Command Line |
| `gui.py` | Desktop application | GUI Window |
| `scan_email.py` | Scan .eml files | Command Line |
| `imap_scanner.py` | Real-time inbox monitor | Command Line |

---

## 1. `detect.py` - Main CLI Tool

The primary command-line interface for URL scanning.

### Usage

```bash
# Interactive mode
python detect.py

# Single URL
python detect.py https://example.com

# Batch mode
python detect.py --batch urls.txt

# Force offline mode
python detect.py --offline

# Disable scraping even when online
python detect.py --no-scrape https://example.com
```

### How It Works

```python
async def main():
    # 1. Check internet connectivity
    if args.offline:
        is_online = False
    else:
        is_online = check_internet_connection()
    
    # 2. Display banner with status
    print_banner(is_online)
    
    # 3. Load service
    service = PhishingDetectionService(load_ml_model=True)
    
    # 4. Analyze URL(s)
    if args.batch:
        await check_batch(service, args.batch, is_online)
    elif args.url:
        await check_single_url(service, args.url, is_online)
    else:
        await interactive_mode(service, is_online)
```

### Key Features

1. **Internet-Aware**: Shows [ONLINE] or [OFFLINE] status
2. **Color-Coded Output**: Red for phishing, green for safe
3. **Detailed Analysis**: Shows risk score, confidence, explanation
4. **Batch Processing**: Scan multiple URLs from file

### Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║   🔒 PHISHING URL DETECTOR                                    ║
║   Mode: 🌐 ONLINE - Full Analysis                             ║
╚═══════════════════════════════════════════════════════════════╝

=================================================================
URL: https://paypa1.com
Analysis Mode: [ONLINE]
=================================================================

⚠️  PHISHING DETECTED

Confidence:  95.0%
Risk Score:  85/100
Action:      BLOCK

Analysis:
Analysis based on scraped content: Brand impersonation detected: paypal

[INFO] Successfully scraped webpage content.
   Title: PayPal Login
   Size: 45678 bytes
   Links: 15

[!] BRAND IMPERSONATION DETECTED:
   Impersonated Brand: PAYPAL
   Method: homoglyph_substitution
   Similarity: 95.0%
```

---

## 2. `gui.py` - Desktop GUI Application

Beautiful graphical interface built with CustomTkinter.

### Usage

```bash
python gui.py
```

### Features

1. **Modern Dark Theme**: Easy on the eyes
2. **Real-time Connectivity Status**: Shows online/offline
3. **Visual Risk Meter**: Color-coded progress bar
4. **Detailed Analysis Panel**: Expandable explanation
5. **Scan History**: Previous scans saved

### GUI Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ 🔒 Phishing URL Detector                    [🌐 Online]        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Enter URL:  https://example.com              [🔍 SCAN]  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  ⚠️  PHISHING DETECTED              Risk: [████████░░] │  │
│  │                                      85/100             │  │
│  │  Confidence: 95.0%    Mode: ONLINE    Action: BLOCK    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Analysis Details:                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ URL: https://paypa1.com                                  │  │
│  │ Brand impersonation detected (paypal)                   │  │
│  │ Homoglyph substitution: '1' instead of 'l'              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  [Results] [History]                    [🔄 Refresh Connection] │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

```python
class PhishingDetectorGUI(ctk.CTk):
    def __init__(self):
        # Create window
        self.title("Phishing URL Detector")
        self.geometry("900x700")
        
        # Build UI components
        self._create_header()
        self._create_input_section()
        self._create_results_section()
        
        # Load service in background
        self._load_service_async()
    
    def _scan_url(self):
        # Get URL from input
        url = self.url_entry.get()
        
        # Run analysis in background thread
        thread = threading.Thread(target=self._run_scan)
        thread.start()
    
    def _display_result(self, result):
        # Update UI with results
        if result['classification'] == 'phishing':
            self.status_icon.configure(text="⚠️")
            self.status_text.configure(text="PHISHING DETECTED")
        else:
            self.status_icon.configure(text="✅")
            self.status_text.configure(text="LEGITIMATE")
```

---

## 3. `scan_email.py` - Email File Scanner

Scans `.eml` files for phishing URLs.

### Usage

```bash
# Scan an email file
python scan_email.py sample_phishing.eml

# Force offline mode
python scan_email.py --offline suspicious_email.eml
```

### How It Works

```python
def extract_urls_from_eml(file_path):
    # Parse email
    with open(file_path, 'rb') as fp:
        msg = BytesParser().parse(fp)
    
    # Extract URLs from HTML links
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            soup = BeautifulSoup(part.get_content(), 'html.parser')
            links = [a.get('href') for a in soup.find_all('a')]
    
    return links

async def scan_email_async(file_path):
    # Extract URLs
    urls = extract_urls_from_eml(file_path)
    
    # Check each URL
    for url in urls:
        result = await service.analyze_url_async(url)
        
        if result['classification'] == 'phishing':
            print(f"[PHISHING] {url}")
```

### Example Output

```
══════════════════════════════════════════════════════════
📧 EMAIL SECURITY SCANNER
══════════════════════════════════════════════════════════
Subject: Your account has been suspended
From: security@paypa1.com
To: victim@example.com

Found 3 links. Analyzing...
----------------------------------------------------------
[PHISHING] [ONL] https://paypa1.com/verify
   Risk: 85/100 | Brand impersonation: paypal
[SAFE]     [ONL] https://google.com
[PHISHING] [ONL] https://amaz0n-deals.xyz
   Risk: 75/100 | Suspicious domain structure

══════════════════════════════════════════════════════════
⚠️  DANGER: This email contains 2 PHISHING link(s)!
DO NOT CLICK any links in this email.
══════════════════════════════════════════════════════════
```

---

## 4. `imap_scanner.py` - Real-time Inbox Monitor

Monitors your email inbox for phishing in real-time.

### Usage

```bash
# Start monitoring
python imap_scanner.py

# Reset saved credentials
python imap_scanner.py --reset

# Force offline mode
python imap_scanner.py --offline
```

### First-Time Setup

```
--- FIRST TIME SETUP ---
To use this, you need an 'App Password' from Google.
Go to: Google Account → Security → 2-Step Verification → App passwords

IMAP Server (default: imap.gmail.com): 
Email: your.email@gmail.com
App Password: ****************
Save credentials for future? (y/n): y
```

### How It Works

```python
async def monitor_inbox_async():
    # Connect to IMAP
    mail = imaplib.IMAP4_SSL(server)
    mail.login(email, password)
    mail.select("inbox")
    
    while True:
        # Check for new emails
        status, messages = mail.search(None, "ALL")
        email_ids = messages[0].split()
        
        if new_emails:
            for email_id in new_email_ids:
                # Fetch email
                msg = mail.fetch(email_id, "(RFC822)")
                
                # Extract URLs
                urls = extract_urls_from_email(msg)
                
                # Analyze each URL
                for url in urls:
                    result = await service.analyze_url_async(url)
                    
                    if result['classification'] == 'phishing':
                        print(f"⚠️ DANGER: Phishing detected!")
        
        # Wait 5 seconds before next check
        await asyncio.sleep(5)
```

### Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║   📧 REAL-TIME EMAIL PHISHING SCANNER                         ║
╚═══════════════════════════════════════════════════════════════╝

Loaded credentials for user@gmail.com
Checking internet connection... Online - Full analysis enabled
Loading detection engine...
Inbox synced (1523 emails). Mode: ONLINE
Monitoring for NEW emails...

══════════════════════════════════════════════════════
🔔 New email detected! Scanning...

Subject: Urgent: Verify your account
From: security@paypa1-verify.com
Found 2 links. Analyzing... [ONLINE]
  [PHISHING] https://paypa1-verify.com/login
     Risk: 90/100
     Reason: Brand impersonation detected: paypal

⚠️  DANGER: Phishing detected in this email!
DO NOT click any links in this email.
══════════════════════════════════════════════════════
```

---

## Comparison of Entry Points

| Feature | detect.py | gui.py | scan_email.py | imap_scanner.py |
|---------|-----------|--------|---------------|-----------------|
| Interface | CLI | GUI | CLI | CLI |
| Input | URL | URL | .eml file | IMAP inbox |
| Real-time | No | No | No | Yes |
| Batch | Yes | No | Yes | Yes |
| Offline Mode | Yes | Yes | Yes | Yes |
| Connectivity Check | Yes | Yes | Yes | Periodic |

---

*This documentation explains the entry point files for beginners.*
