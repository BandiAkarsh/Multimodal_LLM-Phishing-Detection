# GUI Application Guide

## Overview

The GUI application (`gui.py`) provides a beautiful, user-friendly interface for detecting phishing URLs. It's built with CustomTkinter, a modern Tkinter wrapper with dark mode support.

## Installation

```bash
# Install required package
pip install customtkinter Pillow

# Run the GUI
python gui.py
```

---

## Interface Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                         HEADER                                   │
│  🔒 Phishing URL Detector          [Connectivity Status]        │
├─────────────────────────────────────────────────────────────────┤
│                       INPUT SECTION                              │
│  ┌────────────────────────────────────────────────┐ ┌─────────┐ │
│  │ Enter URL...                                   │ │  SCAN   │ │
│  └────────────────────────────────────────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                      RESULTS SECTION                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  [Results Tab]  [History Tab]                              │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │                                                           │  │
│  │   STATUS CARD                                             │  │
│  │   ┌─────────────────────────────────────────────────────┐ │  │
│  │   │  ⚠️    PHISHING DETECTED                            │ │  │
│  │   │        Recommended: BLOCK this URL                  │ │  │
│  │   └─────────────────────────────────────────────────────┘ │  │
│  │                                                           │  │
│  │   METRICS                                                 │  │
│  │   ┌───────────┐ ┌───────────┐ ┌────────────────────────┐ │  │
│  │   │RISK SCORE │ │CONFIDENCE │ │   ANALYSIS MODE       │ │  │
│  │   │    85     │ │   95.0%   │ │     🌐 ONLINE         │ │  │
│  │   │[████████░]│ │           │ │                       │ │  │
│  │   └───────────┘ └───────────┘ └────────────────────────┘ │  │
│  │                                                           │  │
│  │   EXPLANATION                                             │  │
│  │   ┌─────────────────────────────────────────────────────┐ │  │
│  │   │ URL: https://paypa1.com                             │ │  │
│  │   │ Classification: PHISHING                            │ │  │
│  │   │                                                     │ │  │
│  │   │ 📸 Scraped Content:                                 │ │  │
│  │   │   - Title: PayPal Login                             │ │  │
│  │   │   - HTML Size: 45678 bytes                          │ │  │
│  │   │                                                     │ │  │
│  │   │ ⚠️ Typosquatting Detected:                          │ │  │
│  │   │   - Method: homoglyph_substitution                  │ │  │
│  │   │   - Impersonated Brand: PAYPAL                      │ │  │
│  │   └─────────────────────────────────────────────────────┘ │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                         FOOTER                                   │
│  [🔄 Refresh Connection]              v2.0 | ML: Random Forest  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Using the GUI

### Step 1: Launch the Application

```bash
python gui.py
```

The application will:
1. Display the loading screen
2. Check internet connectivity
3. Load the ML model in background
4. Show "Ready" when loaded

### Step 2: Check Connectivity Status

Look at the top-right corner:
- **🌐 Online**: Full analysis with web scraping
- **📴 Offline**: Static analysis only

### Step 3: Enter a URL

1. Click on the URL input field
2. Type or paste a URL (e.g., `https://paypa1.com`)
3. Press Enter or click "SCAN"

### Step 4: View Results

The results section shows:
- **Status Card**: Large icon showing PHISHING or LEGITIMATE
- **Risk Score**: 0-100 with color-coded bar
- **Confidence**: How sure the system is (0-100%)
- **Analysis Mode**: Online, Offline, or Whitelisted
- **Explanation**: Detailed analysis text

### Step 5: Check History

Click the "History" tab to see previous scans.

---

## Color Coding

### Status Card Colors

| Status | Background | Icon |
|--------|------------|------|
| Phishing | Dark Red | ⚠️ |
| Legitimate | Dark Green | ✅ |
| Error | Dark Orange | ❌ |
| Loading | Dark Blue | ⏳ |

### Risk Score Colors

| Range | Color | Meaning |
|-------|-------|---------|
| 0-39 | Green | Low risk |
| 40-69 | Orange | Medium risk |
| 70-100 | Red | High risk |

### Action Recommendations

| Action | Color | When |
|--------|-------|------|
| ALLOW | Green | Safe URL |
| WARN | Yellow | Suspicious URL |
| BLOCK | Red | Dangerous URL |

---

## Features

### 1. Internet-Aware Detection

The GUI automatically:
- Checks internet on startup
- Shows current mode (Online/Offline)
- Uses web scraping when online
- Falls back to static analysis when offline

### 2. Real-time Progress

When scanning:
- Button changes to "⏳ Scanning..."
- Progress bar appears
- Results update when complete

### 3. Detailed Explanation

The explanation box shows:
- Full URL analyzed
- Classification result
- Risk factors found
- Scraped content (if online)
- Typosquatting details (if detected)

### 4. Scan History

The History tab keeps track of:
- Previous URLs scanned
- Their classification
- Risk scores
- Quick access to rescan

### 5. Refresh Connection

Click "🔄 Refresh Connection" to:
- Force check internet status
- Switch modes if connectivity changed

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Enter | Scan URL (when in input field) |
| Ctrl+V | Paste URL |
| Ctrl+C | Copy selected text |

---

## Customization

### Change Theme

The GUI uses dark mode by default. To change:

```python
# In gui.py, line 31
ctk.set_appearance_mode("dark")  # Options: "dark", "light", "system"
```

### Change Window Size

```python
# In gui.py, __init__ method
self.geometry("900x700")  # Width x Height
self.minsize(800, 600)    # Minimum size
```

### Change Color Theme

```python
# In gui.py, line 32
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"
```

---

## Troubleshooting

### GUI won't start

```bash
# Check if customtkinter is installed
pip install customtkinter

# If using Linux, install Tkinter
sudo apt-get install python3-tk
```

### Model loading fails

```bash
# Ensure models exist
ls 02_models/

# Should show:
# phishing_classifier.joblib
# feature_scaler.joblib
# feature_columns.joblib
```

### Slow performance

- Ensure you have at least 4GB RAM
- Close other heavy applications
- MLLM is not loaded by default (saves memory)

### "Offline" when internet is available

- Click "🔄 Refresh Connection"
- Check firewall settings
- Verify DNS resolution

---

## Technical Details

### Dependencies

- `customtkinter>=5.2.0` - Modern Tkinter wrapper
- `Pillow>=10.0.0` - Image handling
- `asyncio` - Async operations
- `threading` - Background tasks

### Architecture

```
GUI (Main Thread)
     │
     ├── UI Event Loop (Tkinter)
     │
     └── Background Thread (Scanning)
              │
              └── AsyncIO Event Loop
                       │
                       └── PhishingDetectionService
```

### Thread Safety

- Service operations run in background thread
- Results passed to main thread via `self.after()`
- UI updates only on main thread

---

*This documentation explains the GUI application for beginners.*
