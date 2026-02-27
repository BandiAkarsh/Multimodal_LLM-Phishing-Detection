# Phishing Guard - Browser Extension (Standalone)

**⚡ Works Without Any Installation!** Just add the extension to your browser and it works immediately.

## What's New - Standalone Mode

This extension now works **completely standalone** - no need to install Python, run servers, or configure anything!

### How It Works
- **JavaScript-based detection** runs entirely in your browser
- **Real-time scanning** of all links on web pages
- **Instant protection** - no setup required
- **Privacy-first** - your data never leaves your computer

---

## 🚀 Installation (30 seconds)

### Chrome / Brave / Edge

1. **Download** this `browser-extension` folder
2. Open your browser and go to: `chrome://extensions/`
3. **Enable "Developer mode"** (toggle in top right)
4. Click **"Load unpacked"**
5. Select the `browser-extension` folder
6. Done! 🎉

### Firefox

1. Open Firefox and go to: `about:debugging`
2. Click **"This Firefox"**
3. Click **"Load Temporary Add-on"**
4. Select `manifest.json` from the extension folder

---

## ✅ Verification - Test It Now!

Open this test page in your browser after installing:
```
file:///path/to/browser-extension/test-page.html
```

Or visit any website with links - you'll see them highlighted automatically!

---

## 🎨 What You'll See

### Automatic Link Highlighting
Every link on every webpage gets color-coded:

| Color | Meaning | Safe? |
|-------|---------|-------|
| 🟢 **Green border** | Safe/Legitimate | ✅ Click freely |
| 🟠 **Orange border** | Suspicious | ⚠️ Be careful |
| 🔴 **Red border** | Phishing detected | 🚫 Don't click! |
| 🔵 **Blue border** | Scanning... | ⏳ Wait a moment |

### Extension Popup
Click the extension icon to see:
- **Quick Scan**: Test any URL manually
- **Current Page Stats**: Links scanned and threats found
- **Protection Toggle**: Enable/disable scanning

---

## 🧪 Test URLs

Try these URLs in the Quick Scan feature:

**Safe URLs:**
- `https://google.com` → Should show GREEN
- `https://github.com` → Should show GREEN
- `https://microsoft.com` → Should show GREEN

**Phishing URLs:**
- `http://paypa1.com` → Should show RED (PayPal fake)
- `http://amaz0n-security.com` → Should show RED (Amazon fake)
- `http://g00gle-login.com` → Should show RED (Google fake)

---

## 🔧 Features

### Automatic Protection
- ✅ Scans ALL links on every webpage automatically
- ✅ Highlights dangerous links in real-time
- ✅ Detects typosquatting (fake brands)
- ✅ Identifies suspicious patterns
- ✅ Shows desktop notifications for threats

### Manual Scanning
- ✅ Quick Scan any URL
- ✅ Get instant risk assessment
- ✅ View confidence scores
- ✅ See detailed threat indicators

### Privacy & Security
- ✅ **100% offline** - works without internet
- ✅ **No data collection** - everything stays local
- ✅ **No API calls** - runs in your browser only
- ✅ **Open source** - transparent detection logic

---

## 🛠️ How It Works (Technical)

The extension uses **heuristic analysis** to detect phishing:

1. **Typosquatting Detection**: Identifies fake brands (paypa1.com, amaz0n.com)
2. **URL Analysis**: Checks for suspicious patterns:
   - Missing HTTPS
   - IP addresses instead of domains
   - Suspicious TLDs (.tk, .ml, .xyz)
   - Suspicious keywords (login, verify, secure)
   - URL length and structure
3. **Risk Scoring**: Calculates 0-100% risk score
4. **Classification**: Labels as Safe, Suspicious, or Phishing

---

## 📊 Comparison: Old vs New

| Feature | Old Version | New Standalone |
|---------|-------------|----------------|
| Setup Time | 10+ minutes | 30 seconds |
| Requires Python | ✅ Yes | ❌ No |
| Requires API Server | ✅ Yes | ❌ No |
| Requires Dependencies | ✅ Yes | ❌ No |
| Works Offline | ❌ No | ✅ Yes |
| Installation Complexity | Hard | Easy |
| User-Friendly | ❌ No | ✅ Yes |

---

## 🚧 Limitations of Standalone Mode

The standalone version uses **rule-based detection** which is fast and effective for:
- ✅ Typosquatting attacks
- ✅ Suspicious URL patterns
- ✅ Known phishing indicators
- ✅ Basic ML model features

For **advanced ML-based detection** (optional):
- Install the Python backend (see main project)
- Extension can connect to local API for enhanced accuracy
- This is optional - standalone mode works great on its own!

---

## 🔄 Optional: Enhanced Mode (Advanced Users)

If you want ML-powered detection, you can:

1. Install the full project (see main README)
2. Run the API: `python 04_inference/api.py`
3. Extension will automatically use it if available

**But this is completely optional!** The standalone version works great for everyday protection.

---

## 🐛 Troubleshooting

### Extension not working?
1. Check if it's enabled: `chrome://extensions/`
2. Refresh the webpage
3. Check browser console (F12 → Console) for errors

### Links not highlighted?
1. Click extension icon → Ensure "Enable Protection" is ON
2. Refresh the page
3. Wait 2-3 seconds for scanning to complete

### False positives?
- Some legitimate sites might be flagged (rare)
- You can disable protection on trusted sites
- Report false positives in GitHub issues

---

## 📱 Browser Compatibility

- ✅ Chrome 88+
- ✅ Brave 1.20+
- ✅ Edge 88+
- ✅ Opera 74+
- ⚠️ Firefox (Manifest V2 version needed)

---

## 🤝 Contributing

This is part of the Phishing Detection Project. See main repository for:
- Source code
- Full documentation
- Issue tracker
- Contributing guidelines

---

**Enjoy safe browsing! 🛡️**

*Version 2.0 - Standalone Edition*
