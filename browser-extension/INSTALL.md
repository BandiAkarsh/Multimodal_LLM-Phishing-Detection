# Phishing Guard - Installation Guide

## 🚀 One-Click Installation (Chrome Web Store)

### Method 1: Chrome Web Store (Recommended)

1. **Click the link below to visit the Chrome Web Store:**
   
   [➡️ Install Phishing Guard from Chrome Web Store](https://chrome.google.com/webstore/detail/YOUR_EXTENSION_ID)
   
   *(Replace with your actual Chrome Web Store URL once published)*

2. **Click "Add to Chrome"**

3. **Click "Add Extension"** in the confirmation dialog

4. **Done!** 🎉 The extension is now protecting your browser

---

## 📦 Manual Installation (From GitHub)

### Method 2: Download and Install from GitHub

#### Step 1: Download the Extension

**Option A: Download Latest Release**
1. Go to the [Releases page](../../releases)
2. Download the latest `phishing-guard-vX.X.X.zip` file
3. Extract the ZIP file to a folder

**Option B: Clone the Repository**
```bash
git clone https://github.com/yourusername/phishing-detection-project.git
cd phishing-detection-project/browser-extension
```

#### Step 2: Install in Chrome/Brave/Edge

1. **Open your browser** and type: `chrome://extensions/`

2. **Enable Developer Mode** (toggle in top-right corner)
   
   ![Developer Mode Toggle](docs/images/dev-mode.png)

3. **Click "Load unpacked"** button (top-left)

4. **Select the folder** containing the extension files:
   - If downloaded ZIP: Select the extracted `browser-extension` folder
   - If cloned: Select the `browser-extension` folder

5. **The extension is now installed!** You'll see the Phishing Guard icon in your toolbar

---

## 🔄 Alternative Installation Methods

### Method 3: Drag and Drop (Chrome/Edge)

1. Download the extension ZIP from releases
2. Extract to a folder
3. Open `chrome://extensions/` with Developer Mode enabled
4. **Drag and drop** the extracted folder onto the extensions page
5. The extension installs automatically

### Method 4: Developer Mode (For Testing)

1. Download or clone the repository
2. Open `chrome://extensions/`
3. Enable Developer Mode
4. Click "Load unpacked"
5. Select the `browser-extension` folder
6. Extension loads immediately

---

## 🌍 Browser-Specific Instructions

### Google Chrome
1. Navigate to `chrome://extensions/`
2. Enable Developer Mode
3. Click "Load unpacked"
4. Select extension folder

### Brave Browser
1. Navigate to `brave://extensions/`
2. Enable Developer Mode
3. Click "Load unpacked"
4. Select extension folder

### Microsoft Edge
1. Navigate to `edge://extensions/`
2. Enable Developer Mode (left sidebar)
3. Click "Load unpacked"
4. Select extension folder

### Opera
1. Navigate to `opera://extensions/`
2. Enable Developer Mode
3. Click "Load unpacked"
4. Select extension folder

---

## ✅ Verify Installation

After installation:

1. **Look for the shield icon** in your browser toolbar
2. **Visit any website** with links (e.g., google.com)
3. **Wait 2-3 seconds** for scanning to complete
4. **Links will be highlighted** with colored borders:
   - 🟢 Green = Safe
   - 🟠 Orange = Suspicious
   - 🔴 Red = Phishing

5. **Click the extension icon** to open the popup and see statistics

---

## 🧪 Test the Extension

Try scanning these test URLs in the Quick Scan feature:

**Safe URLs:**
- `https://google.com`
- `https://github.com`
- `https://microsoft.com`

**Phishing URLs (for testing):**
- `http://paypa1.com` → Should show RED
- `http://amaz0n-security.com` → Should show RED
- `http://g00gle-login.com` → Should show RED

**Open the test page included:**
```
file:///path/to/browser-extension/test-page.html
```

---

## 🔄 Updating the Extension

### Automatic Updates (Chrome Web Store)
If installed from Chrome Web Store, updates happen automatically.

### Manual Updates
1. Download the latest version
2. Open `chrome://extensions/`
3. Find Phishing Guard
4. Click the refresh icon (🔄)
5. Or remove and re-install with the new version

---

## 🗑️ Uninstalling

### From Chrome Web Store Installation
1. Right-click the Phishing Guard icon
2. Select "Remove from Chrome"
3. Confirm removal

### From Manual Installation
1. Go to `chrome://extensions/`
2. Find Phishing Guard
3. Click "Remove"
4. Confirm removal

---

## 🐛 Troubleshooting

### Extension Not Working?
1. **Check if enabled:** Go to `chrome://extensions/` and ensure it's toggled ON
2. **Refresh the page:** Press F5 or Ctrl+R
3. **Check console:** Press F12 → Console tab for error messages

### Links Not Highlighting?
1. **Click the extension icon** → Ensure "Enable Protection" is ON
2. **Refresh the page**
3. **Wait 2-3 seconds** for scanning to complete
4. **Check if JavaScript is enabled** in your browser

### "Manifest file is missing or unreadable" Error?
- Make sure you're selecting the folder containing `manifest.json`
- Not the ZIP file itself
- Not the parent folder

### Extension Disabled Automatically?
- Chrome may disable unpacked extensions on restart
- This is normal for security
- Simply go to `chrome://extensions/` and re-enable it

### Performance Issues?
- Extension is very lightweight (< 1MB)
- If experiencing slowness, try disabling on specific sites
- Check if other extensions are conflicting

---

## 📞 Need Help?

- **Open an issue:** [GitHub Issues](../../issues)
- **Read the FAQ:** [FAQ.md](FAQ.md)
- **Check documentation:** [README.md](README.md)

---

## 🎉 You're All Set!

Phishing Guard is now protecting your browser. Browse safely! 🛡️

**Quick Tips:**
- 🟢 Green links are safe to click
- 🟠 Orange links - be cautious
- 🔴 Red links - avoid clicking!
- Click the shield icon anytime for manual scanning
