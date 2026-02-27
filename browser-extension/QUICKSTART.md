# Quick Start Guide

Get Phishing Guard up and running in 2 minutes!

## 🚀 Install (Choose One Method)

### Option 1: Chrome Web Store (Easiest)
[Click here to install from Chrome Web Store](https://chrome.google.com/webstore/detail/YOUR_EXTENSION_ID)

### Option 2: Manual Install
```bash
# 1. Download the extension
cd browser-extension

# 2. Build the distribution
npm run build:dist

# 3. Install in Chrome
# - Open chrome://extensions/
# - Enable Developer Mode
# - Click "Load unpacked"
# - Select the 'dist' folder
```

## 📦 Build Commands

```bash
# Build distribution files
npm run build

# Create ZIP for distribution
npm run build:zip

# Full build with ZIP
npm run build:dist

# Clean build files
npm run clean

# Run tests
npm test

# Bump version (patch/minor/major)
npm run version -- patch
```

## 🎯 Usage

1. **Install the extension**
2. **Browse normally** - Links are automatically highlighted
3. **Click the shield icon** to see statistics and scan URLs manually
4. **Stay safe!** 🛡️

## 🎨 Link Color Guide

| Color | Meaning | Action |
|-------|---------|--------|
| 🟢 Green | Safe | Click freely |
| 🟠 Orange | Suspicious | Be cautious |
| 🔴 Red | Phishing | DO NOT CLICK |

## 🛠️ Development

```bash
# Clone repository
git clone https://github.com/yourusername/phishing-detection-project.git
cd phishing-detection-project/browser-extension

# Make changes to files
# ...

# Test changes
npm test

# Build
npm run build:dist

# Reload extension in chrome://extensions/
```

## 📁 Project Structure

```
browser-extension/
├── manifest.json          # Extension configuration
├── background.js          # Background service worker
├── content.js            # Content script (runs on pages)
├── popup.html/js/css     # Extension popup UI
├── styles.css            # Link highlighting styles
├── images/               # Extension icons
├── scripts/              # Build and utility scripts
│   ├── build.js         # Build distribution
│   ├── build.sh         # Bash build script
│   ├── version.js       # Version management
│   ├── release.js       # GitHub releases
│   ├── test.js          # Tests
│   └── clean.js         # Clean build files
├── store-assets/         # Chrome Web Store assets
│   ├── screenshots/      # Store screenshots
│   └── promotional/      # Promotional images
├── PRIVACY_POLICY.md     # Privacy policy
├── STORE_LISTING.md      # Store listing text
├── INSTALL.md            # Installation guide
├── CHANGELOG.md          # Version history
└── package.json          # NPM configuration
```

## 🚀 Publishing

### To Chrome Web Store
1. Build distribution: `npm run build:dist`
2. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole/)
3. Click "New Item"
4. Upload `dist/phishing-guard-vX.X.X.zip`
5. Fill in store listing details
6. Submit for review

### To GitHub Releases
```bash
# Tag the release
git tag v2.0.0
git push origin v2.0.0

# Create release with assets
npm run release
```

## 🔗 Links

- [Full Documentation](README.md)
- [Installation Guide](INSTALL.md)
- [Chrome Web Store](https://chrome.google.com/webstore/detail/YOUR_EXTENSION_ID)
- [Privacy Policy](PRIVACY_POLICY.md)
- [Changelog](CHANGELOG.md)

## 💡 Tips

- **Refresh page** after installing to see link highlighting
- **Click extension icon** for manual URL scanning
- **Disable on trusted sites** if needed via popup
- **Check console** (F12) for debugging

## 🆘 Support

- Open an [Issue](../../issues)
- Check [FAQ](FAQ.md) (if available)
- Read [Troubleshooting](INSTALL.md#-troubleshooting)

---

**Ready to browse safely?** Install now! 🛡️
