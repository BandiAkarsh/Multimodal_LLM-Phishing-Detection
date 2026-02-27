# Phishing Guard Extension - File Index

Complete guide to all files in the Chrome Web Store ready package.

## 📁 Root Files (Extension Core)

### Extension Files (Required)
| File | Purpose | Required for Web Store |
|------|---------|------------------------|
| `manifest.json` | Extension configuration | ✅ Yes |
| `background.js` | Service worker (background) | ✅ Yes |
| `content.js` | Content script (page scanner) | ✅ Yes |
| `popup.html` | Extension popup UI | ✅ Yes |
| `popup.js` | Popup JavaScript | ✅ Yes |
| `popup.css` | Popup styles | ✅ Yes |
| `styles.css` | Link highlighting styles | ✅ Yes |

### Icons (Required)
| File | Size | Purpose | Required |
|------|------|---------|----------|
| `images/icon16.png` | 16x16 | Toolbar icon | ✅ Yes |
| `images/icon48.png` | 48x48 | Extension management | ✅ Yes |
| `images/icon128.png` | 128x128 | Store listing | ✅ Yes |

### Legacy/Extra Files (Optional)
| File | Purpose | Notes |
|------|---------|-------|
| `content-script.js` | Alternative content script | Legacy |
| `detector.js` | Standalone detector | Can be integrated |
| `test-page.html` | Testing page | For development |

---

## 📦 Build System (`scripts/`)

| Script | Purpose | Command |
|--------|---------|---------|
| `build.js` | Main build script (Node.js) | `npm run build` |
| `build.sh` | Alternative bash build | `./scripts/build.sh` |
| `version.js` | Version management | `npm run version -- patch` |
| `release.js` | GitHub release creation | `npm run release` |
| `clean.js` | Clean build artifacts | `npm run clean` |
| `test.js` | Validation tests | `npm test` |
| `lint.js` | Basic linting | `npm run lint` |

### Build System Features

#### build.js / build.sh
- Copies extension files to `dist/`
- Validates manifest.json
- Calculates package size
- Creates distribution ZIP (`phishing-guard-v2.0.0.zip`)
- Generates build-info.json

#### version.js
```bash
npm run version -- patch  # 2.0.0 → 2.0.1
npm run version -- minor  # 2.0.0 → 2.1.0
npm run version -- major  # 2.0.0 → 3.0.0
```

#### release.js
- Creates GitHub releases
- Uploads ZIP assets
- Generates release notes from CHANGELOG

---

## 📚 Documentation Files

### Required for Chrome Web Store

| File | Purpose | Required |
|------|---------|----------|
| `PRIVACY_POLICY.md` | Privacy policy | ✅ Yes |
| `manifest.json` | Contains extension metadata | ✅ Yes |

### Store Listing Materials

| File | Purpose | Use When |
|------|---------|----------|
| `STORE_LISTING.md` | Complete store listing text | Submitting to Web Store |
| `CHANGELOG.md` | Version history | GitHub releases |
| `README.md` | Main documentation | GitHub repo |

### Installation & Usage

| File | Purpose | Audience |
|------|---------|----------|
| `INSTALL.md` | Installation guide | End users |
| `QUICKSTART.md` | Quick reference | Developers |
| `PACKAGE_SUMMARY.md` | Package overview | Maintainers |
| `INDEX.md` | This file | Reference |

### Legacy Documentation

| File | Purpose | Status |
|------|---------|--------|
| `STANDALONE_SUMMARY.md` | Standalone mode summary | Legacy |

---

## 🎨 Store Assets (`store-assets/`)

### Directory Structure
```
store-assets/
├── README.md              # Asset creation guidelines
├── screenshots/           # Screenshots for Web Store (YOU NEED TO CREATE)
│   ├── screenshot-1.png
│   ├── screenshot-2.png
│   ├── screenshot-3.png
│   └── screenshot-4.png
└── promotional/           # Promotional images (OPTIONAL)
    ├── small.png         # 440x280
    ├── large.png         # 920x680
    └── marquee.png       # 1400x560
```

### Screenshot Requirements
- **Format**: PNG or JPEG
- **Size**: 1280x800 (recommended) or 640x400 (minimum)
- **Aspect Ratio**: 16:10 or 4:3
- **Max Size**: 5MB per image
- **Quantity**: 1-10 screenshots

### Recommended Screenshot Content
1. Main popup showing safe scan result
2. Page with color-coded links
3. Popup showing phishing warning
4. Statistics dashboard
5. Quick scan in action

See `store-assets/README.md` for detailed creation guidelines.

---

## 🚀 Configuration Files

### NPM Configuration
```json
// package.json
{
  "name": "phishing-guard",
  "version": "2.0.0",
  "scripts": {
    "build": "node scripts/build.js",
    "build:zip": "node scripts/build.js --zip",
    "build:dist": "node scripts/build.js --dist",
    "clean": "node scripts/clean.js",
    "test": "node scripts/test.js",
    "version": "node scripts/version.js",
    "release": "node scripts/release.js"
  }
}
```

### Manifest Configuration
```json
// manifest.json
{
  "manifest_version": 3,
  "name": "Phishing Guard - Real-Time Phishing Protection",
  "version": "2.0.0",
  "description": "AI-powered phishing detection...",
  "author": "Phishing Guard Team",
  "homepage_url": "https://github.com/yourusername/phishing-detection-project"
}
```

---

## 📋 Quick Reference Commands

### Build Commands
```bash
cd browser-extension

npm run build          # Build to dist/
npm run build:dist     # Build + create ZIP
npm test              # Run validation tests
npm run clean         # Remove dist/, node_modules/
```

### Version Management
```bash
npm run version -- patch  # Bump patch version
npm run version -- minor  # Bump minor version
npm run version -- major  # Bump major version
```

### Release Management
```bash
# Create Git tag
git tag v2.0.0
git push origin v2.0.0

# Create GitHub release with assets
npm run release
```

---

## 🌐 Publishing Workflows

### Chrome Web Store
1. Run: `npm run build:dist`
2. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole/)
3. Click "New Item"
4. Upload: `dist/phishing-guard-v2.0.0.zip`
5. Fill in store listing (copy from `STORE_LISTING.md`)
6. Submit for review (1-3 days)

### GitHub Releases
1. Update `CHANGELOG.md`
2. Bump version: `npm run version -- patch`
3. Commit changes: `git commit -am "Bump version"`
4. Create tag: `git tag v2.0.1`
5. Push: `git push origin v2.0.1`
6. Run: `npm run release`

### Direct ZIP Distribution
1. Run: `npm run build:dist`
2. Distribute: `dist/phishing-guard-v2.0.0.zip`
3. Users install via "Load unpacked" in chrome://extensions

---

## 🎯 File Dependencies

### Build Process
```
build.js → manifest.json, background.js, content.js, popup.*, images/*
       ↓
    dist/ folder
       ↓
    phishing-guard-v2.0.0.zip
```

### Version Management
```
version.js → manifest.json, package.json, build.js, build.sh
```

### Release Process
```
release.js → dist/*.zip, CHANGELOG.md → GitHub Release
```

---

## 🔍 What Each File Does

### Core Extension
- **manifest.json**: Tells Chrome what the extension is, what permissions it needs, and what files to load
- **background.js**: Runs in the background, handles notifications, stores statistics
- **content.js**: Runs on every webpage, scans links, applies highlights
- **popup.html/js/css**: The UI you see when clicking the extension icon
- **styles.css**: Makes links colorful (green/orange/red) based on safety

### Build System
- **build.js**: Automates copying files and creating ZIP for distribution
- **version.js**: Updates version numbers across all files
- **release.js**: Creates GitHub releases with proper formatting
- **test.js**: Validates that all required files exist and are properly formatted

### Documentation
- **PRIVACY_POLICY.md**: Required by Chrome Web Store, explains data handling
- **STORE_LISTING.md**: Text for Chrome Web Store description page
- **INSTALL.md**: Step-by-step guide for users installing the extension
- **CHANGELOG.md**: History of what changed in each version

---

## 📊 File Statistics

### Total Files Created
- **Build Scripts**: 7 files
- **Documentation**: 8 files
- **Store Assets**: 1 file (guidelines) + directories
- **Configuration**: 2 files (package.json, manifest.json updated)

### Total Lines of Code
- Build System: ~1,200 lines (JavaScript/Node.js)
- Documentation: ~2,500 lines (Markdown)
- Configuration: ~100 lines (JSON)

### Total Size
- Build Scripts: ~40 KB
- Documentation: ~120 KB
- Assets: ~1 KB (guidelines only, screenshots to be added)

---

## 🎓 Learning Resources

### For First-Time Publishers
1. Read `PRIVACY_POLICY.md` - understand privacy requirements
2. Read `STORE_LISTING.md` - see what text goes in the store
3. Read `INSTALL.md` - understand user installation flow
4. Read `QUICKSTART.md` - get up and running quickly
5. Read `PACKAGE_SUMMARY.md` - see complete package overview

### For Developers
1. Read `scripts/build.js` - understand build process
2. Read `manifest.json` - understand extension structure
3. Read `QUICKSTART.md` - development workflow

### For Maintainers
1. Read `CHANGELOG.md` - version history
2. Read `INDEX.md` - this file, complete reference
3. Read `PACKAGE_SUMMARY.md` - package overview

---

## 🔗 Important URLs

### Chrome Web Store
- Developer Dashboard: https://chrome.google.com/webstore/devconsole/
- Publishing Guide: https://developer.chrome.com/docs/webstore/publish/
- Image Guidelines: https://developer.chrome.com/docs/webstore/images/

### GitHub
- Releases: https://github.com/yourusername/phishing-detection-project/releases
- Issues: https://github.com/yourusername/phishing-detection-project/issues

### Documentation
- Manifest Format: https://developer.chrome.com/docs/extensions/mv3/intro/
- Chrome APIs: https://developer.chrome.com/docs/extensions/reference/

---

## ✅ Checklists

### Pre-Submission Checklist
- [ ] Update all `yourusername` references
- [ ] Add contact email to PRIVACY_POLICY.md
- [ ] Add support email to STORE_LISTING.md
- [ ] Create 4-5 screenshots (1280x800)
- [ ] Run `npm test` - all tests pass
- [ ] Run `npm run build:dist` - ZIP created successfully
- [ ] Test extension in Chrome (load unpacked)

### Store Submission Checklist
- [ ] Privacy Policy URL provided
- [ ] Store listing description filled
- [ ] Category selected (Privacy & Security)
- [ ] Language selected (English)
- [ ] Icons uploaded (16, 48, 128)
- [ ] Screenshots uploaded
- [ ] Contact email provided
- [ ] Website URL provided

### GitHub Release Checklist
- [ ] Version bumped in all files
- [ ] CHANGELOG.md updated
- [ ] Git tag created
- [ ] GitHub release created
- [ ] ZIP asset attached to release
- [ ] Release notes written

---

**Last Updated:** February 27, 2026  
**Version:** 2.0.0  
**Status:** ✅ Chrome Web Store Ready
