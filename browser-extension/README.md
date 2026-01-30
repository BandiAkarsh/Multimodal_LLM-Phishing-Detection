# Phishing Guard - Browser Extension

Real-time phishing detection for your browser. Protects against malicious links in web pages.

## Features

- **Automatic Link Scanning**: Scans all links on web pages as you browse
- **Visual Threat Indicators**: Color-coded highlighting of suspicious links
  - 🟢 Green: Safe (legitimate)
  - 🟠 Orange: AI-generated phishing
  - 🔴 Red: Traditional phishing or phishing kit
- **Real-time Notifications**: Alerts when high-risk threats are detected
- **Quick Scan**: Manual URL scanning via popup
- **Statistics**: Track links scanned and threats blocked

## Installation

### Chrome/Chromium/Brave

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `browser-extension` folder
5. Extension is now installed!

### Firefox

1. Open Firefox and navigate to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select any file in the `browser-extension` folder

## Configuration

The extension connects to your local Phishing Guard API (default: http://localhost:8000).

### First-time Setup

1. Ensure the Phishing Guard API is running:
   ```bash
   cd /path/to/phishing_detection_project
   python 04_inference/api.py
   ```

2. Click the extension icon in your browser
3. The extension will automatically authenticate with the API

### Changing API Endpoint

1. Click the extension icon
2. Go to "Advanced Settings"
3. Update the API URL field
4. Click "Save"

## Usage

### Automatic Protection

Once installed and configured, the extension automatically:
- Scans all links on every web page you visit
- Highlights suspicious links with color coding
- Shows notifications for high-risk threats

### Manual Scan

1. Click the extension icon
2. Enter a URL in the "Quick Scan" field
3. Click "Scan"
4. View the detailed analysis result

### View Statistics

The popup shows:
- Total links scanned on current page
- Number of threats detected
- API connection status

## Visual Indicators

Links on web pages are highlighted based on their risk level:

| Color | Meaning | Action |
|-------|---------|--------|
| 🟢 Green underline | Legitimate | Safe to click |
| 🟠 Orange dashed border | AI-generated phishing | Use caution |
| 🔴 Red solid border | Phishing / Phishing kit | Do not click |
| 🔵 Blue dotted underline | Scanning | Wait for result |

## Privacy & Security

- No browsing history leaves your computer
- All scanning happens via your local API
- No data sent to third parties
- Credentials stored securely in browser storage

## Troubleshooting

### "API Not Connected"

1. Check if the Phishing Guard API is running:
   ```bash
   curl http://localhost:8000/health
   ```

2. Verify the API URL in extension settings

3. Check browser console for errors (F12 → Console)

### Links Not Being Highlighted

1. Ensure "Enable Protection" toggle is ON
2. Refresh the page
3. Check if site is in trusted domains list

### Authentication Errors

1. Clear extension data: chrome://extensions/ → Phishing Guard → Clear data
2. Reload the extension
3. Re-authenticate with the API

## Development

### File Structure

```
browser-extension/
├── manifest.json          # Extension manifest (v3)
├── background.js          # Service worker
├── content.js             # Content script (runs on pages)
├── popup.html             # Popup UI
├── popup.css              # Popup styles
├── popup.js               # Popup logic
├── styles.css             # Content script styles
└── images/                # Icons
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

### Building Icons

Create icons in sizes 16x16, 48x48, and 128x128 pixels:
- Format: PNG
- Transparent background recommended
- Place in `images/` folder

### Testing

1. Load extension in developer mode
2. Open browser console to see logs
3. Test on various websites
4. Check popup functionality

## Compatibility

- Chrome 88+
- Edge 88+
- Brave 1.20+
- Opera 74+
- Firefox 109+ (Manifest V2 version needed)

## License

MIT License - See LICENSE file for details

## Support

For issues and feature requests, please use the GitHub issue tracker.
