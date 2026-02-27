# Store Assets

This directory contains all assets required for Chrome Web Store submission and promotional materials.

## Directory Structure

```
store-assets/
├── screenshots/           # Extension screenshots (REQUIRED)
│   ├── screenshot-1.png   # 1280x800 or 640x400
│   ├── screenshot-2.png
│   ├── screenshot-3.png
│   └── screenshot-4.png
├── promotional/           # Promotional images (OPTIONAL but recommended)
│   ├── small.png         # 440x280 (small promo tile)
│   ├── large.png         # 920x680 (large promo tile)
│   └── marquee.png       # 1400x560 (marquee promo tile)
├── icons/                 # Additional icon sizes
│   └── icon-32.png       # 32x32 icon
└── README.md             # This file
```

## Chrome Web Store Requirements

### Screenshots (Required)
- **Format**: PNG or JPEG
- **Sizes**: 
  - 1280x800 pixels (recommended)
  - 640x400 pixels (minimum)
- **Aspect Ratio**: 16:10 or 4:3
- **Max Size**: 5MB per image
- **Quantity**: 1-10 screenshots
- **Content**: Show actual extension functionality

**Screenshot Guidelines:**
1. Show the extension in action
2. Include browser chrome (address bar, tabs)
3. Demonstrate key features
4. Use real websites, not mockups
5. Keep text minimal and readable
6. Avoid sensitive information

### Promotional Images (Optional)

#### Small Promotional Tile
- **Size**: 440x280 pixels
- **Format**: PNG or JPEG
- **Use**: Store listing page

#### Large Promotional Tile
- **Size**: 920x680 pixels
- **Format**: PNG or JPEG
- **Use**: Store carousel and featured sections

#### Marquee Promotional Tile
- **Size**: 1400x560 pixels
- **Format**: PNG or JPEG
- **Use**: Homepage and category features

**Promotional Image Guidelines:**
- Avoid text where possible
- Use high-contrast colors
- Make text large and readable (if any)
- Avoid busy backgrounds
- Keep branding consistent
- Don't include pricing

## Current Assets

### Icons
- ✅ icon16.png (Toolbar icon)
- ✅ icon48.png (Extension management)
- ✅ icon128.png (Store listing)

### To Be Created
- ⬜ Screenshots (4-5 recommended)
- ⬜ Small promotional tile
- ⬜ Large promotional tile
- ⬜ Marquee promotional tile

## Screenshot Ideas

1. **Main Feature**: Popup showing scan results with green/safe result
2. **Link Highlighting**: Page with multiple links showing different colors
3. **Threat Detection**: Popup showing a phishing warning in red
4. **Statistics**: Popup showing threat statistics
5. **Settings**: Quick scan feature in action

## Creating Assets

### Tools Recommended
- **Screenshots**: Built-in browser screenshot tools or Chrome DevTools
- **Image Editing**: Figma, Canva, Adobe Photoshop, GIMP
- **Mockups**: Browserframe.com, Screely.com

### Screenshot Workflow
1. Open browser with extension installed
2. Navigate to a test page or real website
3. Trigger the feature you want to showcase
4. Use browser's screenshot tool (F12 → Capture screenshot)
5. Crop to 1280x800 or 640x400
6. Save as PNG for best quality

## Asset Checklist

Before submitting to Chrome Web Store:

- [ ] At least 1 screenshot (1280x800 or 640x400)
- [ ] Icons in all required sizes (16, 48, 128)
- [ ] Privacy Policy link provided
- [ ] Store listing description complete
- [ ] Contact email provided
- [ ] Category selected (Privacy & Security)
- [ ] Language specified

## Chrome Web Store Image Specs Summary

| Type | Size | Required | Max Size |
|------|------|----------|----------|
| Screenshot | 1280x800 or 640x400 | Yes | 5MB |
| Small Promo | 440x280 | No | 5MB |
| Large Promo | 920x680 | No | 5MB |
| Marquee | 1400x560 | No | 5MB |
| Icon | 128x128 | Yes | 5MB |

## Resources

- [Chrome Web Store Images and Media](https://developer.chrome.com/docs/webstore/images/)
- [Chrome Web Store Publishing Guide](https://developer.chrome.com/docs/webstore/publish/)
- [Screenshot Best Practices](https://developer.chrome.com/docs/webstore/best_practices/#screenshots)

---

**Note**: Update this README as you add new assets to keep track of what\'s available for store submission.
