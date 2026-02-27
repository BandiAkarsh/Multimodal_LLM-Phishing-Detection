# Changelog

All notable changes to the Phishing Guard browser extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New feature placeholders for upcoming releases

## [2.0.0] - 2026-02-27

### Major Release - Standalone Edition

#### Added
- **Standalone Mode**: Extension now works completely without any external API
- **JavaScript-based Detection**: All analysis happens locally in the browser
- **100% Offline Support**: Works without internet connection
- **Zero Data Collection**: Complete privacy with no data transmission
- **Enhanced UI**: Improved popup interface with better statistics
- **Quick Scan Feature**: Manual URL scanning with detailed results
- **Real-time Link Highlighting**: Automatic visual indicators on all webpages
- **Typosquatting Detection**: Identifies fake domains impersonating trusted brands
- **Risk Score System**: 0-100% risk calculation for each link
- **Protection Toggle**: Enable/disable scanning per page
- **Desktop Notifications**: Alerts for high-risk threats
- **Chrome Web Store Ready**: Full packaging and distribution setup

#### Changed
- Migrated from API-dependent to standalone JavaScript detection
- Updated manifest.json to version 3
- Improved detection algorithms with better accuracy
- Enhanced popup design with modern UI
- Optimized performance for faster scanning

#### Removed
- Dependency on Python backend API
- External server communication
- ML model loading (now uses rule-based heuristics)

#### Security
- All processing now happens locally
- No external network requests for scanning
- Enhanced privacy protection

## [1.1.0] - 2025-XX-XX

### Added
- Support for local API connection
- Enhanced ML-based detection (optional)
- Improved popup statistics
- Better error handling

### Fixed
- Memory leak in content script
- False positives on certain domains

## [1.0.0] - 2025-XX-XX

### Initial Release

#### Added
- Basic phishing detection extension
- Content script for link scanning
- Background service worker
- Popup interface
- Icon set (16px, 48px, 128px)
- Support for Chrome Web Store
- Basic documentation

### Notes
- Requires Python backend for full functionality
- API-based detection system

---

## Versioning Guidelines

- **MAJOR**: Breaking changes, new architecture
- **MINOR**: New features, enhancements
- **PATCH**: Bug fixes, security updates

## Release Checklist

Before releasing a new version:
- [ ] Update version in manifest.json
- [ ] Update version in package.json
- [ ] Update version in build scripts
- [ ] Update CHANGELOG.md
- [ ] Test all features
- [ ] Build distribution package
- [ ] Create GitHub release
- [ ] Upload to Chrome Web Store (if applicable)
- [ ] Tag git commit

## Future Roadmap

### Version 2.1.0 (Planned)
- [ ] Firefox support
- [ ] Edge Add-ons store
- [ ] Additional language support
- [ ] Custom whitelist/blacklist
- [ ] Export/import settings

### Version 2.2.0 (Planned)
- [ ] Machine learning model in browser
- [ ] Advanced threat categorization
- [ ] Detailed threat reports
- [ ] Integration with security APIs (optional)

### Version 3.0.0 (Future)
- [ ] Cross-browser compatibility layer
- [ ] Mobile browser support
- [ ] Team/enterprise features
- [ ] Advanced analytics (local only)

---

[Unreleased]: https://github.com/yourusername/phishing-detection-project/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/yourusername/phishing-detection-project/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/yourusername/phishing-detection-project/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/yourusername/phishing-detection-project/releases/tag/v1.0.0
