# Phishing Guard Desktop

A standalone phishing detection desktop application that runs in the background and monitors your emails for phishing attacks.

## Features

- 🛡️ **Real-time Protection**: Background email scanning every 30 seconds
- 📧 **Thunderbird Support**: Automatically reads emails from your Thunderbird installation
- 🔗 **Gmail/Outlook OAuth**: Connect directly via OAuth for webmail
- 🔔 **System Notifications**: Get notified immediately when phishing is detected
- 🎯 **4-Tier Detection**: Same detection as the parent IEEE phishing detection project
  - Typosquatting detection
  - ML-based URL analysis  
  - Web content scraping
  - Phishing kit detection

## Installation

### Linux

1. Download the `phishing-guard-desktop` executable
2. Make it executable: `chmod +x phishing-guard-desktop`
3. Run it: `./phishing-guard-desktop`

The app will:
- Appear in your system tray
- Auto-detect Thunderbird accounts
- Start background scanning when you click "Start Background Monitor"

### First Run

1. Run the app
2. Click "Start Background Monitor" in the dashboard
3. Close the window (X) - app continues in background!
4. You'll receive notifications when phishing emails are detected

## Usage

- **Open app**: Run the executable
- **Background scan**: Click green "Start Background Monitor" button
- **Manual scan**: Click "Scan Now" button
- **Quit**: Right-click system tray → Quit

## Configuration

- Accounts are saved to: `~/.config/phishing-guard/accounts.json`
- Logs are saved to: `~/.config/phishing-guard/logs/`

## Supported Email Sources

| Source | How It Works |
|--------|--------------|
| Thunderbird | Reads local email files automatically |
| Gmail | Connect via OAuth in the app |
| Outlook | Connect via OAuth in the app |

## Detection Categories

- **legitimate**: Safe website
- **phishing**: Traditional phishing attack
- **ai_generated**: AI-created phishing (ChatGPT, etc.)
- **phishing_kit**: Tool-based phishing (Gophish, HiddenEye, etc.)

## System Requirements

- Linux (tested on Ubuntu/Debian)
- Thunderbird (optional, for local email reading)

## License

MIT License - See parent project for details.
