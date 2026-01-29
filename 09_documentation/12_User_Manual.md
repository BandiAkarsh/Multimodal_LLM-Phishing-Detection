# Phishing Guard Unified Suite - User Manual

## Overview
Phishing Guard is a professional-grade email security suite that provides 24/7 background protection against phishing attacks. It works across all your email services (Gmail, Outlook, Thunderbird, etc.) by monitoring the mail server directly and alerting you with desktop notifications.

## 📋 Important Considerations

- **Download Size**: Phishing Guard uses a sophisticated 3-Billion parameter Large Language Model (LLM) and a security-focused headless browser. The initial setup will download approximately **3GB to 5GB** of data.
- **Disk Space**: Please ensure you have at least **6GB** of free disk space for a full installation.
- **Privacy First**: All analysis happens **locally on your computer**. No email content or private keys are ever sent to a remote server.

## 3-Step Setup

### 1. Link Your Account
Run the setup wizard to connect your email securely.
```bash
cd ~/phishing_detection_project
python3 setup_wizard.py
```
*   **Guided Setup**: The script will automatically open a **new browser window** to guide you to generate a secure **16-digit Security Key** (App Password) from Google.
*   **Masked Input**: As you paste your key, it will be displayed as asterisks (`****`) for security.
*   **Live Verification**: The system will automatically test the connection to ensure your key is working before completing setup.

### 2. Activate Background Protection
During the setup wizard, choose **"Yes"** when asked to install system services. This ensures Phishing Guard starts automatically every time you turn on your computer.

### 3. Real-Time Protection
Once active, Phishing Guard runs silently in the background. 
*   **No terminal needed**: You can close your terminal and go about your day.
*   **Instant Alerts**: If a dangerous link arrives in your inbox, a popup will appear in the corner of your screen:
    *"⚠️ SECURITY ALERT: Phishing Detected in: Urgent Account Update..."*

---

## Technical Details

### Components
1.  **The Engine (API)**: A FastAPI server running the ML models and 4-category classifier.
2.  **The Watchdog (Scanner)**: A background daemon monitoring your inbox via secure IMAP connection.
3.  **The Integrations**: Compatible with the Thunderbird Phishing Guard add-on.

### Management Commands
*   **Check Status**: `systemctl status phishing-scanner.service`
*   **Restart Protection**: `sudo systemctl restart phishing-scanner.service`
*   **View Logs**: `journalctl -u phishing-scanner.service -f`

---
*Created for your Professional Portfolio*
