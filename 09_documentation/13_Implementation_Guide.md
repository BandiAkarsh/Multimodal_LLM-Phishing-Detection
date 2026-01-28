# Technical Implementation Guide: Phishing Guard Suite

This document explains the architectural decisions and technical implementation of the Phishing Guard Unified Suite.

## 1. The "Backbone & Sensor" Architecture

The system is built on a decoupled architecture to ensure maximum versatility:

### The Backbone (The Brain)
- **Technology**: FastAPI (Python) + Scikit-Learn.
- **Implementation**: The `api.py` loads a pre-trained Random Forest model (`phishing_classifier.joblib`) into memory on startup. It exposes a REST API at `localhost:8000`.
- **Logic**: It uses an "Internet-Aware" logic flow. If online, it triggers a Playwright-based scraper to verify content; if offline, it falls back to static URL heuristics.

### The Sensors (The Eyes)
- **Sensors**: IMAP Scanner, Thunderbird Plugin, CLI Tool.
- **Implementation**: These components are "dumb" sensors. They don't contain the ML models. Instead, they extract URLs and send them to the Backbone API for analysis. This allows the models to be updated in one place without touching the sensors.

## 2. Universal Protocol Monitoring (IMAP)

To protect users across different browsers and apps, we implemented monitoring at the **IMAP Protocol level**.
- **Module**: `imap_scanner.py`
- **Logic**: The script connects to the mail server using `imaplib`. It maintains a `last_checked_id` to only scan NEW emails.
- **Parsing**: It uses `BeautifulSoup` to extract links from both Plain Text and HTML email parts, ensuring no link is missed.

## 3. Background Daemonization (systemd)

To make the protection "Set and Forget," we integrated with the Linux `systemd` supervisor.
- **Implementation**: The `setup_wizard.py` dynamically generates `.service` files based on the user's Python path and directory structure.
- **Automation**: Using `subprocess`, the wizard copies these files to `/etc/systemd/system/` and runs `systemctl enable` to ensure the services start automatically on boot.

## 4. Modern Security Flows (Security Key)

We transitioned from complex OAuth2 Client setups to a **Guided Security Key (App Password)** flow for Gmail users.
- **UX Design**: The wizard uses the `webbrowser` module to guide the user to their account's security page.
- **Authentication**: For Gmail, we use the "App Password" approach. This provides a 16-character permanent token that the daemon uses to authenticate securely without storing the user's primary password.

## 5. Native OS Integration

To provide a consumer-grade experience, we bypassed the terminal for alerts.
- **Library**: `plyer`
- **Implementation**: We implemented a multi-layer notification system. It first tries `plyer.notification` for cross-platform support and falls back to `notify-send` for standard Linux environments.
- **Actionable Alerts**: Notifications include the email subject and sender, allowing the user to identify the threat without opening the malicious message.

## 6. Toolkit Fingerprinting & 4-Category ML

We extended binary classification (Phishing/Legit) into a 4-category system:
- **Signatures**: We built a `ToolkitSignatureDetector` that looks for specific DOM patterns and URL parameters (like Gophish's `?rid=`).
- **AI Detection**: We implemented linguistic analysis to identify GPT-generated phishing content.
- **Refinement**: A "Content-Override" logic ensures that if the ML model is suspicious but the scraper finds high-quality, verified content, the site is marked as Legitimate (minimizing false positives).

---
*Created as a comprehensive technical breakdown for Portfolio Review.*
