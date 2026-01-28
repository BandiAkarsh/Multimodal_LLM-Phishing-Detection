#!/usr/bin/env python3
import os
import sys
import json
import getpass
import subprocess
import time
import webbrowser

# Use dynamic absolute paths
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROJECT_ROOT, "email_config.json")

def print_banner():
    print("""
\033[96m\033[1m
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
  ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
  ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
                 GUARDS YOUR INBOX 24/7
\033[0m""")

def run_step(number, title, description):
    print(f"\n\033[1mStep {number}: {title}\033[0m")
    print(f"\033[90m{description}\033[0m")

def setup_email():
    print_banner()
    run_step(1, "Link Your Email Account", "This connects Phishing Guard to your inbox using a secure access key.")
    
    email_addr = input("\n\033[1mEnter your Email Address:\033[0m ").strip()
    
    if "gmail.com" in email_addr.lower():
        setup_gmail_guided(email_addr)
    else:
        setup_standard_imap(email_addr)

def setup_gmail_guided(email_addr):
    print("\n\033[94m[Gmail Detection: Guided Setup]\033[0m")
    print("Google requires a 16-character 'App Password' to allow background monitoring.")
    print("Think of this as a secure Security Key just for this app.")
    
    print("\n\033[1mInstructions:\033[0m")
    print("1. A browser window will open to your Google Security page.")
    print("2. Login (if asked) and look for 'App passwords'.")
    print("3. Give it a name like 'Phishing Guard' and click Create.")
    print("4. \033[92mCopy the 16-character code\033[0m and paste it here.")
    
    open_browser = input("\nOpen Google Security page now? (y/n): ").lower()
    if open_browser != 'n':
        webbrowser.open("https://myaccount.google.com/apppasswords")
    
    password = getpass.getpass("\n\033[1mPaste your 16-character Security Key here:\033[0m ").strip().replace(" ", "")
    
    if len(password) != 16:
        print("\033[93mWarning: Most Google Security Keys are 16 characters long. Double check if it fails.\033[0m")

    config = {
        "auth_type": "standard",
        "server": "imap.gmail.com",
        "email": email_addr,
        "password": password
    }
    _save_config(config)

def setup_standard_imap(email_addr):
    print("\n\033[96m[Standard IMAP Setup]\033[0m")
    print("Find your server settings in your email app's 'Account Settings' or 'Help' page.")
    print("Common Servers:")
    print("  - Outlook: \033[94moutlook.office365.com\033[0m")
    print("  - Yahoo:   \033[94mimap.mail.yahoo.com\033[0m")
    
    server = input("\nIMAP Server (e.g., imap.mail.yahoo.com): ").strip()
    password = getpass.getpass("Password / App Password: ").strip()
    
    config = {
        "auth_type": "standard",
        "server": server,
        "email": email_addr,
        "password": password
    }
    _save_config(config)

def _save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)
    os.chmod(CONFIG_FILE, 0o600)
    print(f"\n\033[92m✅ Success! Account linked to {config['email']}\033[0m")

def install_system_services():
    run_step(2, "Activate Automatic Protection", "This ensures Phishing Guard starts every time you turn on your computer.")
    
    install = input("\nEnable 24/7 background protection? (y/n): ").lower()
    if install != 'y':
        print("\033[93mManual start required: python3 imap_scanner.py\033[0m")
        return

    user = getpass.getuser()
    python_path = sys.executable
    service_dir = "/etc/systemd/system"
    
    # Define services
    api_service = f"""[Unit]
Description=Phishing Guard API Backbone
After=network.target

[Service]
ExecStart={python_path} {PROJECT_ROOT}/04_inference/api.py
WorkingDirectory={PROJECT_ROOT}
Restart=always
User={user}

[Install]
WantedBy=multi-user.target
"""

    scanner_service = f"""[Unit]
Description=Phishing Guard IMAP Watchdog
After=network.target phishing-api.service

[Service]
ExecStart={python_path} {PROJECT_ROOT}/imap_scanner.py --daemon
WorkingDirectory={PROJECT_ROOT}
Restart=always
User={user}

[Install]
WantedBy=multi-user.target
"""

    try:
        # We'll write to temp files first, then use sudo to copy them
        with open("/tmp/phishing-api.service", "w") as f: f.write(api_service)
        with open("/tmp/phishing-scanner.service", "w") as f: f.write(scanner_service)
        
        print("\n\033[93m[System Action] Admin permission required to install services...\033[0m")
        subprocess.run(["sudo", "cp", "/tmp/phishing-api.service", f"{service_dir}/"], check=True)
        subprocess.run(["sudo", "cp", "/tmp/phishing-scanner.service", f"{service_dir}/"], check=True)
        
        print("Configuring system...")
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", "phishing-api.service", "phishing-scanner.service"], check=True)
        subprocess.run(["sudo", "systemctl", "start", "phishing-api.service", "phishing-scanner.service"], check=True)
        
        print("\n\033[92m🚀 PROTECTION IS ACTIVE!\033[0m")
        print("Phishing Guard is now running silently in the background.")
        print("You will see a notification here if a threat is detected.")
        
    except Exception as e:
        print(f"\n\033[91m❌ Installation failed: {e}\033[0m")
        print("You can try running the scanner manually with: python3 imap_scanner.py")

def main():
    try:
        setup_email()
        install_system_services()
        print("\n\033[96m\033[1mSetup Complete! You can close this terminal.\033[0m")
    except KeyboardInterrupt:
        print("\n\n\033[93mSetup cancelled by user.\033[0m")

if __name__ == "__main__":
    main()
