#!/usr/bin/env python3
import os
import sys
import json
import getpass
import subprocess
import time
import webbrowser

# Identify which suite this is
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Check if we are in hub or main project
if "lightweight" in CURRENT_DIR:
    SUITE_TYPE = "lightweight"
elif "advanced_ai" in CURRENT_DIR:
    SUITE_TYPE = "advanced_ai"
else:
    SUITE_TYPE = "standard"

PROJECT_ROOT = CURRENT_DIR
CONFIG_FILE = os.path.join(PROJECT_ROOT, "email_config.json")
CREDS_FILE = os.path.join(PROJECT_ROOT, "credentials.json")
REGISTRY_FILE = os.path.expanduser("~/.phishing_guard_registry.json")

def print_banner():
    color = "\033[92m" if "lightweight" in SUITE_TYPE else "\033[95m"
    print(f"""
{color}\033[1m
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
  ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
  ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
                 [Phishing Guard Team]
                 VERSION: {SUITE_TYPE.upper()} (Pure OAuth2)
\033[0m""")

def run_step(number, title, description):
    print(f"\n\033[1mStep {number}: {title}\033[0m")
    print(f"\033[90m{description}\033[0m")

def check_system_readiness():
    run_step(0, "System Readiness Check", "Verifying hardware and installing necessary components.")
    
    # Check for credentials.json
    if not os.path.exists(CREDS_FILE):
        print(f"\n\033[91m❌ ERROR: credentials.json not found in {PROJECT_ROOT}\033[0m")
        print("To use 'Sign in with Google', you must first setup your Google Cloud Project.")
        print("Please read 'CREDENTIALS_GUIDE.md' for instructions.")
        sys.exit(1)

    # 1. GPU Check for AI version
    if SUITE_TYPE == "advanced_ai":
        try:
            import torch
            if not torch.cuda.is_available():
                print("\n\033[93m⚠️  WARNING: No NVIDIA GPU detected.\033[0m")
                print("The 'Advanced AI' version requires a GPU for acceptable performance.")
                if input("\nContinue anyway? (y/n): ").lower() != 'y': sys.exit(0)
        except: pass

    # 2. Install Dependencies
    print("\n\033[94mChecking Python dependencies...\033[0m")
    req_file = os.path.join(PROJECT_ROOT, "requirements.txt")
    if os.path.exists(req_file):
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file, "google-auth-oauthlib", "google-auth-httplib2"], check=True)
            print("\033[92m✅ Dependencies verified.\033[0m")
        except:
            print("\033[91m❌ Failed to install dependencies.\033[0m")

    # 3. Playwright Installation
    print("\n\033[94mChecking Web Scraper (Playwright)...\033[0m")
    try:
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        print("\033[92m✅ Web Scraper ready.\033[0m")
    except:
        print("\033[91m❌ Failed to install Playwright browser.\033[0m")

def check_existing_account():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, 'r') as f:
                reg = json.load(f)
                email = reg.get("active_email")
                suite = reg.get("suite_type")
                if email:
                    print(f"\n\033[91m\033[1m⚠️  WARNING: ACCOUNT ALREADY PROTECTED\033[0m")
                    print(f"\033[93mThe account '{email}' is already being guarded by the '{suite}' version.\033[0m")
                    if input("\nDo you want to (1) Replace it or (2) Stop setup? (1/2): ") != "1":
                        sys.exit(0)
        except: pass

def setup_email():
    check_existing_account()
    run_step(1, "Link Your Google Account", "Securely connect Phishing Guard using standard Google Login.")
    
    from google_auth_oauthlib.flow import InstalledAppFlow
    SCOPES = ['https://mail.google.com/']
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(CREDS_FILE, SCOPES)
        creds = flow.run_local_server(
            port=0, 
            authorization_prompt_message='\033[94mPlease log in through the browser window that just opened...\033[0m',
            success_message='\033[92m✅ Success! Your account is now linked securely.\033[0m'
        )
        
        email_addr = input("\n\033[1mConfirm your Gmail Address:\033[0m ").strip()
        
        config = {
            "auth_type": "oauth2",
            "email": email_addr,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "server": "imap.gmail.com"
        }
        
        with open(CONFIG_FILE, 'w') as f: json.dump(config, f)
        os.chmod(CONFIG_FILE, 0o600)
        
        # Update registry
        try:
            with open(REGISTRY_FILE, 'w') as f:
                json.dump({"active_email": email_addr, "suite_type": SUITE_TYPE, "path": PROJECT_ROOT}, f)
        except: pass
        
        print(f"\n\033[92m✅ Google Account '{email_addr}' linked successfully!\033[0m")
        
    except Exception as e:
        print(f"\n\033[91m❌ OAuth Flow Failed: {e}\033[0m")
        sys.exit(1)

def install_services():
    run_step(2, "Activate 24/7 Protection", "Installs Phishing Guard as a silent background service.")
    if input("\nEnable background protection? (y/n): ").lower() != 'y': return

    user = getpass.getuser()
    py = sys.executable
    api_svc = f"phishing-api-{SUITE_TYPE}.service"
    mon_svc = f"phishing-monitor-{SUITE_TYPE}.service"

    api_content = f"""[Unit]
Description=Phishing Guard API ({SUITE_TYPE})
After=network.target
[Service]
ExecStart={py} {PROJECT_ROOT}/04_inference/api.py
WorkingDirectory={PROJECT_ROOT}
Restart=always
User={user}
[Install]
WantedBy=multi-user.target"""

    mon_content = f"""[Unit]
Description=Phishing Guard Email Watchdog ({SUITE_TYPE})
After=network.target {api_svc}
[Service]
ExecStart={py} {PROJECT_ROOT}/email_scanner.py --monitor --daemon
WorkingDirectory={PROJECT_ROOT}
Restart=always
User={user}
[Install]
WantedBy=multi-user.target"""

    try:
        for name, content in [(api_svc, api_content), (mon_svc, mon_content)]:
            with open(f"/tmp/{name}", "w") as f: f.write(content)
            subprocess.run(["sudo", "cp", f"/tmp/{name}", "/etc/systemd/system/"], check=True)
        
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", api_svc, mon_svc], check=True)
        subprocess.run(["sudo", "systemctl", "start", api_svc, mon_svc], check=True)
        print(f"\n\033[92m🚀 PROTECTION ACTIVE! Check alerts in your desktop notifications.\033[0m")
    except Exception as e: print(f"\033[91m❌ Failed: {e}\033[0m")

def main():
    try:
        print_banner()
        check_system_readiness()
        setup_email()
        install_services()
        print("\n\033[96m\033[1mSetup Complete! Your inbox is now being guarded.\033[0m")
    except KeyboardInterrupt: print("\n\n\033[93mCancelled.\033[0m")

if __name__ == "__main__":
    main()
