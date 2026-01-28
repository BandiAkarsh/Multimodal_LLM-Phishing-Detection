#!/usr/bin/env python3
"""
Real-time IMAP Email Scanner - Monitor inbox for phishing emails

This script connects to your email inbox via IMAP and monitors
for new emails in real-time, scanning each one for phishing URLs.

Features:
- SYSTEM NOTIFICATIONS: Native desktop alerts on threats
- DAEMON COMPATIBLE: Designed to run as a background service
- INTERNET-AWARE: Automatically adapts to connectivity changes
"""

import imaplib
import email
from email.header import decode_header
import re
import sys
import os
import time
import json
import getpass
import asyncio
import argparse
import subprocess
from bs4 import BeautifulSoup
from plyer import notification

# Use dynamic absolute paths for daemon compatibility
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, '04_inference'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, '05_utils'))

from service import PhishingDetectionService

# Import connectivity checker
try:
    from connectivity import check_internet_connection, ConnectivityMonitor
except ImportError:
    def check_internet_connection():
        return True
    class ConnectivityMonitor:
        def __init__(self, check_interval=30):
            self.is_online = True

CONFIG_FILE = os.path.join(PROJECT_ROOT, "email_config.json")

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def send_desktop_notification(title, message, timeout=10):
    """Send a native desktop notification with fallback."""
    print(f"\n{Colors.BOLD}[NOTIFICATION] {title}: {message}{Colors.END}")
    try:
        # 1. Try plyer (Native OS notifications)
        notification.notify(
            title=f"Phishing Guard: {title}",
            message=message,
            app_name="Phishing Guard",
            timeout=timeout
        )
    except Exception as e:
        # 2. Try notify-send (Linux standard)
        try:
            subprocess.run(["notify-send", f"Phishing Guard: {title}", message], check=False)
        except:
            pass

def extract_urls_from_text(text):
    """Extract URLs from text."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def connect_imap(config):
    """Connect to IMAP server with support for Standard and OAuth2."""
    try:
        imap_server = config.get("server", "imap.gmail.com")
        mail = imaplib.IMAP4_SSL(imap_server)
        
        if config.get("auth_type") == "oauth2":
            # Handle Google OAuth2 (XOAUTH2)
            import google.oauth2.credentials
            import google.auth.transport.requests
            
            creds = google.oauth2.credentials.Credentials(
                None,
                refresh_token=config['refresh_token'],
                client_id=config['client_id'],
                client_secret=config['client_secret'],
                token_uri=config['token_uri']
            )
            
            # Refresh token to get access token
            request = google.auth.transport.requests.Request()
            creds.refresh(request)
            
            # Authenticate using XOAUTH2
            auth_string = f"user={config['email']}\1auth=Bearer {creds.token}\1\1"
            mail.authenticate('XOAUTH2', lambda x: auth_string)
        else:
            # Standard IMAP Login
            mail.login(config['email'], config['password'])
            
        return mail
    except Exception as e:
        print(f"{Colors.RED}Connection failed: {e}{Colors.END}")
        return None

def load_config():
    """Load saved credentials."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            return None
    return None

def save_config(server, email_addr, password):
    """Save credentials to config file."""
    data = {"server": server, "email": email_addr, "password": password, "auth_type": "standard"}
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f)
    print(f"{Colors.GREEN}Credentials saved to {CONFIG_FILE}{Colors.END}")

def delete_config():
    """Delete saved credentials."""
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print(f"{Colors.GREEN}Credentials deleted.{Colors.END}")

async def analyze_urls(service, urls, is_online, subject, sender):
    """Analyze a list of URLs and notify if phishing found."""
    phishing_found = False
    threats = []
    
    for url in urls:
        if len(url) < 10:
            continue
            
        try:
            result = await service.analyze_url_async(url, force_mllm=is_online)
            
            if result['classification'] != 'legitimate':
                phishing_found = True
                category = result.get('classification', 'phishing').upper()
                threats.append(f"{category}: {url[:30]}...")
                
                print(f"  {Colors.RED}[{category}]{Colors.END} {url[:55]}")
                print(f"     {Colors.YELLOW}Risk:{Colors.END} {result['risk_score']}/100")
                print(f"     {Colors.YELLOW}Reason:{Colors.END} {result['explanation'][:60]}...")
        except Exception as e:
            print(f"  {Colors.YELLOW}[ERROR]{Colors.END} {url[:40]} - {e}")
    
    if phishing_found:
        msg = f"Detected in: {subject[:30]}...\nFrom: {sender[:30]}\n"
        msg += "\n".join(threats[:2])
        if len(threats) > 2:
            msg += f"\n...and {len(threats)-2} more"
            
        send_desktop_notification("⚠️ SECURITY ALERT", msg)
        
    return phishing_found

async def monitor_inbox_async(force_offline=False, daemon_mode=False):
    """Main monitoring loop (async version)."""
    if not daemon_mode:
        print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   📧 REAL-TIME EMAIL PHISHING SCANNER                         ║
║   Integrated Desktop Notifications Enabled                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}""")
    
    # Load or setup credentials
    config = load_config()
    
    if not config:
        if daemon_mode:
            print("No config found. Please run setup first.")
            return
            
        print(f"{Colors.CYAN}--- FIRST TIME SETUP ---{Colors.END}")
        server = input("IMAP Server (default: imap.gmail.com): ").strip() or "imap.gmail.com"
        user = input("Email: ").strip()
        pwd = getpass.getpass("App Password: ").strip()
        save_config(server, user, pwd)
        config = load_config()
    else:
        if not daemon_mode:
            print(f"{Colors.GREEN}Loaded credentials for {config['email']}{Colors.END}")
    
    # Initialize connectivity monitor
    connectivity_monitor = ConnectivityMonitor(check_interval=60)
    is_online = connectivity_monitor.is_online if not force_offline else False
    
    # Initialize detection service
    if not daemon_mode:
        print(f"{Colors.CYAN}Loading detection engine...{Colors.END}")
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    service._is_online = is_online
    
    if not daemon_mode:
        print(f"\n{Colors.YELLOW}Starting Real-Time Email Monitor... (Ctrl+C to stop){Colors.END}")
    
    last_checked_id = 0
    last_connectivity_status = is_online
    
    while True:
        try:
            # Periodic connectivity check
            current_online = connectivity_monitor.is_online if not force_offline else False
            if current_online != last_connectivity_status:
                last_connectivity_status = current_online
                service._is_online = current_online
            
            # Connect to IMAP
            mail = connect_imap(config)
            if not mail:
                await asyncio.sleep(60)
                continue
            
            mail.select("inbox")
            status, messages = mail.search(None, "ALL")
            email_ids = messages[0].split()
            
            if not email_ids:
                mail.logout()
                await asyncio.sleep(10)
                continue
            
            current_max_id = int(email_ids[-1])
            
            # First run: Just set the baseline
            if last_checked_id == 0:
                last_checked_id = current_max_id
                if not daemon_mode:
                    print(f"{Colors.GREEN}Monitoring for NEW emails...{Colors.END}\n")
                mail.logout()
                await asyncio.sleep(10)
                continue
            
            # Check for new emails
            if current_max_id > last_checked_id:
                for i in range(last_checked_id + 1, current_max_id + 1):
                    eid = str(i).encode()
                    res, msg_data = mail.fetch(eid, "(RFC822)")
                    
                    if not msg_data or msg_data[0] is None:
                        continue
                    
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            
                            # Decode subject
                            subject_header = msg.get("Subject", "No Subject")
                            decoded_parts = decode_header(subject_header)
                            subject = ""
                            for part, encoding in decoded_parts:
                                if isinstance(part, bytes):
                                    subject += part.decode(encoding or "utf-8", errors='ignore')
                                else:
                                    subject += str(part)
                            
                            sender = msg.get("From", "Unknown Sender")
                            
                            if not daemon_mode:
                                print(f"\n{Colors.CYAN}🔔 New email: {subject[:50]}{Colors.END}")
                            
                            # Extract body and URLs
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() in ["text/plain", "text/html"]:
                                        try:
                                            payload = part.get_payload(decode=True)
                                            if payload:
                                                text = payload.decode('utf-8', errors='ignore')
                                                if part.get_content_type() == "text/html":
                                                    soup = BeautifulSoup(text, 'html.parser')
                                                    links = [a.get('href') for a in soup.find_all('a', href=True)]
                                                    body += " ".join(filter(None, links))
                                                else:
                                                    body += text
                                        except: pass
                            else:
                                try:
                                    payload = msg.get_payload(decode=True)
                                    if payload: body = payload.decode('utf-8', errors='ignore')
                                except: pass
                            
                            urls = list(set(extract_urls_from_text(body)))
                            urls = [u for u in urls if not any(x in u.lower() for x in ['unsubscribe', 'mailto:', 'tel:'])]
                            
                            if urls:
                                await analyze_urls(service, urls, current_online, subject, sender)
                
                last_checked_id = current_max_id
            
            mail.logout()
            await asyncio.sleep(10)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            if not daemon_mode: print(f"Error: {e}")
            await asyncio.sleep(30)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time IMAP Email Phishing Scanner")
    parser.add_argument("--reset", action="store_true", help="Delete saved credentials")
    parser.add_argument("--offline", action="store_true", help="Force offline mode")
    parser.add_argument("--daemon", action="store_true", help="Run in background daemon mode")
    
    args = parser.parse_args()
    
    if args.reset:
        delete_config()
    else:
        asyncio.run(monitor_inbox_async(force_offline=args.offline, daemon_mode=args.daemon))
