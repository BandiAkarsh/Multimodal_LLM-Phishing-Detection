#!/usr/bin/env python3
"""
Real-time IMAP Email Scanner - Monitor inbox for phishing emails

This script connects to your email inbox via IMAP and monitors
for new emails in real-time, scanning each one for phishing URLs.

Features:
- INTERNET-AWARE: Automatically adapts to connectivity changes
- Real-time monitoring with configurable check interval
- Secure credential storage
- Support for Gmail, Outlook, and other IMAP servers

Usage:
    python imap_scanner.py              # Start monitoring
    python imap_scanner.py --reset      # Reset saved credentials
    python imap_scanner.py --offline    # Force offline mode (for testing)

Setup (Gmail):
    1. Enable 2-Step Verification in your Google Account
    2. Generate an App Password: Security > 2-Step Verification > App passwords
    3. Use your email and app password when prompted
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
from bs4 import BeautifulSoup

# Add project paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '04_inference'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '05_utils'))

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

CONFIG_FILE = "email_config.json"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def extract_urls_from_text(text):
    """Extract URLs from text."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def connect_imap(username, password, imap_server):
    """Connect to IMAP server."""
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, password)
        return mail
    except Exception as e:
        print(f"{Colors.RED}Connection failed: {e}{Colors.END}")
        return None

def load_config():
    """Load saved credentials."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def save_config(server, email_addr, password):
    """Save credentials to config file."""
    data = {"server": server, "email": email_addr, "password": password}
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f)
    print(f"{Colors.GREEN}Credentials saved to {CONFIG_FILE}{Colors.END}")

def delete_config():
    """Delete saved credentials."""
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print(f"{Colors.GREEN}Credentials deleted.{Colors.END}")

async def analyze_urls(service, urls, is_online):
    """Analyze a list of URLs."""
    phishing_found = False
    
    for url in urls:
        if len(url) < 10:
            continue
            
        try:
            result = await service.analyze_url_async(url, force_mllm=is_online)
            
            if result['classification'] == 'phishing':
                phishing_found = True
                print(f"  {Colors.RED}[PHISHING]{Colors.END} {url[:55]}")
                print(f"     {Colors.YELLOW}Risk:{Colors.END} {result['risk_score']}/100")
                print(f"     {Colors.YELLOW}Reason:{Colors.END} {result['explanation'][:60]}...")
            # Uncomment to show safe URLs
            # else:
            #     print(f"  {Colors.GREEN}[SAFE]{Colors.END} {url[:55]}")
        except Exception as e:
            print(f"  {Colors.YELLOW}[ERROR]{Colors.END} {url[:40]} - {e}")
    
    return phishing_found

async def monitor_inbox_async(force_offline=False):
    """Main monitoring loop (async version)."""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   📧 REAL-TIME EMAIL PHISHING SCANNER                         ║
║   Monitors your inbox for dangerous emails                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}""")
    
    # Load or setup credentials
    config = load_config()
    
    if not config:
        print(f"{Colors.CYAN}--- FIRST TIME SETUP ---{Colors.END}")
        print("To use this, you need an 'App Password' from Google (not your login password).")
        print("Go to Google Account -> Security -> 2-Step Verification -> App passwords.\n")
        
        server = input("IMAP Server (default: imap.gmail.com): ").strip() or "imap.gmail.com"
        user = input("Email: ").strip()
        pwd = getpass.getpass("App Password: ").strip()
        
        save = input("Save credentials for future? (y/n): ").lower()
        if save == 'y':
            save_config(server, user, pwd)
    else:
        print(f"{Colors.GREEN}Loaded credentials for {config['email']}{Colors.END}")
        server = config['server']
        user = config['email']
        pwd = config['password']
    
    # Check initial connectivity
    if force_offline:
        is_online = False
        print(f"\n{Colors.YELLOW}[FORCED OFFLINE MODE] Using static analysis only{Colors.END}")
    else:
        print(f"\n{Colors.CYAN}Checking internet connection...{Colors.END}", end=" ")
        is_online = check_internet_connection()
        if is_online:
            print(f"{Colors.GREEN}Online - Full analysis enabled{Colors.END}")
        else:
            print(f"{Colors.YELLOW}Offline - Using static analysis{Colors.END}")
    
    # Initialize detection service
    print(f"{Colors.CYAN}Loading detection engine...{Colors.END}")
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    
    if force_offline:
        service._is_online = False
    
    # Initialize connectivity monitor for periodic checks
    connectivity_monitor = ConnectivityMonitor(check_interval=60)
    
    print(f"\n{Colors.YELLOW}Starting Real-Time Email Monitor... (Ctrl+C to stop){Colors.END}")
    print(f"{Colors.BLUE}Checking for new emails every 5 seconds...{Colors.END}\n")
    
    last_checked_id = 0
    last_connectivity_status = is_online
    
    while True:
        try:
            # Periodic connectivity check
            current_online = connectivity_monitor.is_online if not force_offline else False
            
            if current_online != last_connectivity_status:
                if current_online:
                    print(f"\n{Colors.GREEN}[STATUS] Internet connection restored - switching to full analysis{Colors.END}")
                else:
                    print(f"\n{Colors.YELLOW}[STATUS] Internet connection lost - switching to static analysis{Colors.END}")
                last_connectivity_status = current_online
                service._is_online = current_online
            
            # Connect to IMAP
            mail = connect_imap(user, pwd, server)
            if not mail:
                print(f"{Colors.YELLOW}Retrying in 60 seconds...{Colors.END}")
                await asyncio.sleep(60)
                continue
            
            mail.select("inbox")
            status, messages = mail.search(None, "ALL")
            email_ids = messages[0].split()
            
            if not email_ids:
                mail.logout()
                await asyncio.sleep(5)
                continue
            
            current_max_id = int(email_ids[-1])
            
            # First run: Just set the baseline
            if last_checked_id == 0:
                last_checked_id = current_max_id
                mode = "ONLINE" if current_online else "OFFLINE"
                print(f"{Colors.BLUE}Inbox synced ({len(email_ids)} emails). Mode: {mode}{Colors.END}")
                print(f"{Colors.GREEN}Monitoring for NEW emails...{Colors.END}\n")
                mail.logout()
                await asyncio.sleep(5)
                continue
            
            # Check for new emails
            if current_max_id > last_checked_id:
                print(f"\n{Colors.CYAN}{'='*50}{Colors.END}")
                print(f"{Colors.CYAN}🔔 New email detected! Scanning...{Colors.END}")
                
                for i in range(last_checked_id + 1, current_max_id + 1):
                    eid = str(i).encode()
                    res, msg_data = mail.fetch(eid, "(RFC822)")
                    
                    if not msg_data or msg_data[0] is None:
                        continue
                    
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            
                            # Decode subject
                            subject, encoding = decode_header(msg["Subject"])[0]
                            if isinstance(subject, bytes):
                                subject = subject.decode(encoding if encoding else "utf-8", errors='ignore')
                            
                            sender = msg["From"]
                            
                            print(f"\n{Colors.BOLD}Subject:{Colors.END} {subject}")
                            print(f"{Colors.BOLD}From:{Colors.END} {sender}")
                            
                            # Extract body and URLs
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    content_disposition = str(part.get("Content-Disposition"))
                                    
                                    if "attachment" in content_disposition:
                                        continue
                                    
                                    try:
                                        payload = part.get_payload(decode=True)
                                        if not payload:
                                            continue
                                        
                                        text = payload.decode('utf-8', errors='ignore')
                                        
                                        if content_type == "text/plain":
                                            body += text
                                        elif content_type == "text/html":
                                            soup = BeautifulSoup(text, 'html.parser')
                                            links = [a.get('href') for a in soup.find_all('a', href=True)]
                                            body += " ".join(filter(None, links))
                                    except:
                                        pass
                            else:
                                try:
                                    payload = msg.get_payload(decode=True)
                                    if payload:
                                        body = payload.decode('utf-8', errors='ignore')
                                except:
                                    pass
                            
                            urls = list(set(extract_urls_from_text(body)))
                            # Filter out tracking/unsubscribe URLs
                            urls = [u for u in urls if not any(x in u.lower() for x in ['unsubscribe', 'mailto:', 'tel:'])]
                            
                            if urls:
                                mode = "[ONLINE]" if current_online else "[OFFLINE]"
                                print(f"{Colors.BLUE}Found {len(urls)} links. Analyzing... {mode}{Colors.END}")
                                
                                phishing_found = await analyze_urls(service, urls, current_online)
                                
                                if phishing_found:
                                    print(f"\n{Colors.RED}{Colors.BOLD}⚠️  DANGER: Phishing detected in this email!{Colors.END}")
                                    print(f"{Colors.RED}DO NOT click any links in this email.{Colors.END}")
                                else:
                                    print(f"{Colors.GREEN}✅ No threats detected.{Colors.END}")
                            else:
                                print(f"{Colors.GREEN}✅ No links found in email.{Colors.END}")
                
                print(f"{Colors.CYAN}{'='*50}{Colors.END}\n")
                last_checked_id = current_max_id
            
            mail.logout()
            await asyncio.sleep(5)  # Check every 5 seconds
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.GREEN}Monitor stopped. Goodbye!{Colors.END}")
            break
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")
            await asyncio.sleep(10)

def monitor_inbox(force_offline=False):
    """Wrapper for async monitor function."""
    asyncio.run(monitor_inbox_async(force_offline))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time IMAP Email Phishing Scanner")
    parser.add_argument("--reset", action="store_true", help="Delete saved credentials")
    parser.add_argument("--offline", action="store_true", help="Force offline mode")
    
    args = parser.parse_args()
    
    if args.reset:
        delete_config()
        print("Run the script again to set up new credentials.")
    else:
        monitor_inbox(force_offline=args.offline)
