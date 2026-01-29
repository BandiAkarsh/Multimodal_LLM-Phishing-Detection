#!/usr/bin/env python3
"""
Email Phishing Scanner - Unified Security Tool
Phishing Guard Team

This tool provides two modes of email protection:
1. File Mode: Scan a single .eml file for phishing links.
2. Monitor Mode: Background watchdog that monitors your IMAP inbox in real-time.
"""

import imaplib
import email
from email.header import decode_header
from email import policy
from email.parser import BytesParser
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

# Dynamic path resolution
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, '04_inference'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, '05_utils'))

from service import PhishingDetectionService

# Import connectivity checker
try:
    from connectivity import check_internet_connection, ConnectivityMonitor
except ImportError:
    def check_internet_connection(): return True
    class ConnectivityMonitor:
        def __init__(self, check_interval=30): self.is_online = True

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
    """Send a native desktop notification with robust fallback."""
    print(f"\n{Colors.BOLD}[NOTIFICATION] {title}: {message}{Colors.END}")
    
    # Try notify-send first (more reliable on Linux daemons)
    try:
        subprocess.run(["notify-send", "-a", "Phishing Guard", "-u", "critical", title, message], check=False)
        return # If successful, stop here
    except:
        pass

    # Fallback to plyer
    try:
        notification.notify(
            title=f"Phishing Guard: {title}",
            message=message,
            app_name="Phishing Guard",
            timeout=timeout
        )
    except:
        pass

def extract_urls_from_text(text):
    """Find all URLs in a text string."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def parse_email_content(msg):
    """Extract body and URLs from an email message object."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode('utf-8', errors='ignore')
                        if ctype == "text/html":
                            soup = BeautifulSoup(text, 'html.parser')
                            links = [a.get('href') for a in soup.find_all('a', href=True)]
                            body += " ".join(filter(None, links))
                        else: body += text
                except: pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload: body = payload.decode('utf-8', errors='ignore')
        except: pass
    
    urls = list(set(extract_urls_from_text(body)))
    urls = [u for u in urls if not any(x in u.lower() for x in ['unsubscribe', 'mailto:', 'tel:'])]
    return urls

def connect_imap(config):
    """Connect to IMAP server using secure login."""
    try:
        imap_server = config.get("server", "imap.gmail.com")
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(config['email'], config['password'])
        return mail
    except Exception as e:
        print(f"{Colors.RED}Connection failed: {e}{Colors.END}")
        return None

async def monitor_inbox(service, force_offline=False, daemon_mode=False):
    """Monitor IMAP inbox for new emails."""
    if not daemon_mode:
        print(f"{Colors.CYAN}{Colors.BOLD}\n📧 REAL-TIME EMAIL MONITOR ACTIVE{Colors.END}")
    
    if not os.path.exists(CONFIG_FILE):
        print(f"{Colors.RED}No config found. Run setup_wizard.py first.{Colors.END}")
        return

    with open(CONFIG_FILE, 'r') as f: config = json.load(f)
    monitor = ConnectivityMonitor(check_interval=60)
    last_id = 0
    
    while True:
        try:
            is_online = monitor.is_online if not force_offline else False
            mail = connect_imap(config)
            if not mail:
                await asyncio.sleep(60); continue
            
            mail.select("inbox")
            _, msgs = mail.search(None, "ALL")
            ids = msgs[0].split()
            
            if not ids:
                mail.logout(); await asyncio.sleep(15); continue
                
            curr_max = int(ids[-1])
            if last_id == 0: last_id = curr_max
            
            if curr_max > last_id:
                for i in range(last_id + 1, curr_max + 1):
                    _, data = mail.fetch(str(i).encode(), "(RFC822)")
                    msg = email.message_from_bytes(data[0][1])
                    subject = decode_header(msg.get("Subject", "No Subject"))[0][0]
                    if isinstance(subject, bytes): subject = subject.decode(errors='ignore')
                    
                    urls = parse_email_content(msg)
                    if urls:
                        found_phish = False
                        highest_threat = ""
                        for url in urls:
                            res = await service.analyze_url_async(url, force_mllm=is_online)
                            if res['classification'] != 'legitimate':
                                found_phish = True
                                # Map internal classification to display name
                                cat = res['classification'].upper().replace('_', ' ')
                                if not highest_threat or "KIT" in cat: # Prioritize KIT > AI > PHISH
                                    highest_threat = cat
                        if found_phish:
                            title = f"🚨 {highest_threat} DETECTED"
                            send_desktop_notification(title, f"Threat found in: {subject}")
                last_id = curr_max
            
            mail.logout()
            await asyncio.sleep(15)
        except Exception as e:
            if not daemon_mode: print(f"Error: {e}")
            await asyncio.sleep(30)

async def scan_file(service, file_path, is_online):
    """Scan a local .eml file."""
    if not os.path.exists(file_path):
        print(f"{Colors.RED}Error: File {file_path} not found.{Colors.END}")
        return

    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    print(f"\n{Colors.BOLD}📧 SCANNING EMAIL: {msg['subject']}{Colors.END}")
    urls = parse_email_content(msg)
    
    if not urls:
        print(f"{Colors.GREEN}✅ No links found in this email.{Colors.END}")
        return

    print(f"Found {len(urls)} links. Analyzing...\n")
    for url in urls:
        res = await service.analyze_url_async(url, force_mllm=is_online)
        status = f"{Colors.RED}[{res['classification'].upper()}]{Colors.END}" if res['classification'] != 'legitimate' else f"{Colors.GREEN}[SAFE]{Colors.END}"
        print(f"{status} {url[:60]}")
        if res['classification'] != 'legitimate':
            print(f"   ↳ {Colors.YELLOW}Reason:{Colors.END} {res['explanation']}")

async def main():
    parser = argparse.ArgumentParser(description="Phishing Guard: Unified Email Scanner")
    parser.add_argument("file", nargs="?", help="Path to .eml file to scan")
    parser.add_argument("--monitor", action="store_true", help="Start real-time IMAP monitoring")
    parser.add_argument("--offline", action="store_true", help="Force offline mode")
    parser.add_argument("--daemon", action="store_true", help="Run in background mode (silences output)")
    
    args = parser.parse_args()
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    is_online = not args.offline and check_internet_connection()
    
    if args.monitor:
        await monitor_inbox(service, force_offline=args.offline, daemon_mode=args.daemon)
    elif args.file:
        await scan_file(service, args.file, is_online)
    else:
        parser.print_help()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
