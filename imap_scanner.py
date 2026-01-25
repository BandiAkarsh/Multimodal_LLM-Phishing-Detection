import imaplib
import email
from email.header import decode_header
import re
import sys
import os
import time
import json
import getpass
from bs4 import BeautifulSoup

# Add project paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '04_inference'))

from service import PhishingDetectionService

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
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def connect_imap(username, password, imap_server):
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, password)
        return mail
    except Exception as e:
        print(f"{Colors.RED}Connection failed: {e}{Colors.END}")
        return None

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def save_config(server, email, password):
    data = {"server": server, "email": email, "password": password}
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f)
    print(f"{Colors.GREEN}Credentials saved securely to {CONFIG_FILE}{Colors.END}")

def monitor_inbox():
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

    print(f"\n{Colors.YELLOW}Starting Real-Time Email Monitor... (Ctrl+C to stop){Colors.END}")
    print("Initializing Detection Engine...")
    
    # Load model once
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    last_checked_id = 0
    
    while True:
        try:
            mail = connect_imap(user, pwd, server)
            if not mail:
                print("Retrying in 60 seconds...")
                time.sleep(60)
                continue
                
            mail.select("inbox")
            status, messages = mail.search(None, "ALL")
            email_ids = messages[0].split()
            
            if not email_ids:
                continue
                
            current_max_id = int(email_ids[-1])
            
            # First run: Just set the baseline, don't scan entire history
            if last_checked_id == 0:
                last_checked_id = current_max_id
                print(f"{Colors.BLUE}Inbox synced. Monitoring for NEW emails...{Colors.END}")
                mail.logout()
                time.sleep(5)
                continue
            
            # Check for new emails
            if current_max_id > last_checked_id:
                print(f"\n{Colors.CYAN}New email detected! Scanning...{Colors.END}")
                
                # Scan all new emails
                for i in range(last_checked_id + 1, current_max_id + 1):
                    eid = str(i).encode()
                    res, msg_data = mail.fetch(eid, "(RFC822)")
                    
                    if not msg_data or msg_data[0] is None:
                        continue

                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            subject, encoding = decode_header(msg["Subject"])[0]
                            if isinstance(subject, bytes):
                                subject = subject.decode(encoding if encoding else "utf-8")
                            
                            print(f"{Colors.BOLD}Subject: {subject}{Colors.END}")
                            
                            # Extract body
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    content_disposition = str(part.get("Content-Disposition"))
                                    
                                    if "attachment" in content_disposition:
                                        continue
                                        
                                    try:
                                        payload = part.get_payload(decode=True)
                                        if not payload: continue
                                        
                                        text = payload.decode('utf-8', errors='ignore')
                                        
                                        if content_type == "text/plain":
                                            body += text
                                        elif content_type == "text/html":
                                            soup = BeautifulSoup(text, 'html.parser')
                                            links = [a.get('href') for a in soup.find_all('a', href=True)]
                                            body += " ".join(links)
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
                            
                            if urls:
                                print(f"Found {len(urls)} links. Analyzing...")
                                phishing_found = False
                                for url in urls:
                                    res = service.analyze_url(url)
                                    if res['classification'] == 'phishing':
                                        phishing_found = True
                                        print(f"  {Colors.RED}🚨 PHISHING: {url}{Colors.END}")
                                        print(f"     Reason: {res['explanation']}")
                                    else:
                                        pass # Safe links are silent to reduce noise
                                
                                if phishing_found:
                                    print(f"{Colors.RED}{Colors.BOLD}🚫 DANGER: Phishing detected in this email!{Colors.END}")
                                else:
                                    print(f"{Colors.GREEN}✅ Safe email.{Colors.END}")
                            else:
                                print(f"{Colors.GREEN}No links found.{Colors.END}")
                                
                last_checked_id = current_max_id
            
            mail.logout()
            time.sleep(5) # Check every 5 seconds
            
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}Monitor stopped.{Colors.END}")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    monitor_inbox()
