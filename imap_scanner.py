import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import re
import sys
import os
import getpass
from bs4 import BeautifulSoup

# Add project paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '04_inference'))

from service import PhishingDetectionService

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def extract_urls_from_text(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def connect_imap(username, password, imap_server="imap.gmail.com"):
    print(f"Connecting to {imap_server}...")
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, password)
        return mail
    except Exception as e:
        print(f"{Colors.RED}Connection failed: {e}{Colors.END}")
        return None

def scan_inbox(username, password, imap_server, num_emails=5):
    mail = connect_imap(username, password, imap_server)
    if not mail:
        return

    print(f"{Colors.GREEN}Connected! Scanning last {num_emails} emails...{Colors.END}\n")
    
    # Select inbox
    mail.select("inbox")
    
    # Search for all emails
    status, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()[-num_emails:] # Get last N emails
    
    # Initialize Service
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    
    for eid in reversed(email_ids):
        res, msg_data = mail.fetch(eid, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                
                sender = msg.get("From")
                print(f"{Colors.BOLD}Subject: {subject}{Colors.END}")
                print(f"From: {sender}")
                
                # Extract body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        try:
                            if content_type == "text/plain":
                                body += part.get_content()
                            elif content_type == "text/html":
                                soup = BeautifulSoup(part.get_content(), 'html.parser')
                                links = [a.get('href') for a in soup.find_all('a', href=True)]
                                body += " ".join(links)
                        except:
                            pass
                else:
                    body = msg.get_content()
                
                urls = list(set(extract_urls_from_text(body)))
                
                if not urls:
                    print(f"{Colors.GREEN}[SAFE] No links found.{Colors.END}\n")
                    continue
                
                print(f"Found {len(urls)} links. Checking...")
                is_phishing = False
                
                for url in urls:
                    result = service.analyze_url(url)
                    if result['classification'] == 'phishing':
                        is_phishing = True
                        print(f"  {Colors.RED}🚨 PHISHING: {url}{Colors.END}")
                        print(f"     Reason: {result['explanation']}")
                    else:
                        pass # print(f"  {Colors.GREEN}✔ Safe: {url}{Colors.END}")
                
                if is_phishing:
                    print(f"{Colors.RED}🚫 VERDICT: MALICIOUS EMAIL{Colors.END}")
                else:
                    print(f"{Colors.GREEN}✅ VERDICT: SAFE EMAIL{Colors.END}")
                print("-" * 50)

    mail.close()
    mail.logout()

if __name__ == "__main__":
    print(f"{Colors.CYAN}--- AUTOMATED EMAIL PHISHING SCANNER ---{Colors.END}")
    print("Supports Gmail, Outlook, Yahoo, etc.")
    
    server = input("IMAP Server (default: imap.gmail.com): ").strip() or "imap.gmail.com"
    user = input("Email: ").strip()
    pwd = getpass.getpass("Password (App Password recommended): ").strip()
    
    scan_inbox(user, pwd, server)
