import sys
import os
import re
import email
from email import policy
from email.parser import BytesParser
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
    """Find all URLs in a text string."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def extract_urls_from_eml(file_path):
    """Parse an EML file and extract URLs from body."""
    if not os.path.exists(file_path):
        print(f"{Colors.RED}Error: File {file_path} not found.{Colors.END}")
        return []

    with open(file_path, 'rb') as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    print(f"{Colors.BLUE}Scanning Email Subject: {msg['subject']}{Colors.END}")
    print(f"{Colors.BLUE}From: {msg['from']}{Colors.END}")
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                body += part.get_content()
            elif content_type == "text/html":
                html_content = part.get_content()
                soup = BeautifulSoup(html_content, 'html.parser')
                # Extract href links from <a> tags
                links = [a.get('href') for a in soup.find_all('a', href=True)]
                body += " ".join(links)
                # Also get text content
                body += soup.get_text()
    else:
        body = msg.get_content()

    return list(set(extract_urls_from_text(body)))

def scan_email(file_path):
    print(f"\n{Colors.BOLD}--- 📧 EMAIL SECURITY SCANNER ---{Colors.END}")
    
    # Initialize Service
    print("Initializing Detection Engine...")
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    
    urls = extract_urls_from_eml(file_path)
    
    if not urls:
        print(f"{Colors.GREEN}No URLs found in this email. Safe to open.{Colors.END}")
        return

    print(f"\nFound {len(urls)} links. Analyzing...\n")
    
    phishing_found = False
    
    for url in urls:
        print(f"Checking: {url} ...", end="\r")
        result = service.analyze_url(url)
        
        if result['classification'] == 'phishing':
            phishing_found = True
            print(f"{Colors.RED}[PHISHING] {url}{Colors.END}")
            print(f"   ↳ Reason: {result['explanation']}")
            print(f"   ↳ Risk Score: {result['risk_score']}/100")
        else:
            print(f"{Colors.GREEN}[SAFE]     {url}{Colors.END}")

    print("\n" + "="*50)
    if phishing_found:
        print(f"{Colors.RED}{Colors.BOLD}🚫 DANGER: This email contains PHISHING links!{Colors.END}")
        print(f"{Colors.RED}{Colors.BOLD}   DO NOT CLICK any links in this email.{Colors.END}")
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}✅ CLEAN: No threats detected.{Colors.END}")
    print("="*50 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_email.py <path_to_email.eml>")
    else:
        scan_email(sys.argv[1])
