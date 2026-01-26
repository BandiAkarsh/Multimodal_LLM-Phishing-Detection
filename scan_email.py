#!/usr/bin/env python3
"""
Email File Scanner - Analyze .eml files for phishing URLs

This script scans email files (.eml format) for embedded URLs and
checks each one for phishing indicators.

Features:
- INTERNET-AWARE: Uses web scraping when online, static analysis when offline
- Parses both plain text and HTML email content
- Extracts URLs from href attributes and plain text
- Provides clear warnings for dangerous emails

Usage:
    python scan_email.py <path_to_email.eml>
    python scan_email.py --offline sample.eml  # Force offline mode
"""

import sys
import os
import re
import email
import asyncio
import argparse
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

# Add project paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '04_inference'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '05_utils'))

from service import PhishingDetectionService

# Import connectivity checker
try:
    from connectivity import check_internet_connection
except ImportError:
    def check_internet_connection():
        return True

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
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
        return [], None

    with open(file_path, 'rb') as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    email_info = {
        'subject': msg['subject'],
        'from': msg['from'],
        'to': msg['to'],
        'date': msg['date']
    }
    
    print(f"\n{Colors.BOLD}📧 EMAIL DETAILS{Colors.END}")
    print(f"{Colors.BLUE}Subject:{Colors.END} {email_info['subject']}")
    print(f"{Colors.BLUE}From:{Colors.END} {email_info['from']}")
    print(f"{Colors.BLUE}To:{Colors.END} {email_info['to']}")
    print(f"{Colors.BLUE}Date:{Colors.END} {email_info['date']}")
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body += part.get_content()
                except:
                    pass
            elif content_type == "text/html":
                try:
                    html_content = part.get_content()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    # Extract href links from <a> tags
                    links = [a.get('href') for a in soup.find_all('a', href=True)]
                    body += " ".join(filter(None, links))
                    # Also get text content
                    body += " " + soup.get_text()
                except:
                    pass
    else:
        try:
            body = msg.get_content()
        except:
            body = ""

    urls = list(set(extract_urls_from_text(body)))
    # Filter out common safe/tracking URLs
    urls = [u for u in urls if not any(x in u.lower() for x in ['unsubscribe', 'mailto:', 'tel:'])]
    
    return urls, email_info

async def scan_email_async(file_path, force_offline=False):
    """Scan an email file for phishing URLs (async version)."""
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}📧 EMAIL SECURITY SCANNER{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    
    # Check connectivity
    if force_offline:
        is_online = False
        print(f"{Colors.YELLOW}[FORCED OFFLINE MODE]{Colors.END}")
    else:
        print(f"{Colors.CYAN}Checking internet connection...{Colors.END}", end=" ")
        is_online = check_internet_connection()
        if is_online:
            print(f"{Colors.GREEN}Online - Full analysis enabled{Colors.END}")
        else:
            print(f"{Colors.YELLOW}Offline - Using static analysis{Colors.END}")
    
    # Initialize Service
    print(f"{Colors.CYAN}Loading detection engine...{Colors.END}")
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    
    if force_offline:
        service._is_online = False
    
    # Extract URLs
    urls, email_info = extract_urls_from_eml(file_path)
    
    if not urls:
        print(f"\n{Colors.GREEN}✅ No URLs found in this email. Safe to open.{Colors.END}")
        return
    
    print(f"\n{Colors.CYAN}Found {len(urls)} links. Analyzing...{Colors.END}\n")
    print("-" * 60)
    
    phishing_urls = []
    safe_urls = []
    
    for url in urls:
        # Skip very short URLs or obvious non-URLs
        if len(url) < 10:
            continue
            
        print(f"Scanning: {url[:50]}...", end="\r")
        
        try:
            result = await service.analyze_url_async(url, force_mllm=is_online)
            
            mode = result.get('analysis_mode', '?')[:3].upper()
            
            if result['classification'] == 'phishing':
                phishing_urls.append((url, result))
                print(f"{Colors.RED}[PHISHING]{Colors.END} [{mode}] {url[:55]}")
                print(f"   {Colors.YELLOW}Risk:{Colors.END} {result['risk_score']}/100 | {result['explanation'][:60]}...")
            else:
                safe_urls.append((url, result))
                print(f"{Colors.GREEN}[SAFE]{Colors.END}     [{mode}] {url[:55]}")
        except Exception as e:
            print(f"{Colors.YELLOW}[ERROR]{Colors.END}    {url[:50]} - {e}")
    
    # Summary
    print("\n" + "=" * 60)
    
    if phishing_urls:
        print(f"""
{Colors.RED}{Colors.BOLD}⚠️  DANGER: This email contains {len(phishing_urls)} PHISHING link(s)!{Colors.END}

{Colors.RED}{Colors.BOLD}DO NOT CLICK any links in this email.{Colors.END}
{Colors.YELLOW}Consider reporting this email as phishing.{Colors.END}

{Colors.BOLD}Dangerous URLs:{Colors.END}""")
        for url, result in phishing_urls:
            print(f"  • {url[:60]}")
            if result['features'].get('typosquatting', {}).get('is_typosquatting'):
                brand = result['features']['typosquatting'].get('impersonated_brand', 'Unknown')
                print(f"    {Colors.RED}↳ Impersonates: {brand.upper()}{Colors.END}")
    else:
        print(f"""
{Colors.GREEN}{Colors.BOLD}✅ CLEAN: No phishing threats detected.{Colors.END}

All {len(safe_urls)} link(s) appear to be safe.
""")
    
    print("=" * 60 + "\n")

def scan_email(file_path, force_offline=False):
    """Wrapper for async scan function."""
    asyncio.run(scan_email_async(file_path, force_offline))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan email files for phishing URLs")
    parser.add_argument("file", help="Path to .eml file")
    parser.add_argument("--offline", action="store_true", help="Force offline mode")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"{Colors.RED}Error: File '{args.file}' not found{Colors.END}")
        sys.exit(1)
    
    scan_email(args.file, force_offline=args.offline)
