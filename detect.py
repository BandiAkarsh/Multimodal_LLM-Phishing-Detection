#!/usr/bin/env python3
"""
Phishing URL Detector - Interactive CLI Tool

Usage:
    python detect.py                     # Interactive mode (Full Scan)
    python detect.py --fast              # Interactive mode (Fast Scan)
    python detect.py <url>               # Check single URL
    python detect.py --fast <url>        # Check single URL (Fast Scan)
    python detect.py --batch urls.txt    # Check multiple URLs from file
"""

import sys
import os
import json
import asyncio
import argparse

# Add project paths
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, '04_inference'))

from service import PhishingDetectionService

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔒 PHISHING URL DETECTOR                                    ║
║   Multimodal LLM-based Phishing Detection System              ║
║                                                               ║
║   ML Model: Random Forest (99.8% F1 Score)                    ║
║   Features: Typosquatting + URL Analysis + ML Classification  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}""")

def print_result(result):
    """Pretty print the analysis result."""
    url = result['url']
    classification = result['classification']
    confidence = result['confidence']
    risk_score = result['risk_score']
    explanation = result['explanation']
    action = result['recommended_action']
    
    # Color based on classification
    if classification == 'phishing':
        color = Colors.RED
        status = "PHISHING DETECTED"
    else:
        color = Colors.GREEN
        status = "LEGITIMATE"
    
    # Action color
    if action == 'block':
        action_color = Colors.RED
    elif action == 'warn':
        action_color = Colors.YELLOW
    else:
        action_color = Colors.GREEN
    
    print(f"""
{Colors.BOLD}================================================================={Colors.END}
{Colors.CYAN}URL:{Colors.END} {url}
{Colors.BOLD}================================================================={Colors.END}

{color}{Colors.BOLD}[RESULT] {status}{Colors.END}

{Colors.BLUE}Confidence:{Colors.END}  {confidence*100:.1f}%
{Colors.BLUE}Risk Score:{Colors.END}  {risk_score}/100
{action_color}Action:{Colors.END}      {action.upper()}

{Colors.MAGENTA}Analysis:{Colors.END}
{explanation}
""")
    
    if result.get('scraped'):
        print(f"{Colors.GREEN}[INFO] Successfully scraped webpage content.{Colors.END}")
        proof = result.get('scrape_proof')
        if proof:
            print(f"   {Colors.BLUE}Title:{Colors.END} {proof.get('title')}")
            print(f"   {Colors.BLUE}Size:{Colors.END} {proof.get('html_size_bytes')} bytes")
            print(f"   {Colors.BLUE}Resolution:{Colors.END} {proof.get('screenshot_size')}")
    
    # Show typosquatting details if detected
    typo = result['features'].get('typosquatting', {})
    if typo.get('is_typosquatting'):
        method = typo.get('detection_method', 'unknown')
        if method in ['faulty_extension', 'invalid_domain_structure', 'invalid_extension']:
             print(f"""{Colors.RED}{Colors.BOLD}[!] INVALID DOMAIN / EXTENSION DETECTED:{Colors.END}
   {typo.get('details', ["Unknown error"])[0]}
""")
        else:
            brand = typo.get('impersonated_brand', 'unknown')
            brand_display = brand.upper() if brand else "UNKNOWN"
            
            print(f"""{Colors.RED}{Colors.BOLD}[!] BRAND IMPERSONATION DETECTED:{Colors.END}
   Impersonated Brand: {brand_display}
   Method: {method}
   Similarity: {typo.get('similarity_score', 0)*100:.1f}%
""")

async def check_single_url(service, url, force_mllm=False):
    """Check a single URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"Scanning {url}...")
    # Call the async version which supports scraping
    result = await service.analyze_url_async(url, force_mllm=force_mllm)
    print_result(result)
    return result

async def interactive_mode(service, force_mllm=False):
    """Run interactive mode for checking URLs."""
    print(f"\n{Colors.YELLOW}Enter URLs to check (type 'quit' or 'exit' to stop):{Colors.END}")
    if force_mllm:
        print(f"{Colors.MAGENTA}[Full Scan Mode Enabled - Scraping Active]{Colors.END}\n")
    else:
        print(f"{Colors.BLUE}[Fast Scan Mode - URL Analysis Only]{Colors.END}\n")
    
    while True:
        try:
            url = input(f"{Colors.CYAN}URL > {Colors.END}").strip()
            
            if not url:
                continue
            
            if url.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Colors.GREEN}Terminating session.{Colors.END}\n")
                break
            
            await check_single_url(service, url, force_mllm)
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.GREEN}Terminating session.{Colors.END}\n")
            break
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")

async def check_batch(service, filename, force_mllm=False):
    """Check multiple URLs from a file."""
    if not os.path.exists(filename):
        print(f"{Colors.RED}Error: File '{filename}' not found{Colors.END}")
        return
    
    with open(filename, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(f"\n{Colors.CYAN}Checking {len(urls)} URLs...{Colors.END}\n")
    
    phishing_count = 0
    legitimate_count = 0
    
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        result = await service.analyze_url_async(url, force_mllm=force_mllm)
        
        if result['classification'] == 'phishing':
            phishing_count += 1
            icon = f"{Colors.RED}[PHISHING]{Colors.END}"
        else:
            legitimate_count += 1
            icon = f"{Colors.GREEN}[LEGIT]{Colors.END}"
        
        print(f"{icon} | {result['confidence']*100:5.1f}% | {url[:60]}")
    
    print(f"""
{Colors.BOLD}================================================================={Colors.END}
{Colors.CYAN}Summary:{Colors.END}
  Total URLs:  {len(urls)}
  {Colors.RED}Phishing:{Colors.END}    {phishing_count}
  {Colors.GREEN}Legitimate:{Colors.END}  {legitimate_count}
{Colors.BOLD}================================================================={Colors.END}
""")

async def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Phishing URL Detector")
    parser.add_argument("url", nargs="?", help="URL to check")
    parser.add_argument("--fast", action="store_true", help="Disable scraping (Fast Mode)")
    parser.add_argument("--batch", help="Batch process a file of URLs")
    
    args = parser.parse_args()
    
    # By default, use FULL scan (scraping enabled) unless --fast is specified
    use_scraping = not args.fast
    
    print(f"{Colors.YELLOW}Loading ML model...{Colors.END}")
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    print(f"{Colors.GREEN}Model loaded successfully!{Colors.END}")
    
    if args.batch:
        await check_batch(service, args.batch, force_mllm=use_scraping)
    elif args.url:
        await check_single_url(service, args.url, force_mllm=use_scraping)
    else:
        await interactive_mode(service, force_mllm=use_scraping)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass