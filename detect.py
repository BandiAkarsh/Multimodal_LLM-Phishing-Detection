#!/usr/bin/env python3
"""
Phishing URL Detector - Interactive CLI Tool

Usage:
    python detect.py                     # Interactive mode
    python detect.py https://example.com # Single URL check
    python detect.py --batch urls.txt    # Check multiple URLs from file
"""

import sys
import os
import json

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
        icon = "🚨"
        status = "PHISHING DETECTED"
    else:
        color = Colors.GREEN
        icon = "✅"
        status = "LEGITIMATE"
    
    # Action color
    if action == 'block':
        action_color = Colors.RED
        action_icon = "🛑"
    elif action == 'warn':
        action_color = Colors.YELLOW
        action_icon = "⚠️"
    else:
        action_color = Colors.GREEN
        action_icon = "✓"
    
    print(f"""
{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
{Colors.CYAN}URL:{Colors.END} {url}
{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}

{icon} {color}{Colors.BOLD}Result: {status}{Colors.END}

{Colors.BLUE}Confidence:{Colors.END}  {confidence*100:.1f}%
{Colors.BLUE}Risk Score:{Colors.END}  {risk_score}/100
{action_icon} {action_color}Action:{Colors.END}     {action.upper()}

{Colors.MAGENTA}Analysis:{Colors.END}
{explanation}
""")
    
    # Show typosquatting details if detected
    typo = result['features'].get('typosquatting', {})
    if typo.get('is_typosquatting'):
        method = typo.get('detection_method', 'unknown')
        if method in ['faulty_extension', 'invalid_domain_structure', 'invalid_extension']:
             print(f"""{Colors.RED}{Colors.BOLD}⚠️  INVALID DOMAIN / EXTENSION DETECTED:{Colors.END}
   {typo.get('details', ["Unknown error"])[0]}
""")
        else:
            brand = typo.get('impersonated_brand', 'unknown')
            brand_display = brand.upper() if brand else "UNKNOWN"
            
            print(f"""{Colors.RED}{Colors.BOLD}⚠️  BRAND IMPERSONATION DETECTED:{Colors.END}
   Impersonated Brand: {brand_display}
   Method: {method}
   Similarity: {typo.get('similarity_score', 0)*100:.1f}%
""")

def interactive_mode(service):
    """Run interactive mode for checking URLs."""
    print(f"\n{Colors.YELLOW}Enter URLs to check (type 'quit' or 'exit' to stop):{Colors.END}\n")
    
    while True:
        try:
            url = input(f"{Colors.CYAN}URL> {Colors.END}").strip()
            
            if not url:
                continue
            
            if url.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Colors.GREEN}Goodbye! Stay safe online. 🔒{Colors.END}\n")
                break
            
            # Add https:// if no protocol specified
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Analyze URL
            result = service.analyze_url(url)
            print_result(result)
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.GREEN}Goodbye! Stay safe online. 🔒{Colors.END}\n")
            break
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")

def check_single_url(service, url):
    """Check a single URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = service.analyze_url(url)
    print_result(result)
    return result

def check_batch(service, filename):
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
        
        result = service.analyze_url(url)
        
        if result['classification'] == 'phishing':
            phishing_count += 1
            icon = f"{Colors.RED}🚨 PHISHING{Colors.END}"
        else:
            legitimate_count += 1
            icon = f"{Colors.GREEN}✅ LEGIT{Colors.END}"
        
        print(f"{icon} | {result['confidence']*100:5.1f}% | {url[:60]}")
    
    print(f"""
{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
{Colors.CYAN}Summary:{Colors.END}
  Total URLs:  {len(urls)}
  {Colors.RED}Phishing:{Colors.END}    {phishing_count}
  {Colors.GREEN}Legitimate:{Colors.END}  {legitimate_count}
{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
""")

def main():
    print_banner()
    
    # Initialize service
    print(f"{Colors.YELLOW}Loading ML model...{Colors.END}")
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    print(f"{Colors.GREEN}Model loaded successfully!{Colors.END}")
    
    # Parse arguments
    if len(sys.argv) == 1:
        # No arguments - interactive mode
        interactive_mode(service)
    elif sys.argv[1] == '--batch' and len(sys.argv) == 3:
        # Batch mode
        check_batch(service, sys.argv[2])
    elif sys.argv[1] == '--help' or sys.argv[1] == '-h':
        print(f"""
{Colors.CYAN}Usage:{Colors.END}
    python detect.py                     # Interactive mode
    python detect.py <url>               # Check single URL
    python detect.py --batch <file>      # Check URLs from file
    
{Colors.CYAN}Examples:{Colors.END}
    python detect.py https://paypal.com
    python detect.py paypa1.com
    python detect.py --batch suspicious_urls.txt
""")
    else:
        # Single URL
        url = sys.argv[1]
        check_single_url(service, url)

if __name__ == "__main__":
    main()
