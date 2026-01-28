#!/usr/bin/env python3
"""
Phishing URL Detector - Interactive CLI Tool

This is the main command-line interface for the phishing detection system.
It supports INTERNET-AWARE detection with 4-CATEGORY CLASSIFICATION:

Classifications:
- LEGITIMATE (Green): Safe website
- PHISHING (Red): Traditional phishing attack
- AI_GENERATED_PHISHING (Orange): AI-created phishing
- PHISHING_KIT (Dark Red): Toolkit-based phishing (Gophish, etc.)
- UNKNOWN (Yellow): Unable to determine (unreachable, error)

Usage:
    python detect.py                     # Interactive mode
    python detect.py <url>               # Check single URL
    python detect.py --batch urls.txt    # Check multiple URLs from file
    python detect.py --offline           # Force offline mode (for testing)
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
sys.path.insert(0, os.path.join(project_root, '05_utils'))

from service import PhishingDetectionService

# Import connectivity checker
try:
    from connectivity import check_internet_connection, get_connectivity_status
except ImportError:
    def check_internet_connection():
        return True
    def get_connectivity_status():
        return {'is_online': True, 'mode': 'online'}


class Colors:
    """Terminal color codes for all classification types."""
    # Basic colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    # Extended colors for 4-category classification
    DARK_RED = '\033[38;5;124m'    # Dark red for PHISHING_KIT
    ORANGE = '\033[38;5;208m'       # Orange for AI_GENERATED
    GRAY = '\033[38;5;245m'         # Gray for UNKNOWN


# Classification display configuration
CLASSIFICATION_CONFIG = {
    'legitimate': {
        'color': Colors.GREEN,
        'icon': 'SAFE',
        'emoji': '(ok)',
        'label': 'LEGITIMATE',
    },
    'phishing': {
        'color': Colors.RED,
        'icon': 'DANGER',
        'emoji': '(!)',
        'label': 'PHISHING DETECTED',
    },
    'ai_generated_phishing': {
        'color': Colors.ORANGE,
        'icon': 'AI-PHISH',
        'emoji': '[AI]',
        'label': 'AI-GENERATED PHISHING',
    },
    'phishing_kit': {
        'color': Colors.DARK_RED,
        'icon': 'TOOLKIT',
        'emoji': '[KIT]',
        'label': 'PHISHING KIT ATTACK',
    },
    'unknown': {
        'color': Colors.YELLOW,
        'icon': 'UNKNOWN',
        'emoji': '(?)',
        'label': 'UNKNOWN / ERROR',
    },
    'error': {
        'color': Colors.GRAY,
        'icon': 'ERROR',
        'emoji': '[ERR]',
        'label': 'ANALYSIS ERROR',
    },
}


def print_banner(is_online: bool = True):
    """Display the application banner with connectivity status."""
    mode_color = Colors.GREEN if is_online else Colors.YELLOW
    mode_text = "ONLINE - Full Analysis" if is_online else "OFFLINE - Static Analysis"
    mode_icon = "[NET]" if is_online else "[OFF]"
    
    print(f"""
{Colors.CYAN}{Colors.BOLD}
+===================================================================+
|                                                                   |
|   PHISHING URL DETECTOR                                           |
|   Multimodal LLM-based Phishing Detection System                  |
|                                                                   |
|   ML Model: Random Forest (99.8% F1 Score)                        |
|   Features: Typosquatting + URL Analysis + Web Scraping           |
|                                                                   |
|   Classification Categories:                                      |
|   {Colors.GREEN}[LEGIT]{Colors.CYAN} Safe     {Colors.RED}[PHISH]{Colors.CYAN} Danger     {Colors.ORANGE}[AI]{Colors.CYAN} AI-Gen     {Colors.DARK_RED}[KIT]{Colors.CYAN} Toolkit   |
|                                                                   |
+-------------------------------------------------------------------+
|   {mode_icon} Mode: {mode_color}{mode_text:^45}{Colors.CYAN}|
+===================================================================+
{Colors.END}""")


def print_result(result):
    """Pretty print the analysis result with proper 4-category display."""
    url = result['url']
    classification = result['classification']
    confidence = result['confidence']
    risk_score = result['risk_score']
    explanation = result['explanation']
    action = result['recommended_action']
    analysis_mode = result.get('analysis_mode', 'unknown')
    
    # Get classification config
    config = CLASSIFICATION_CONFIG.get(classification, CLASSIFICATION_CONFIG['unknown'])
    color = config['color']
    icon = config['icon']
    emoji = config['emoji']
    label = config['label']
    
    # Action color
    if action == 'block':
        action_color = Colors.RED
    elif action == 'warn':
        action_color = Colors.YELLOW
    else:
        action_color = Colors.GREEN
    
    # Analysis mode indicator
    mode_indicators = {
        'online': f"{Colors.GREEN}[ONLINE]{Colors.END}",
        'offline': f"{Colors.YELLOW}[OFFLINE]{Colors.END}",
        'online_failed': f"{Colors.YELLOW}[SCRAPE FAILED]{Colors.END}",
        'whitelist': f"{Colors.BLUE}[WHITELISTED]{Colors.END}",
    }
    mode_indicator = mode_indicators.get(analysis_mode, f"{Colors.GRAY}[UNKNOWN]{Colors.END}")
    
    print(f"""
{Colors.BOLD}================================================================={Colors.END}
{Colors.CYAN}URL:{Colors.END} {url}
{Colors.CYAN}Analysis Mode:{Colors.END} {mode_indicator}
{Colors.BOLD}================================================================={Colors.END}

{color}{Colors.BOLD}{emoji} {label}{Colors.END}

{Colors.BLUE}Confidence:{Colors.END}  {confidence*100:.1f}%
{Colors.BLUE}Risk Score:{Colors.END}  {risk_score}/100
{action_color}Action:{Colors.END}      {action.upper()}

{Colors.MAGENTA}Analysis:{Colors.END}
{explanation}
""")
    
    # Show scrape info
    if result.get('scraped'):
        print(f"{Colors.GREEN}[INFO] Successfully scraped webpage content.{Colors.END}")
        proof = result.get('scrape_proof')
        if proof:
            print(f"   {Colors.BLUE}Title:{Colors.END} {proof.get('title', 'N/A')[:60]}")
            print(f"   {Colors.BLUE}Size:{Colors.END} {proof.get('html_size_bytes', 0)} bytes")
            print(f"   {Colors.BLUE}Links:{Colors.END} {proof.get('num_links', 0)}")
            print(f"   {Colors.BLUE}Forms:{Colors.END} {proof.get('num_forms', 0)}")
            
            # Show toolkit detection
            if proof.get('toolkit_detected'):
                print(f"   {Colors.DARK_RED}Toolkit:{Colors.END} {proof.get('toolkit_name', 'Unknown')}")
    elif analysis_mode == 'online_failed':
        print(f"{Colors.YELLOW}[WARNING] Could not reach website.{Colors.END}")
    
    # Show AI indicators
    if result.get('ai_indicators'):
        print(f"{Colors.ORANGE}[AI DETECTION] Found AI-generated content patterns:{Colors.END}")
        for indicator in result['ai_indicators'][:3]:
            print(f"   - {indicator}")
    
    # Show toolkit signatures
    if result.get('toolkit_signatures', {}).get('detected'):
        sigs = result['toolkit_signatures']
        print(f"{Colors.DARK_RED}[TOOLKIT DETECTION] {sigs.get('toolkit_name', 'Unknown')} detected:{Colors.END}")
        for sig in sigs.get('signatures_found', [])[:3]:
            print(f"   - {sig}")
    
    # Show typosquatting details
    typo = result['features'].get('typosquatting', {})
    if typo.get('is_typosquatting'):
        method = typo.get('detection_method', 'unknown')
        if method in ['faulty_extension', 'invalid_domain_structure', 'invalid_extension']:
            print(f"""{Colors.RED}{Colors.BOLD}[!] INVALID DOMAIN / EXTENSION DETECTED:{Colors.END}
   {typo.get('details', ["Unknown error"])[0]}
""")
        elif not typo.get('content_verified'):
            brand = typo.get('impersonated_brand', 'unknown')
            brand_display = brand.upper() if brand else "UNKNOWN"
            
            print(f"""{Colors.RED}{Colors.BOLD}[!] BRAND IMPERSONATION DETECTED:{Colors.END}
   Impersonated Brand: {brand_display}
   Method: {method}
   Similarity: {typo.get('similarity_score', 0)*100:.1f}%
""")
        else:
            print(f"{Colors.GREEN}[VERIFIED] Content verification passed:{Colors.END}")
            print(f"   {typo.get('verification_reason', 'Legitimate content detected')}")


async def check_single_url(service, url, force_scraping=True):
    """Check a single URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"\n{Colors.CYAN}Analyzing {url}...{Colors.END}")
    
    result = await service.analyze_url_async(url, force_mllm=force_scraping)
    print_result(result)
    return result


async def interactive_mode(service, is_online: bool = True):
    """Run interactive mode for checking URLs."""
    if is_online:
        print(f"\n{Colors.GREEN}[ONLINE MODE] Full web scraping analysis enabled.{Colors.END}")
        print(f"{Colors.GREEN}URLs will be scraped and analyzed for actual content.{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}[OFFLINE MODE] Static URL analysis only.{Colors.END}")
        print(f"{Colors.YELLOW}Using heuristics (entropy, patterns) - less accurate.{Colors.END}")
    
    print(f"\n{Colors.YELLOW}Enter URLs to check (type 'quit' or 'exit' to stop):{Colors.END}\n")
    
    while True:
        try:
            url = input(f"{Colors.CYAN}URL > {Colors.END}").strip()
            
            if not url:
                continue
            
            if url.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Colors.GREEN}Session terminated.{Colors.END}\n")
                break
            
            if url.lower() == 'refresh':
                new_status = service.refresh_connectivity()
                if new_status:
                    print(f"{Colors.GREEN}[ONLINE] Internet connection restored!{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}[OFFLINE] Still no internet connection.{Colors.END}")
                continue
            
            await check_single_url(service, url, force_scraping=is_online)
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.GREEN}Session terminated.{Colors.END}\n")
            break
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")


async def check_batch(service, filename, is_online: bool = True):
    """Check multiple URLs from a file."""
    if not os.path.exists(filename):
        print(f"{Colors.RED}Error: File '{filename}' not found{Colors.END}")
        return
    
    with open(filename, 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    mode_text = "ONLINE (Full Analysis)" if is_online else "OFFLINE (Static Analysis)"
    print(f"\n{Colors.CYAN}Checking {len(urls)} URLs in {mode_text} mode...{Colors.END}\n")
    
    # Counters for all 4 categories
    counts = {
        'legitimate': 0,
        'phishing': 0,
        'ai_generated_phishing': 0,
        'phishing_kit': 0,
        'unknown': 0,
    }
    results = []
    
    for i, url in enumerate(urls, 1):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"[{i}/{len(urls)}] Scanning {url[:50]}...", end="\r")
        
        try:
            result = await service.analyze_url_async(url, force_mllm=is_online)
            results.append(result)
            
            classification = result['classification']
            counts[classification] = counts.get(classification, 0) + 1
            
            config = CLASSIFICATION_CONFIG.get(classification, CLASSIFICATION_CONFIG['unknown'])
            icon = f"{config['color']}[{config['icon'][:5]:^5}]{Colors.END}"
            
            mode = result.get('analysis_mode', '?')[:3].upper()
            print(f"{icon} [{mode}] | {result['confidence']*100:5.1f}% | {url[:55]}")
        except Exception as e:
            print(f"{Colors.GRAY}[ERROR]{Colors.END}         | {url[:55]} - {e}")
            counts['unknown'] = counts.get('unknown', 0) + 1
    
    print(f"""
{Colors.BOLD}================================================================={Colors.END}
{Colors.CYAN}Summary:{Colors.END}
  Total URLs:          {len(urls)}
  {Colors.GREEN}Legitimate:{Colors.END}         {counts.get('legitimate', 0)}
  {Colors.RED}Phishing:{Colors.END}           {counts.get('phishing', 0)}
  {Colors.ORANGE}AI-Generated:{Colors.END}       {counts.get('ai_generated_phishing', 0)}
  {Colors.DARK_RED}Phishing Kit:{Colors.END}       {counts.get('phishing_kit', 0)}
  {Colors.YELLOW}Unknown/Error:{Colors.END}      {counts.get('unknown', 0)}
  Analysis Mode:       {mode_text}
{Colors.BOLD}================================================================={Colors.END}
""")


async def main():
    parser = argparse.ArgumentParser(
        description="Phishing URL Detector - Internet-Aware Detection System with 4-Category Classification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detect.py                          # Interactive mode
  python detect.py https://example.com      # Check single URL
  python detect.py --batch urls.txt         # Check multiple URLs
  python detect.py --offline                # Force offline mode

Classifications:
  LEGITIMATE           - Safe website (Green)
  PHISHING             - Traditional phishing (Red)
  AI_GENERATED_PHISHING - AI-created phishing (Orange)
  PHISHING_KIT         - Toolkit attack (Dark Red)
  UNKNOWN              - Unable to determine (Yellow)
        """
    )
    parser.add_argument("url", nargs="?", help="URL to check")
    parser.add_argument("--batch", help="Batch process a file of URLs")
    parser.add_argument("--offline", action="store_true", 
                        help="Force offline mode (static analysis only)")
    parser.add_argument("--no-scrape", action="store_true",
                        help="Disable web scraping even if online")
    
    args = parser.parse_args()
    
    # Check internet connectivity
    if args.offline:
        is_online = False
        print(f"{Colors.YELLOW}[FORCED OFFLINE MODE]{Colors.END}")
    else:
        print(f"{Colors.CYAN}Checking internet connection...{Colors.END}", end=" ")
        is_online = check_internet_connection()
        if is_online:
            print(f"{Colors.GREEN}Connected!{Colors.END}")
        else:
            print(f"{Colors.YELLOW}No connection - using offline mode{Colors.END}")
    
    # Print banner
    print_banner(is_online)
    
    # Initialize service
    print(f"{Colors.YELLOW}Loading ML model...{Colors.END}")
    service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
    
    # Override connectivity if forced offline
    if args.offline:
        service._is_online = False
    
    print(f"{Colors.GREEN}Model loaded successfully!{Colors.END}")
    
    # Determine scraping mode
    use_scraping = is_online and not args.no_scrape
    
    if args.batch:
        await check_batch(service, args.batch, is_online=use_scraping)
    elif args.url:
        await check_single_url(service, args.url, force_scraping=use_scraping)
    else:
        await interactive_mode(service, is_online=use_scraping)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}Goodbye!{Colors.END}")
