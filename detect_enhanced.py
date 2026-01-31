#!/usr/bin/env python3
"""
Phishing Guard CLI - Enhanced Command Line Interface

Features:
- Colored output for better readability
- Progress bars for batch operations
- JSON export capabilities
- Interactive prompts
- Rich formatting

Usage:
    python detect.py <url>              # Scan single URL
    python detect.py --file urls.txt    # Scan multiple URLs from file
    python detect.py --json             # Output as JSON
    python detect.py --batch urls.txt --output results.json

Author: Phishing Guard Team
Version: 2.0.0
"""

import sys
import os
import json
import argparse
import asyncio
from pathlib import Path
from typing import List, Dict, Any

# Add project paths
sys.path.insert(0, '04_inference')
sys.path.insert(0, '05_utils')

from colorama import init, Fore, Back, Style
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Import detection service
try:
    from service import PhishingDetectionService
    from connectivity import check_internet_connection
except ImportError as e:
    print(f"{Fore.RED}Error: Could not import required modules: {e}{Style.RESET_ALL}")
    sys.exit(1)


class Colors:
    """Color constants for terminal output"""
    HEADER = Fore.CYAN + Style.BRIGHT
    SUCCESS = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    INFO = Fore.BLUE + Style.BRIGHT
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM


class PhishingGuardCLI:
    """Enhanced CLI for Phishing Guard"""
    
    def __init__(self):
        self.service = None
        self.is_online = check_internet_connection()
        
    def initialize_service(self, load_mllm: bool = False):
        """Initialize the detection service with progress indicator"""
        print(f"{Colors.HEADER}🚀 Initializing Phishing Guard...{Colors.RESET}")
        
        with tqdm(total=100, desc="Loading models", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            self.service = PhishingDetectionService(load_mllm=load_mllm, load_ml_model=True)
            pbar.update(100)
        
        mode = "online" if self.is_online else "offline"
        print(f"{Colors.SUCCESS}✓ Service ready ({mode} mode){Colors.RESET}\n")
    
    def print_banner(self):
        """Print CLI banner"""
        banner = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║                    🔒 PHISHING GUARD v2.0                     ║
║              AI-Powered Phishing Detection                    ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
    
    def format_result(self, result: Dict[str, Any], compact: bool = False) -> str:
        """Format detection result for display"""
        classification = result.get('classification', 'unknown')
        confidence = result.get('confidence', 0)
        risk_score = result.get('risk_score', 0)
        url = result.get('url', 'unknown')
        
        # Determine color based on classification
        if classification == 'legitimate':
            color = Colors.SUCCESS
            icon = "✓"
        elif classification == 'ai_generated_phishing':
            color = Colors.WARNING
            icon = "⚠"
        elif classification == 'phishing':
            color = Colors.ERROR
            icon = "✗"
        elif classification == 'phishing_kit':
            color = Colors.ERROR
            icon = "🚨"
        else:
            color = Colors.INFO
            icon = "?"
        
        if compact:
            return f"{color}{icon} {classification.upper():20} | Risk: {risk_score:3}/100 | {url[:50]}...{Colors.RESET}"
        
        # Full format
        output = f"""
{Colors.BOLD}URL:{Colors.RESET} {url}
{color}{icon} Classification: {classification.upper()}{Colors.RESET}
{Colors.INFO}Confidence:{Colors.RESET} {confidence:.1%}
{Colors.INFO}Risk Score:{Colors.RESET} {risk_score}/100
"""
        
        if 'explanation' in result:
            output += f"{Colors.DIM}Explanation: {result['explanation']}{Colors.RESET}\n"
        
        if 'features' in result and result['features']:
            output += f"{Colors.DIM}Features analyzed: {len(result['features'])}{Colors.RESET}\n"
        
        return output
    
    def scan_single(self, url: str, verbose: bool = False) -> Dict[str, Any]:
        """Scan a single URL"""
        if not self.service:
            self.initialize_service()
        
        print(f"{Colors.INFO}🔍 Scanning: {url}{Colors.RESET}")
        
        try:
            result = asyncio.run(self.service.analyze_url_async(url))
            print(self.format_result(result, compact=not verbose))
            return result
        except Exception as e:
            print(f"{Colors.ERROR}✗ Error scanning URL: {e}{Colors.RESET}")
            return {'error': str(e), 'url': url}
    
    def scan_batch(self, urls: List[str], output_file: str = None) -> List[Dict[str, Any]]:
        """Scan multiple URLs with progress bar"""
        if not self.service:
            self.initialize_service()
        
        print(f"{Colors.HEADER}📊 Batch Scan: {len(urls)} URLs{Colors.RESET}\n")
        
        results = []
        stats = {
            'legitimate': 0,
            'phishing': 0,
            'ai_generated_phishing': 0,
            'phishing_kit': 0,
            'errors': 0
        }
        
        # Process with progress bar
        with tqdm(total=len(urls), desc="Scanning URLs", unit="url") as pbar:
            for url in urls:
                try:
                    result = asyncio.run(self.service.analyze_url_async(url))
                    results.append(result)
                    
                    # Update stats
                    classification = result.get('classification', 'unknown')
                    if classification in stats:
                        stats[classification] += 1
                    
                    # Show result inline
                    pbar.write(self.format_result(result, compact=True))
                    
                except Exception as e:
                    error_result = {'error': str(e), 'url': url, 'classification': 'error'}
                    results.append(error_result)
                    stats['errors'] += 1
                    pbar.write(f"{Colors.ERROR}✗ Error: {url} - {e}{Colors.RESET}")
                
                pbar.update(1)
        
        # Print summary
        print(f"\n{Colors.HEADER}📈 Scan Summary:{Colors.RESET}")
        print(f"  {Colors.SUCCESS}✓ Legitimate: {stats['legitimate']}{Colors.RESET}")
        print(f"  {Colors.WARNING}⚠ AI Phishing: {stats['ai_generated_phishing']}{Colors.RESET}")
        print(f"  {Colors.ERROR}✗ Phishing: {stats['phishing']}{Colors.RESET}")
        print(f"  {Colors.ERROR}🚨 Phishing Kit: {stats['phishing_kit']}{Colors.RESET}")
        if stats['errors'] > 0:
            print(f"  {Colors.ERROR}✗ Errors: {stats['errors']}{Colors.RESET}")
        print(f"  {Colors.INFO}📊 Total: {len(urls)}{Colors.RESET}")
        
        # Save to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump({
                    'scan_date': str(datetime.now()),
                    'total_urls': len(urls),
                    'statistics': stats,
                    'results': results
                }, f, indent=2)
            print(f"\n{Colors.SUCCESS}✓ Results saved to: {output_file}{Colors.RESET}")
        
        return results
    
    def interactive_mode(self):
        """Interactive CLI mode"""
        self.print_banner()
        self.initialize_service()
        
        print(f"{Colors.INFO}Interactive mode started. Type 'quit' to exit.{Colors.RESET}\n")
        
        while True:
            try:
                url = input(f"{Colors.BOLD}Enter URL to scan: {Colors.RESET}").strip()
                
                if url.lower() in ['quit', 'exit', 'q']:
                    print(f"\n{Colors.SUCCESS}👋 Goodbye!{Colors.RESET}")
                    break
                
                if not url:
                    continue
                
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                self.scan_single(url, verbose=True)
                print()
                
            except KeyboardInterrupt:
                print(f"\n\n{Colors.SUCCESS}👋 Goodbye!{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.ERROR}Error: {e}{Colors.RESET}\n")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Phishing Guard - AI-Powered Phishing Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com                    # Scan single URL
  %(prog)s --file urls.txt                        # Scan URLs from file
  %(prog)s --batch urls.txt --output results.json # Batch scan with JSON output
  %(prog)s --interactive                          # Interactive mode
  %(prog)s --json https://example.com             # Output as JSON
        """
    )
    
    parser.add_argument('url', nargs='?', help='URL to scan')
    parser.add_argument('--file', '-f', help='File containing URLs to scan (one per line)')
    parser.add_argument('--batch', '-b', help='Batch scan mode with file')
    parser.add_argument('--output', '-o', help='Output file for batch results (JSON)')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--mllm', action='store_true', help='Enable MLLM (slower but more accurate)')
    
    args = parser.parse_args()
    
    cli = PhishingGuardCLI()
    
    # Interactive mode
    if args.interactive:
        cli.interactive_mode()
        return
    
    # Single URL scan
    if args.url:
        cli.initialize_service(load_mllm=args.mllm)
        result = cli.scan_single(args.url, verbose=args.verbose)
        
        if args.json:
            print(json.dumps(result, indent=2))
        return
    
    # Batch scan from file
    if args.file or args.batch:
        input_file = args.file or args.batch
        
        if not os.path.exists(input_file):
            print(f"{Colors.ERROR}Error: File not found: {input_file}{Colors.RESET}")
            sys.exit(1)
        
        # Read URLs from file
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not urls:
            print(f"{Colors.ERROR}Error: No URLs found in file{Colors.RESET}")
            sys.exit(1)
        
        results = cli.scan_batch(urls, output_file=args.output)
        
        if args.json and not args.output:
            print(json.dumps(results, indent=2))
        return
    
    # No arguments - show help
    parser.print_help()
    print(f"\n{Colors.INFO}Tip: Use --interactive for an interactive session{Colors.RESET}")


if __name__ == '__main__':
    from datetime import datetime
    main()
