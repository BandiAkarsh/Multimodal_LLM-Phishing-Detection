#!/usr/bin/env python3
"""
===============================================================================
  PHISHING DETECTION SYSTEM - FINAL YEAR PROJECT DEMONSTRATION
===============================================================================

An interactive demonstration showcasing the detection mechanism step-by-step.
Perfect for project viva, stakeholder demos, and educational presentations.

Features:
- Step-by-step analysis explanation
- Feature extraction visualization
- Classification reasoning
- Colored output for clarity
- Works online or offline

Author: Phishing Guard Team
Version: 2.0.0 (Security Hardened)
"""

import os
import sys
import time
from datetime import datetime
from typing import Any, Dict

# Dynamic path resolution
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "04_inference"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "05_utils"))

# Color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    DIM = "\033[2m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

def print_header(text: str, color: str = Colors.BRIGHT_BLUE):
    """Print a section header."""
    print(f"\n{color}{'='*80}")
    print(f"  {text}")
    print(f"{'='*80}{Colors.RESET}\n")

def print_step(step: str, description: str):
    """Print a numbered step."""
    print(f"{Colors.BOLD}[STEP]{Colors.RESET} {step}")
    print(f"{Colors.CYAN}{description}{Colors.RESET}")
    print()

def print_substep(text: str):
    """Print a substep with indentation."""
    print(f"  {Colors.YELLOW}→{Colors.RESET} {text}")

def print_success(text: str):
    """Print success message."""
    print(f"  {Colors.GREEN}✓{Colors.RESET} {text}")

def print_warning(text: str):
    """Print warning message."""
    print(f"  {Colors.YELLOW}⚠{Colors.RESET} {text}")

def print_error(text: str):
    """Print error message."""
    print(f"  {Colors.RED}✗{Colors.RESET} {text}")

def print_highlight(text: str, value: Any = None):
    """Print a key-value pair."""
    if value is not None:
        print(f"  {Colors.BOLD}{text}:{Colors.RESET} {Colors.WHITE}{value}{Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}{text}{Colors.RESET}")

def draw_risk_meter(risk_score: float) -> str:
    """Draw a visual risk meter."""
    blocks = "█" * int(risk_score // 10) + "░" * (10 - int(risk_score // 10))
    if risk_score >= 70:
        color = Colors.BRIGHT_RED
    elif risk_score >= 40:
        color = Colors.BRIGHT_YELLOW
    else:
        color = Colors.BRIGHT_GREEN
    return f"{color}[{blocks}]{Colors.RESET} {risk_score:.1f}%"

def draw_confidence_bar(confidence: float) -> str:
    """Draw a confidence bar."""
    bars = "▓" * int(confidence * 10)
    spaces = "░" * (10 - int(confidence * 10))
    return f"{Colors.BRIGHT_CYAN}[{bars}{spaces}]{Colors.RESET} {confidence*100:.1f}%"

def print_dict_box(data: Dict[str, Any], title: str = None):
    """Print a dictionary in a box."""
    if title:
        print(f"\n{Colors.BRIGHT_MAGENTA}┌─ {title}{Colors.RESET}")
    for key, value in data.items():
        if isinstance(value, (int, float)) and key.lower() in ("confidence", "risk_score", "score"):
            print(f"  {Colors.BOLD}{key}:{Colors.RESET} {value*100:.2f}%" if "confidence" in key.lower() else f"  {Colors.BOLD}{key}:{Colors.RESET} {value}")
        else:
            print(f"  {Colors.BOLD}{key}:{Colors.RESET} {value}")
    print()

def format_seconds(seconds: float) -> str:
    """Format seconds into human readable time."""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    return f"{seconds:.2f}s"

class FinalYearDemo:
    """Final Year Project Demonstration Interface."""
    
    def __init__(self):
        self.service = None
        self.is_online = True
        print(f"\n{Colors.BRIGHT_CYAN}Phishing Detection System - Final Year Project Demo{Colors.RESET}")
        print(f"{Colors.CYAN}Security Hardened • 4-Category Classification • 93 Features{Colors.RESET}")
        print(f"{Colors.DIM}{'─'*80}{Colors.RESET}\n")
    
    def initialize(self):
        """Initialize the detection service."""
        print_step("INITIALIZATION", "Loading the Phishing Detection Engine...")
        
        try:
            from service import PhishingDetectionService
            print_substep("Importing service modules...")
            # Initialize service (auto-detects online/offline)
            self.service = PhishingDetectionService(load_ml_model=True, load_mllm=False)
            print_success("Service loaded successfully")
            
            # Check connectivity status
            import socket
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=2)
                self.is_online = True
                print_highlight("Internet Status", "ONLINE - Full 4-category classification available")
            except:
                self.is_online = False
                print_warning("Internet Status", "OFFLINE - Limited to LEGITIMATE/PHISHING (content analysis disabled)")
            
            print()
            return True
            
        except ImportError as e:
            print_error(f"Failed to import service modules: {e}")
            print("  Make sure you're running from the project root directory.")
            return False
        except Exception as e:
            print_error(f"Service initialization failed: {e}")
            return False
    
    def display_banner(self, url: str):
        """Display analysis banner."""
        print(f"{Colors.BRIGHT_WHITE}╔{'═'*78}╗")
        print(f"║{' '*78}║")
        print(f"║{'ANALYZING URL':^78}║")
        print(f"║{' '*78}║")
        print(f"║{url:<78}║")
        print(f"║{' '*78}║")
        print(f"╚{'═'*78}╝{Colors.RESET}")
        print()
    
    def run_analysis(self, url: str) -> Dict[str, Any]:
        """Run complete analysis with step-by-step explanation."""
        
        start_time = time.time()
        self.display_banner(url)
        
        try:
            # Run the analysis
            print_step("ANALYSIS IN PROGRESS", "Running detection engine...\n")
            result = self.service.analyze_url(url, force_mllm=False)
            elapsed = time.time() - start_time
            
            # Display results step by step
            self.display_results_stepwise(result, elapsed)
            
            return result
            
        except Exception as e:
            print_error(f"Analysis failed: {e}")
            return {"classification": "ERROR", "confidence": 0, "explanation": str(e)}
    
    def display_results_stepwise(self, result: Dict[str, Any], total_time: float):
        """Display results in a structured, educational format."""
        
        # 1. Classification Summary
        print_header("CLASSIFICATION RESULT", Colors.BRIGHT_GREEN)
        
        classification = result.get("classification", "UNKNOWN")
        confidence = result.get("confidence", 0)
        risk_score = result.get("risk_score", 0)
        action = result.get("recommended_action", "UNKNOWN")
        
        class_color = {
            "LEGITIMATE": Colors.BRIGHT_GREEN,
            "PHISHING": Colors.BRIGHT_RED,
            "AI_GENERATED_PHISHING": Colors.BRIGHT_MAGENTA,
            "PHISHING_KIT": Colors.BRIGHT_RED,
            "ERROR": Colors.BRIGHT_RED
        }.get(classification, Colors.WHITE)
        
        print(f"{Colors.BOLD}Verdict:{Colors.RESET} {class_color}{classification}{Colors.RESET}")
        print(f"{Colors.BOLD}Confidence:{Colors.RESET} {draw_confidence_bar(confidence)} ({confidence*100:.1f}%)")
        print(f"{Colors.BOLD}Risk Score:{Colors.RESET} {draw_risk_meter(risk_score)} (lower is safer)")
        print(f"{Colors.BOLD}Recommendation:{Colors.RESET} {Colors.GREEN if action == 'allow' else Colors.RED}{action.upper()}{Colors.RESET}")
        print(f"{Colors.BOLD}Processing Time:{Colors.RESET} {format_seconds(total_time)}")
        print()
        
        # 2. Feature Highlights
        features = result.get("features", {})
        if features:
            print_header("EXTRACTED FEATURES (Top 10 of 93)", Colors.BRIGHT_YELLOW)
            
            # Sort by importance (risk_score contribution if available)
            feature_items = []
            for key, value in features.items():
                if isinstance(value, (int, float)) and key not in ("typosquatting",):
                    feature_items.append((key, value))
            
            # Show top 10 features sorted by absolute value
            feature_items.sort(key=lambda x: abs(x[1]) if isinstance(x[1], (int, float)) else 0, reverse=True)
            
            for i, (key, value) in enumerate(feature_items[:10], 1):
                print(f"  {i:2d}. {Colors.BOLD}{key:<30}{Colors.RESET}: {value}")
            
            print(f"\n  {Colors.DIM}Total features extracted: {len(features)}{Colors.RESET}")
            print()
        
        # 3. Typosquatting Detection
        typosquat = result.get("features", {}).get("typosquatting")
        if typosquat:
            print_header("TYPOSQUATTING ANALYSIS", Colors.BRIGHT_RED)
            if isinstance(typosquat, dict):
                print_highlight("Impersonated Brand", typosquat.get("brand"))
                print_highlight("Similarity Score", f"{typosquat.get('similarity', 0)*100:.1f}%")
                print_highlight("Distance", typosquat.get("distance"))
                print_highlight("Domain", result.get("url", "").split("/")[2] if len(result.get("url", "").split("/")) > 2 else "N/A")
            print()
        
        # 4. Web Scraping Results (if online)
        proof = result.get("scrape_proof")
        if proof and self.is_online:
            print_header("WEB CONTENT ANALYSIS (ONLINE)", Colors.BRIGHT_BLUE)
            
            # Suspicious forms
            suspicious_forms = proof.get("suspicious_forms_count", 0)
            if suspicious_forms > 0:
                print_warning(f"Suspicious forms detected: {suspicious_forms}")
            
            # External domains
            ext_domains = proof.get("external_domains_count", 0)
            if ext_domains > 0:
                print_warning(f"External form actions: {ext_domains}")
            
            # Toolkit signatures
            toolkits = result.get("toolkit_signatures")
            if toolkits:
                print_error(f"Toolkit signatures found: {', '.join(toolkits.keys())}")
            
            # Phishing keywords
            phishing_indicators = proof.get("phishing_indicators_count", 0)
            if phishing_indicators > 0:
                print_warning(f"Phishing keyword hits: {phishing_indicators}")
            
            print(f"\n  {Colors.DIM}Title:{Colors.RESET} {proof.get('title', 'N/A')}")
            print(f"  {Colors.DIM}Forms found:{Colors.RESET} {proof.get('forms_count', 0)}")
            print()
        
        # 5. AI Analysis (if enabled)
        ai_indicators = result.get("ai_indicators")
        if ai_indicators:
            print_header("AI-GENERATED CONTENT DETECTION", Colors.BRIGHT_MAGENTA)
            print_highlight("AI Probability", f"{ai_indicators.get('ai_probability', 0)*100:.1f}%")
            print_highlight("Classification", ai_indicators.get('classification', 'N/A'))
            print()
        
        # 6. Explanation
        print_header("ANALYSIS EXPLANATION", Colors.BRIGHT_GREEN)
        explanation = result.get("explanation", "No explanation available")
        print(f"{Colors.WHITE}{explanation}{Colors.RESET}")
        print()
        
        # 7. Recommendation box
        print(f"\n{Colors.BOLD}{'─'*80}{Colors.RESET}")
        if action == "allow":
            rec_color = Colors.BRIGHT_GREEN
            icon = "✓"
        elif action == "block":
            rec_color = Colors.BRIGHT_RED
            icon = "⛔"
        else:
            rec_color = Colors.BRIGHT_YELLOW
            icon = "⚠"
        
        print(f"{rec_color}FINAL RECOMMENDATION:{Colors.RESET} {icon} {action.upper()}")
        print(f"{Colors.BOLD}{'─'*80}{Colors.RESET}")
        print()
    
    def interactive_loop(self):
        """Main interactive loop."""
        if not self.initialize():
            return
        
        print(f"{Colors.GREEN}Ready! Enter URLs to analyze (type 'quit' or 'exit' to leave).{Colors.RESET}")
        print(f"{Colors.DIM}Tip: Try legitimate sites (google.com) and suspicious ones (paypal-security.com){Colors.RESET}\n")
        
        while True:
            try:
                url = input(f"\n{Colors.BOLD}Enter URL:{Colors.RESET} ").strip()
                if url.lower() in ('quit', 'exit', 'q'):
                    print(f"\n{Colors.CYAN}Thank you for using the Phishing Detection System!{Colors.RESET}")
                    break
                
                if not url:
                    continue
                
                # Add scheme if missing
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                self.run_analysis(url)
                
            except KeyboardInterrupt:
                print(f"\n\n{Colors.CYAN}Interrupted. Type 'quit' to exit.{Colors.RESET}")
            except Exception as e:
                print_error(f"Unexpected error: {e}")

def main():
    """Main entry point."""
    demo = FinalYearDemo()
    demo.interactive_loop()

if __name__ == "__main__":
    main()
