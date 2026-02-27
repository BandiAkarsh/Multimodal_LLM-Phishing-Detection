#!/usr/bin/env python3
"""
================================================================================
  PHISHING DETECTION SYSTEM - INTERACTIVE DEMONSTRATION INTERFACE
================================================================================

A comprehensive showcase of the Phishing Detection System's capabilities.
Designed for educational presentations, testing, and stakeholder demos.

Author: Phishing Detection Team
Version: 2.0.0
Date: 2026-02-15

Features:
- Interactive URL analysis with verbose output
- Color-coded visual indicators
- Progress animations and spinners
- Batch URL comparison mode
- Demo mode with curated test cases
- Feature extraction visualization
- Risk meter visualizations
- Side-by-side URL comparisons

Usage:
    python demo.py                    # Launch interactive menu
    python demo.py --single URL       # Analyze single URL
    python demo.py --batch URL1 URL2  # Compare multiple URLs
    python demo.py --demo             # Run demonstration mode
    python demo.py --features URL     # Extract features only
    python demo.py --offline          # Force offline mode
"""

import asyncio
import argparse
import itertools
import os
import random
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Dynamic path resolution
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "04_inference"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "05_utils"))

# Import service
from service import PhishingDetectionService

# Import connectivity checker
try:
    from connectivity import check_internet_connection
except ImportError:
    def check_internet_connection():
        return True


# =============================================================================
# COLOR CODES AND STYLING
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    # Standard colors
    BLACK = "\033[30m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    # Bright colors
    BRIGHT_RED = "\033[1;91m"
    BRIGHT_GREEN = "\033[1;92m"
    BRIGHT_YELLOW = "\033[1;93m"
    BRIGHT_BLUE = "\033[1;94m"
    BRIGHT_MAGENTA = "\033[1;95m"
    BRIGHT_CYAN = "\033[1;96m"
    
    # Background colors
    BG_RED = "\033[101m"
    BG_GREEN = "\033[102m"
    BG_YELLOW = "\033[103m"
    BG_BLUE = "\033[104m"
    
    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    HIDDEN = "\033[8m"
    
    # Reset
    END = "\033[0m"
    
    # Classification-specific colors
    @staticmethod
    def classification_color(classification: str) -> str:
        """Get color based on classification."""
        colors = {
            "legitimate": Colors.BRIGHT_GREEN,
            "phishing": Colors.BRIGHT_RED,
            "ai_generated_phishing": Colors.BRIGHT_MAGENTA,
            "phishing_kit": Colors.BRIGHT_RED,
            "unknown": Colors.YELLOW,
        }
        return colors.get(classification.lower(), Colors.WHITE)
    
    @staticmethod
    def risk_color(risk_score: float) -> str:
        """Get color based on risk score."""
        if risk_score <= 20:
            return Colors.BRIGHT_GREEN
        elif risk_score <= 40:
            return Colors.GREEN
        elif risk_score <= 60:
            return Colors.YELLOW
        elif risk_score <= 80:
            return Colors.RED
        else:
            return Colors.BRIGHT_RED
    
    @staticmethod
    def confidence_color(confidence: float) -> str:
        """Get color based on confidence."""
        if confidence >= 0.9:
            return Colors.BRIGHT_GREEN
        elif confidence >= 0.7:
            return Colors.GREEN
        elif confidence >= 0.5:
            return Colors.YELLOW
        else:
            return Colors.RED


# =============================================================================
# BOX DRAWING CHARACTERS
# =============================================================================

class BoxChars:
    """Unicode box drawing characters for visual sections."""
    # Single line
    HORIZONTAL = "─"
    VERTICAL = "│"
    TOP_LEFT = "┌"
    TOP_RIGHT = "┐"
    BOTTOM_LEFT = "└"
    BOTTOM_RIGHT = "┘"
    T_LEFT = "├"
    T_RIGHT = "┤"
    T_TOP = "┬"
    T_BOTTOM = "┴"
    CROSS = "┼"
    
    # Double line
    HORIZONTAL_DBL = "═"
    VERTICAL_DBL = "║"
    TOP_LEFT_DBL = "╔"
    TOP_RIGHT_DBL = "╗"
    BOTTOM_LEFT_DBL = "╚"
    BOTTOM_RIGHT_DBL = "╝"
    
    # Rounded corners
    TOP_LEFT_ROUND = "╭"
    TOP_RIGHT_ROUND = "╮"
    BOTTOM_LEFT_ROUND = "╰"
    BOTTOM_RIGHT_ROUND = "╯"
    
    # Special
    ARROW_RIGHT = "▶"
    ARROW_LEFT = "◀"
    ARROW_UP = "▲"
    ARROW_DOWN = "▼"
    CHECK = "✓"
    CROSS_X = "✗"
    WARNING = "⚠"
    INFO = "ℹ"
    BULLET = "•"
    DIAMOND = "◆"
    STAR = "★"
    CIRCLE = "●"
    
    # Progress
    BLOCK_FULL = "█"
    BLOCK_7_8 = "▉"
    BLOCK_3_4 = "▊"
    BLOCK_5_8 = "▋"
    BLOCK_1_2 = "▌"
    BLOCK_3_8 = "▍"
    BLOCK_1_4 = "▎"
    BLOCK_1_8 = "▏"
    BLOCK_EMPTY = "░"


# =============================================================================
# SPINNER AND PROGRESS INDICATORS
# =============================================================================

class Spinner:
    """Terminal spinner for indicating progress."""
    
    SPINNERS = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
        'line': ['-', '\\', '|', '/'],
        'arrow': ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        'bounce': ['( ●    )', '(  ●   )', '(   ●  )', '(    ● )', '(     ●)', '(    ● )', '(   ●  )', '(  ●   )'],
        'pulse': ['◐', '◓', '◑', '◒'],
    }
    
    def __init__(self, message: str = "Processing", spinner_type: str = 'dots'):
        self.message = message
        self.spinner = itertools.cycle(self.SPINNERS.get(spinner_type, self.SPINNERS['dots']))
        self.busy = False
        self.delay = 0.1
        self._thread = None
        
    def start(self):
        """Start the spinner."""
        self.busy = True
        self._thread = threading.Thread(target=self._spin)
        self._thread.start()
        
    def _spin(self):
        """Spinner loop."""
        while self.busy:
            symbol = next(self.spinner)
            sys.stdout.write(f"\r{Colors.CYAN}{symbol}{Colors.END} {self.message}...")
            sys.stdout.flush()
            time.sleep(self.delay)
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stdout.flush()
        
    def stop(self, success: bool = True):
        """Stop the spinner."""
        self.busy = False
        if self._thread:
            self._thread.join()
        if success:
            print(f"{Colors.GREEN}{BoxChars.CHECK}{Colors.END} {self.message} complete!")
        else:
            print(f"{Colors.RED}{BoxChars.CROSS_X}{Colors.END} {self.message} failed!")


# =============================================================================
# VISUAL COMPONENTS
# =============================================================================

def draw_box(content: str, width: int = 80, title: str = "", style: str = "single", color: str = "") -> str:
    """Draw a box around content.
    
    Args:
        content: Content to box
        width: Box width
        title: Optional title
        style: 'single', 'double', 'rounded'
        color: Color code for border
    """
    if style == "double":
        tl, tr, bl, br, h, v = BoxChars.TOP_LEFT_DBL, BoxChars.TOP_RIGHT_DBL, BoxChars.BOTTOM_LEFT_DBL, BoxChars.BOTTOM_RIGHT_DBL, BoxChars.HORIZONTAL_DBL, BoxChars.VERTICAL_DBL
    elif style == "rounded":
        tl, tr, bl, br, h, v = BoxChars.TOP_LEFT_ROUND, BoxChars.TOP_RIGHT_ROUND, BoxChars.BOTTOM_LEFT_ROUND, BoxChars.BOTTOM_RIGHT_ROUND, BoxChars.HORIZONTAL, BoxChars.VERTICAL
    else:
        tl, tr, bl, br, h, v = BoxChars.TOP_LEFT, BoxChars.TOP_RIGHT, BoxChars.BOTTOM_LEFT, BoxChars.BOTTOM_RIGHT, BoxChars.HORIZONTAL, BoxChars.VERTICAL
    
    border_color = color if color else Colors.BLUE
    
    lines = content.split('\n')
    result = []
    
    # Top border
    if title:
        title_str = f" {title} "
        title_len = len(title)
        left_len = (width - title_len - 2) // 2
        right_len = width - title_len - 2 - left_len
        result.append(f"{border_color}{tl}{h * left_len}{Colors.BOLD}{title}{Colors.END}{border_color}{h * right_len}{tr}{Colors.END}")
    else:
        result.append(f"{border_color}{tl}{h * width}{tr}{Colors.END}")
    
    # Content
    for line in lines:
        padding = width - len(line)
        result.append(f"{border_color}{v}{Colors.END} {line}{' ' * max(0, padding - len(line) - 1)}{border_color}{v}{Colors.END}")
    
    # Bottom border
    result.append(f"{border_color}{bl}{h * width}{br}{Colors.END}")
    
    return '\n'.join(result)


def draw_section_header(title: str, icon: str = "", color: str = Colors.BRIGHT_BLUE) -> str:
    """Draw a section header with icon.
    
    Args:
        title: Section title
        icon: Optional icon character
        color: Header color
    """
    icon_str = f"{icon} " if icon else ""
    header = f"\n{color}{BoxChars.HORIZONTAL_DBL * 3}{Colors.END} {Colors.BOLD}{icon_str}{title}{Colors.END}"
    return header


def draw_risk_meter(risk_score: float, width: int = 40) -> str:
    """Draw a visual risk meter.
    
    Args:
        risk_score: Risk score from 0-100
        width: Width of the meter
    """
    filled = int((risk_score / 100) * width)
    empty = width - filled
    
    # Color gradient based on risk
    if risk_score <= 30:
        color = Colors.BRIGHT_GREEN
    elif risk_score <= 50:
        color = Colors.YELLOW
    elif risk_score <= 70:
        color = Colors.RED
    else:
        color = Colors.BRIGHT_RED
    
    bar = f"{color}{BoxChars.BLOCK_FULL * filled}{Colors.END}{Colors.DIM}{BoxChars.BLOCK_EMPTY * empty}{Colors.END}"
    
    return f"[{bar}] {color}{risk_score:.1f}%{Colors.END}"


def draw_confidence_bar(confidence: float, width: int = 30) -> str:
    """Draw a confidence bar.
    
    Args:
        confidence: Confidence from 0-1
        width: Width of the bar
    """
    filled = int(confidence * width)
    empty = width - filled
    
    color = Colors.confidence_color(confidence)
    percentage = confidence * 100
    
    bar = f"{color}{BoxChars.BLOCK_FULL * filled}{Colors.END}{Colors.DIM}{BoxChars.BLOCK_EMPTY * empty}{Colors.END}"
    
    return f"[{bar}] {color}{percentage:.1f}%{Colors.END}"


def draw_feature_table(features: Dict[str, Any], max_width: int = 80) -> str:
    """Draw a formatted feature table.
    
    Args:
        features: Dictionary of features
        max_width: Maximum width
    """
    lines = []
    
    # Group features into categories
    categories = {
        "Basic Length": ["url_length", "domain_length", "path_length", "hostname_length"],
        "Character Counts": ["num_dots", "num_hyphens", "num_underscores", "num_slashes", 
                            "num_question_marks", "num_equals", "num_at", "num_ampersand", "num_digits"],
        "Security": ["is_https", "is_ip_address", "has_suspicious_words"],
        "Entropy": ["entropy", "domain_entropy"],
        "Domain": ["subdomain_count", "is_random_domain", "domain_has_digits"],
    }
    
    for category, keys in categories.items():
        lines.append(f"\n{Colors.CYAN}{BoxChars.BULLET} {category}:{Colors.END}")
        for key in keys:
            if key in features:
                value = features[key]
                # Format value
                if isinstance(value, float):
                    value_str = f"{value:.3f}"
                elif isinstance(value, bool) or value in [0, 1]:
                    value_str = f"{Colors.GREEN}Yes{Colors.END}" if value else f"{Colors.RED}No{Colors.END}"
                else:
                    value_str = str(value)
                
                key_formatted = key.replace('_', ' ').title()
                lines.append(f"  {Colors.DIM}{key_formatted:<25}{Colors.END} {value_str}")
    
    return '\n'.join(lines)


def draw_typosquatting_analysis(typosquat_result: Dict[str, Any]) -> str:
    """Draw typosquatting analysis details.
    
    Args:
        typosquat_result: Typosquatting detection result
    """
    lines = []
    
    is_typosquat = typosquat_result.get("is_typosquatting", False)
    
    if is_typosquat:
        lines.append(f"\n{Colors.BRIGHT_RED}{BoxChars.WARNING} TYPOQUATTING DETECTED{Colors.END}")
        lines.append(f"{Colors.RED}Method: {typosquat_result.get('detection_method', 'Unknown')}{Colors.END}")
        
        if "impersonated_brand" in typosquat_result:
            lines.append(f"{Colors.RED}Impersonated Brand: {typosquat_result['impersonated_brand']}{Colors.END}")
        
        if "details" in typosquat_result and typosquat_result["details"]:
            lines.append(f"\n{Colors.YELLOW}Details:{Colors.END}")
            for detail in typosquat_result["details"][:3]:
                lines.append(f"  {Colors.DIM}{BoxChars.ARROW_RIGHT}{Colors.END} {detail}")
        
        if "risk_increase" in typosquat_result:
            lines.append(f"\n{Colors.RED}Risk Increase: +{typosquat_result['risk_increase']} points{Colors.END}")
    else:
        lines.append(f"\n{Colors.GREEN}{BoxChars.CHECK} No typosquatting detected{Colors.END}")
        if "verification_reason" in typosquat_result:
            lines.append(f"{Colors.GREEN}Verification: {typosquat_result['verification_reason']}{Colors.END}")
    
    return '\n'.join(lines)


def draw_toolkit_signatures(toolkit_data: Optional[Dict[str, Any]]) -> str:
    """Draw toolkit signature detection details.
    
    Args:
        toolkit_data: Toolkit detection data
    """
    if not toolkit_data or not toolkit_data.get("detected"):
        return f"\n{Colors.GREEN}{BoxChars.CHECK} No phishing toolkit signatures detected{Colors.END}"
    
    lines = []
    lines.append(f"\n{Colors.BRIGHT_RED}{BoxChars.WARNING} PHISHING KIT DETECTED!{Colors.END}")
    lines.append(f"{Colors.RED}Toolkit Name: {toolkit_data.get('toolkit_name', 'Unknown')}{Colors.END}")
    lines.append(f"{Colors.RED}Confidence: {toolkit_data.get('confidence', 0) * 100:.1f}%{Colors.END}")
    
    signatures = toolkit_data.get("signatures_found", [])
    if signatures:
        lines.append(f"\n{Colors.YELLOW}Signatures Found:{Colors.END}")
        for sig in signatures[:5]:
            lines.append(f"  {Colors.RED}{BoxChars.DIAMOND}{Colors.END} {sig}")
    
    return '\n'.join(lines)


def draw_ai_indicators(ai_indicators: Optional[List[str]]) -> str:
    """Draw AI-generated content indicators.
    
    Args:
        ai_indicators: List of AI indicators
    """
    if not ai_indicators:
        return f"\n{Colors.GREEN}{BoxChars.CHECK} No AI-generated content patterns detected{Colors.END}"
    
    lines = []
    lines.append(f"\n{Colors.MAGENTA}{BoxChars.WARNING} AI-GENERATED CONTENT INDICATORS{Colors.END}")
    lines.append(f"{Colors.MAGENTA}Potential AI-generated phishing content detected{Colors.END}")
    
    lines.append(f"\n{Colors.YELLOW}Indicators:{Colors.END}")
    for indicator in ai_indicators[:5]:
        lines.append(f"  {Colors.MAGENTA}{BoxChars.DIAMOND}{Colors.END} {indicator}")
    
    return '\n'.join(lines)


def draw_scraping_proof(proof: Optional[Dict[str, Any]]) -> str:
    """Draw web scraping results.
    
    Args:
        proof: Scraping proof data
    """
    if not proof:
        return f"\n{Colors.YELLOW}{BoxChars.INFO} No scraping data available (offline mode or site unreachable){Colors.END}"
    
    lines = []
    lines.append(f"\n{Colors.CYAN}{BoxChars.INFO} WEB SCRAPING RESULTS{Colors.END}")
    lines.append(f"{Colors.CYAN}Page Title:{Colors.END} {proof.get('title', 'N/A')}")
    lines.append(f"{Colors.CYAN}HTML Size:{Colors.END} {proof.get('html_size_bytes', 0):,} bytes")
    lines.append(f"{Colors.CYAN}Links Found:{Colors.END} {proof.get('num_links', 0)}")
    lines.append(f"{Colors.CYAN}Images Found:{Colors.END} {proof.get('num_images', 0)}")
    lines.append(f"{Colors.CYAN}Forms Found:{Colors.END} {proof.get('num_forms', 0)}")
    lines.append(f"{Colors.CYAN}Login Form:{Colors.END} {'Yes' if proof.get('has_login_form') else 'No'}")
    
    return '\n'.join(lines)


def draw_recommendation(recommendation: str, classification: str) -> str:
    """Draw recommendation with appropriate styling.
    
    Args:
        recommendation: Recommended action
        classification: Classification result
    """
    action_colors = {
        "block": Colors.BG_RED + Colors.WHITE + Colors.BOLD,
        "warn": Colors.BG_YELLOW + Colors.BLACK + Colors.BOLD,
        "allow": Colors.BG_GREEN + Colors.WHITE + Colors.BOLD,
    }
    
    color = action_colors.get(recommendation, Colors.BG_BLUE)
    action_text = recommendation.upper()
    
    lines = []
    lines.append(f"\n{color}  RECOMMENDED ACTION: {action_text}  {Colors.END}")
    
    # Add explanation
    explanations = {
        "block": "This URL shows strong phishing indicators. Do not visit.",
        "warn": "This URL shows suspicious patterns. Proceed with caution.",
        "allow": "This URL appears legitimate. Safe to visit.",
    }
    
    if recommendation in explanations:
        lines.append(f"\n{Colors.DIM}{explanations[recommendation]}{Colors.END}")
    
    return '\n'.join(lines)


# =============================================================================
# MAIN DISPLAY FUNCTIONS
# =============================================================================

def display_banner():
    """Display the main application banner."""
    banner = f"""
{Colors.BRIGHT_CYAN}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗                  ║
║   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝                  ║
║   ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗                 ║
║   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║                 ║
║   ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝                 ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝                  ║
║                                                                              ║
║                    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗        ║
║                    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝        ║
║                    ██║  ██║█████╗     ██║   █████╗  ██║        ██║           ║
║                    ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║           ║
║                    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║           ║
║                    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝           ║
║                                                                              ║
║                    ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗     ║
║                    ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║     ║
║                    ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║     ║
║                    ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║     ║
║                    ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║     ║
║                    ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝     ║
║                                                                              ║
║{Colors.YELLOW}                    Interactive Demonstration Interface v2.0{Colors.BRIGHT_CYAN}                    ║
║{Colors.DIM}                    4-Category Classification • ML-Powered • Real-time{Colors.BRIGHT_CYAN}         ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)


def display_analysis_result(result: Dict[str, Any], verbose: bool = True):
    """Display comprehensive analysis result.
    
    Args:
        result: Analysis result dictionary
        verbose: Whether to show verbose output
    """
    url = result.get("url", "Unknown")
    classification = result.get("classification", "unknown")
    confidence = result.get("confidence", 0)
    risk_score = result.get("risk_score", 0)
    explanation = result.get("explanation", "")
    features = result.get("features", {})
    recommended_action = result.get("recommended_action", "unknown")
    analysis_mode = result.get("analysis_mode", "unknown")
    scraped = result.get("scraped", False)
    
    # Classification display
    class_color = Colors.classification_color(classification)
    class_display = classification.upper().replace("_", " ")
    
    print(f"\n{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}")
    print(f"{Colors.BOLD}URL:{Colors.END} {Colors.CYAN}{url}{Colors.END}")
    print(f"{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}")
    
    # Main result box
    result_content = f"""
{Colors.BOLD}Classification:{Colors.END}  {class_color}{class_display}{Colors.END}
{Colors.BOLD}Confidence:{Colors.END}      {draw_confidence_bar(confidence)}
{Colors.BOLD}Risk Score:{Colors.END}      {draw_risk_meter(risk_score)}
{Colors.BOLD}Analysis Mode:{Colors.END} {Colors.CYAN}{analysis_mode.upper()}{Colors.END}
{Colors.BOLD}Web Scraping:{Colors.END}  {'Yes' if scraped else 'No'}
"""
    print(draw_box(result_content.strip(), width=76, title="ANALYSIS RESULT", style="double", color=class_color))
    
    if verbose:
        # Features section
        print(draw_section_header("FEATURE EXTRACTION", "📊", Colors.BRIGHT_CYAN))
        print(draw_feature_table(features))
        
        # Typosquatting section
        typosquat = features.get("typosquatting", {})
        if typosquat:
            print(draw_section_header("TYPOSQUATTING ANALYSIS", "🔍", Colors.BRIGHT_YELLOW))
            print(draw_typosquatting_analysis(typosquat))
        
        # Web scraping section
        if scraped:
            proof = result.get("scrape_proof")
            print(draw_section_header("WEB CONTENT ANALYSIS", "🌐", Colors.BRIGHT_BLUE))
            print(draw_scraping_proof(proof))
        
        # Toolkit signatures
        toolkit = result.get("toolkit_signatures")
        if toolkit:
            print(draw_section_header("TOOLKIT DETECTION", "🛠️", Colors.BRIGHT_RED))
            print(draw_toolkit_signatures(toolkit))
        
        # AI indicators
        ai_indicators = result.get("ai_indicators")
        if ai_indicators:
            print(draw_section_header("AI CONTENT ANALYSIS", "🤖", Colors.BRIGHT_MAGENTA))
            print(draw_ai_indicators(ai_indicators))
        
        # Explanation
        print(draw_section_header("ANALYSIS EXPLANATION", "📝", Colors.BRIGHT_GREEN))
        print(f"\n{Colors.WHITE}{explanation}{Colors.END}")
    
    # Recommendation
    print(draw_recommendation(recommended_action, classification))
    print()


def display_comparison_table(results: List[Dict[str, Any]]):
    """Display side-by-side comparison of multiple URLs.
    
    Args:
        results: List of analysis results
    """
    print(f"\n{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 100}{Colors.END}")
    print(f"{Colors.BOLD}{'URL Comparison':^100}{Colors.END}")
    print(f"{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 100}{Colors.END}\n")
    
    # Header
    header = f"{Colors.BOLD}{'URL':<40} {'Class':<20} {'Confidence':<15} {'Risk':<10} {'Action':<10}{Colors.END}"
    print(header)
    print(f"{Colors.DIM}{'-' * 100}{Colors.END}")
    
    # Rows
    for result in results:
        url = result.get("url", "Unknown")[:38]
        classification = result.get("classification", "unknown").upper().replace("_", " ")[:18]
        confidence = result.get("confidence", 0)
        risk_score = result.get("risk_score", 0)
        action = result.get("recommended_action", "unknown").upper()
        
        class_color = Colors.classification_color(result.get("classification", ""))
        risk_color = Colors.risk_color(risk_score)
        
        row = f"{url:<40} {class_color}{classification:<20}{Colors.END} {confidence*100:>6.1f}%       {risk_color}{risk_score:>6.1f}%{Colors.END}     {action:<10}"
        print(row)
    
    print(f"{Colors.DIM}{'-' * 100}{Colors.END}\n")


def display_summary_statistics(results: List[Dict[str, Any]]):
    """Display summary statistics for batch analysis.
    
    Args:
        results: List of analysis results
    """
    total = len(results)
    classifications = {}
    avg_risk = 0
    avg_confidence = 0
    
    for result in results:
        classification = result.get("classification", "unknown")
        classifications[classification] = classifications.get(classification, 0) + 1
        avg_risk += result.get("risk_score", 0)
        avg_confidence += result.get("confidence", 0)
    
    avg_risk /= total
    avg_confidence /= total
    
    print(f"\n{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 60}{Colors.END}")
    print(f"{Colors.BOLD}{'BATCH ANALYSIS SUMMARY':^60}{Colors.END}")
    print(f"{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 60}{Colors.END}\n")
    
    print(f"{Colors.CYAN}Total URLs Analyzed:{Colors.END} {total}")
    print(f"{Colors.CYAN}Average Risk Score:{Colors.END} {draw_risk_meter(avg_risk)}")
    print(f"{Colors.CYAN}Average Confidence:{Colors.END} {draw_confidence_bar(avg_confidence)}")
    
    print(f"\n{Colors.BOLD}Classifications:{Colors.END}")
    for classification, count in sorted(classifications.items(), key=lambda x: x[1], reverse=True):
        color = Colors.classification_color(classification)
        class_name = classification.upper().replace("_", " ")
        percentage = (count / total) * 100
        print(f"  {color}{BoxChars.BULLET}{Colors.END} {class_name:<25} {count:>3} ({percentage:>5.1f}%)")
    
    print()


# =============================================================================
# SAMPLE URLS
# =============================================================================

SAMPLE_URLS = {
    "safe": [
        ("https://google.com", "Legitimate search engine"),
        ("https://github.com", "Popular code repository"),
        ("https://microsoft.com", "Microsoft official site"),
        ("https://apple.com", "Apple official site"),
        ("https://amazon.com", "Amazon e-commerce"),
    ],
    "phishing_typosquatting": [
        ("http://paypa1.com", "PayPal typosquat (1 instead of l)"),
        ("http://amaz0n-security.com", "Amazon typosquat (0 instead of o)"),
        ("http://g00gle-login.com", "Google typosquat"),
        ("http://faceb00k-verify.net", "Facebook typosquat"),
        ("http://netfl1x-account.com", "Netflix typosquat (1 instead of i)"),
    ],
    "phishing_suspicious": [
        ("http://secure-bank-update.tk", "Suspicious TLD (.tk) + banking keywords"),
        ("http://verify-account-now.xyz", "Suspicious TLD (.xyz) + action keywords"),
        ("http://login-paypal-secure.cf", "Free TLD (.cf) with brand name"),
        ("http://update-your-info.gq", "Free TLD (.gq) with generic terms"),
    ],
    "technical": [
        ("https://192.168.1.1/login", "IP address based URL"),
        ("http://xn--pple-43d.com", "Punycode/homograph attack"),
        ("http://bit.ly/3xyz123", "URL shortener"),
    ],
}


# =============================================================================
# DEMO MODES
# =============================================================================

class DemoInterface:
    """Interactive demonstration interface."""
    
    def __init__(self, force_offline: bool = False):
        self.service = None
        self.force_offline = force_offline
        self.is_online = not force_offline and check_internet_connection()
        
    async def initialize(self):
        """Initialize the phishing detection service."""
        spinner = Spinner("Loading Phishing Detection Engine", "dots")
        spinner.start()
        
        try:
            self.service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
            spinner.stop(success=True)
        except Exception as e:
            spinner.stop(success=False)
            print(f"{Colors.RED}Error initializing service: {e}{Colors.END}")
            raise
    
    async def analyze_single(self, url: str, verbose: bool = True) -> Dict[str, Any]:
        """Analyze a single URL."""
        spinner = Spinner(f"Analyzing {url[:50]}...", "dots")
        spinner.start()
        
        try:
            result = await self.service.analyze_url_async(url, force_mllm=self.is_online)
            spinner.stop(success=True)
            display_analysis_result(result, verbose=verbose)
            return result
        except Exception as e:
            spinner.stop(success=False)
            print(f"{Colors.RED}Error analyzing URL: {e}{Colors.END}")
            raise
    
    async def analyze_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple URLs."""
        print(f"\n{Colors.CYAN}Analyzing {len(urls)} URLs...{Colors.END}\n")
        
        results = []
        for i, url in enumerate(urls, 1):
            print(f"{Colors.DIM}[{i}/{len(urls)}]{Colors.END} {url}")
            try:
                result = await self.service.analyze_url_async(url, force_mllm=self.is_online)
                results.append(result)
            except Exception as e:
                print(f"{Colors.RED}  Error: {e}{Colors.END}")
                results.append({
                    "url": url,
                    "classification": "unknown",
                    "confidence": 0,
                    "risk_score": 0,
                    "explanation": f"Error: {str(e)}",
                    "recommended_action": "warn",
                })
        
        # Display comparison table
        display_comparison_table(results)
        display_summary_statistics(results)
        
        return results
    
    def display_sample_urls(self):
        """Display sample URLs for testing."""
        print(f"\n{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}")
        print(f"{Colors.BOLD}{'SAMPLE URLs FOR TESTING':^80}{Colors.END}")
        print(f"{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}\n")
        
        for category, urls in SAMPLE_URLS.items():
            category_display = category.replace("_", " ").title()
            color = Colors.GREEN if category == "safe" else Colors.RED if "phishing" in category else Colors.YELLOW
            
            print(f"\n{color}{BoxChars.DIAMOND} {category_display}{Colors.END}")
            for url, description in urls:
                print(f"  {Colors.DIM}{BoxChars.BULLET}{Colors.END} {url:<40} {Colors.DIM}- {description}{Colors.END}")
        
        print()
    
    async def run_demo_mode(self):
        """Run demonstration mode with sample URLs."""
        print(f"\n{Colors.BRIGHT_CYAN}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}")
        print(f"{Colors.BRIGHT_CYAN}{'DEMONSTRATION MODE':^80}{Colors.END}")
        print(f"{Colors.BRIGHT_CYAN}{'Testing the system with curated examples':^80}{Colors.END}")
        print(f"{Colors.BRIGHT_CYAN}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}\n")
        
        demo_urls = []
        for category, urls in SAMPLE_URLS.items():
            # Select 2 from each category
            demo_urls.extend([url for url, _ in urls[:2]])
        
        await self.analyze_batch(demo_urls)
    
    async def extract_features_only(self, url: str):
        """Extract and display features without full classification."""
        spinner = Spinner(f"Extracting features from {url[:50]}...", "dots")
        spinner.start()
        
        try:
            features = self.service.url_extractor.extract_features(url)
            typosquat = self.service.typosquatting_detector.analyze(url)
            risk_score = self.service._calculate_risk_score(features, typosquat)
            
            spinner.stop(success=True)
            
            print(f"\n{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}")
            print(f"{Colors.BOLD}FEATURE EXTRACTION RESULTS{Colors.END}")
            print(f"{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 80}{Colors.END}\n")
            
            print(f"{Colors.CYAN}URL:{Colors.END} {url}")
            print(f"{Colors.CYAN}Calculated Risk Score:{Colors.END} {draw_risk_meter(risk_score)}")
            
            print(draw_feature_table(features))
            
            print(draw_section_header("TYPOSQUATTING ANALYSIS", "🔍", Colors.BRIGHT_YELLOW))
            print(draw_typosquatting_analysis(typosquat))
            
        except Exception as e:
            spinner.stop(success=False)
            print(f"{Colors.RED}Error extracting features: {e}{Colors.END}")
            raise
    
    async def interactive_menu(self):
        """Display and handle interactive menu."""
        while True:
            print(f"\n{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 60}{Colors.END}")
            print(f"{Colors.BOLD}{'MAIN MENU':^60}{Colors.END}")
            print(f"{Colors.BOLD}{BoxChars.HORIZONTAL_DBL * 60}{Colors.END}\n")
            
            print(f"  {Colors.CYAN}1.{Colors.END} Analyze Single URL (detailed)")
            print(f"  {Colors.CYAN}2.{Colors.END} Batch URL Analysis (comparison)")
            print(f"  {Colors.CYAN}3.{Colors.END} Demo Mode (sample URLs)")
            print(f"  {Colors.CYAN}4.{Colors.END} Feature Extraction Only")
            print(f"  {Colors.CYAN}5.{Colors.END} View Sample URLs")
            print(f"  {Colors.CYAN}6.{Colors.END} Check Connectivity Status")
            print(f"  {Colors.CYAN}0.{Colors.END} Exit")
            
            try:
                choice = input(f"\n{Colors.BOLD}Enter your choice (0-6):{Colors.END} ").strip()
                
                if choice == "0":
                    print(f"\n{Colors.GREEN}Thank you for using Phishing Detection System!{Colors.END}\n")
                    break
                
                elif choice == "1":
                    url = input(f"{Colors.CYAN}Enter URL to analyze:{Colors.END} ").strip()
                    if url:
                        await self.analyze_single(url, verbose=True)
                
                elif choice == "2":
                    urls_input = input(f"{Colors.CYAN}Enter URLs separated by commas:{Colors.END} ").strip()
                    if urls_input:
                        urls = [u.strip() for u in urls_input.split(",")]
                        await self.analyze_batch(urls)
                
                elif choice == "3":
                    await self.run_demo_mode()
                
                elif choice == "4":
                    url = input(f"{Colors.CYAN}Enter URL for feature extraction:{Colors.END} ").strip()
                    if url:
                        await self.extract_features_only(url)
                
                elif choice == "5":
                    self.display_sample_urls()
                
                elif choice == "6":
                    self.is_online = check_internet_connection()
                    status = f"{Colors.GREEN}ONLINE{Colors.END}" if self.is_online else f"{Colors.RED}OFFLINE{Colors.END}"
                    print(f"\n{Colors.CYAN}Connectivity Status:{Colors.END} {status}")
                    if self.is_online:
                        print(f"{Colors.GREEN}Full multimodal analysis available{Colors.END}")
                    else:
                        print(f"{Colors.YELLOW}Limited to static URL analysis{Colors.END}")
                
                else:
                    print(f"{Colors.RED}Invalid choice. Please try again.{Colors.END}")
            
            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}Interrupted by user.{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.END}")


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Phishing Detection System - Interactive Demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Launch interactive menu
  %(prog)s --single https://example.com       # Analyze single URL
  %(prog)s --batch url1 url2 url3             # Compare multiple URLs
  %(prog)s --demo                             # Run demo with sample URLs
  %(prog)s --features https://example.com     # Extract features only
  %(prog)s --offline                          # Force offline mode
        """
    )
    
    parser.add_argument("--single", metavar="URL", help="Analyze a single URL")
    parser.add_argument("--batch", nargs="+", metavar="URL", help="Analyze multiple URLs")
    parser.add_argument("--demo", action="store_true", help="Run demonstration mode with sample URLs")
    parser.add_argument("--features", metavar="URL", help="Extract features only (no classification)")
    parser.add_argument("--offline", action="store_true", help="Force offline mode (no web scraping)")
    parser.add_argument("--samples", action="store_true", help="Display sample URLs and exit")
    
    args = parser.parse_args()
    
    # Display banner
    display_banner()
    
    # Display sample URLs only
    if args.samples:
        demo = DemoInterface(force_offline=args.offline)
        demo.display_sample_urls()
        return
    
    # Initialize interface
    demo = DemoInterface(force_offline=args.offline)
    
    try:
        await demo.initialize()
        
        # Handle command line arguments
        if args.single:
            await demo.analyze_single(args.single, verbose=True)
        
        elif args.batch:
            await demo.analyze_batch(args.batch)
        
        elif args.demo:
            await demo.run_demo_mode()
        
        elif args.features:
            await demo.extract_features_only(args.features)
        
        else:
            # Interactive mode
            await demo.interactive_menu()
    
    except Exception as e:
        print(f"\n{Colors.BRIGHT_RED}Fatal Error: {e}{Colors.END}\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Exiting...{Colors.END}\n")
        sys.exit(0)
