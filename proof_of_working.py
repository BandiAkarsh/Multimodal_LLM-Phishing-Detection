#!/usr/bin/env python3
"""
===============================================================================
  PHISHING DETECTION SYSTEM - INTERACTIVE PROOF-OF-WORKING
===============================================================================

Real-time demonstration where reviewers can enter ANY URL and see the complete
detection mechanism in action with step-by-step explanations.

WHAT HAPPENS:
1. Takes user URL input
2. Runs the FULL detection pipeline
3. Shows EACH step of the mechanism:
   - URL parsing & validation
   - Feature extraction (93 features)
   - Typosquatting detection
   - ML classification
   - Content scraping (if online)
   - Toolkit detection
   - AI content analysis (if enabled)
4. Displays detailed results and final verdict

For final year project viva/stakeholder demonstration.

Author: Phishing Guard Team (Security Hardened)
Version: 2.0.0
"""

import os
import sys
import time
import warnings
from datetime import datetime
from typing import Any, Dict

# Suppress MLflow FutureWarnings for clean demo output
warnings.filterwarnings("ignore", category=FutureWarning, module="mlflow")

# Dynamic path resolution
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "04_inference"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "05_utils"))

class InteractiveProof:
    """Interactive proof-of-working demonstration."""
    
    def __init__(self):
        self.service = None
        self.is_online = True
        self.setup_environment()
    
    def setup_environment(self):
        """Set up required environment variables."""
        # Set JWT secret if not present (for demo only)
        if not os.getenv("JWT_SECRET"):
            os.environ["JWT_SECRET"] = "demo_secret_only_for_testing_12345_change_in_prod"
        # Disable MLLM to avoid heavy downloads for demo
        os.environ["LOAD_MLLM"] = "false"
    
    def initialize(self):
        """Initialize the detection service."""
        print(f"\n{'='*80}")
        print(f"  PHISHING DETECTION SYSTEM - INTERACTIVE PROOF OF WORKING")
        print(f"{'='*80}\n")
        
        try:
            from service import PhishingDetectionService
            print("[INIT] Loading Phishing Detection Service...")
            
            # Load service
            self.service = PhishingDetectionService(load_ml_model=True, load_mllm=False)
            
            # Check connectivity
            import socket
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=2)
                self.is_online = True
                print("[INIT] ✓ Internet: ONLINE (full analysis)")
            except:
                self.is_online = False
                print("[INIT] ⚠ Internet: OFFLINE (limited analysis)")
            
            print("[INIT] ✓ Service ready!\n")
            return True
            
        except Exception as e:
            print(f"[INIT] ✗ Failed to initialize: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def print_header(self, text):
        """Print a section header."""
        print(f"\n{'─'*80}")
        print(f"  {text}")
        print(f"{'─'*80}\n")
    
    def print_step(self, step_num, text):
        """Print a numbered step."""
        print(f"[STEP {step_num}] {text}")
    
    def print_substep(self, text):
        """Print a substep."""
        print(f"  → {text}")
    
    def print_success(self, text):
        """Print success."""
        print(f"  ✓ {text}")
    
    def print_warning(self, text):
        """Print warning."""
        print(f"  ⚠ {text}")
    
    def print_risk_meter(self, score):
        """Visual risk meter."""
        blocks = int(score // 10)
        meter = "█" * blocks + "░" * (10 - blocks)
        color = "\033[91m" if score >= 70 else "\033[93m" if score >= 40 else "\033[92m"
        reset = "\033[0m"
        return f"{color}[{meter}]{reset} {score:.1f}%"
    
    def analyze_url(self, url):
        """Analyze a single URL with full output."""
        
        start = time.time()
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n{'='*80}")
        print(f"  ANALYZING: {url}")
        print(f"{'='*80}")
        
        try:
            # STEP 1: Input validation
            self.print_header("STEP 1: URL VALIDATION & SECURITY CHECKS")
            from security_validator import URLSecurityValidator
            validator = URLSecurityValidator()
            is_valid, errors = validator.validate(url)
            
            self.print_substep(f"URL parsed and validated")
            self.print_substep(f"Scheme allowed: {url.split(':')[0]}")
            
            if errors:
                for err in errors:
                    self.print_warning(err)
            else:
                self.print_success("URL passed security validation")
            
            time.sleep(0.5)  # Pause for demo clarity
            
            # STEP 2: Feature extraction
            self.print_header("STEP 2: FEATURE EXTRACTION (93 features)")
            from feature_extraction import URLFeatureExtractor
            extractor = URLFeatureExtractor()
            features = extractor.extract_features(url)
            
            self.print_substep(f"Extracted {len(features)} features")
            
            # Show feature categories
            categories = {
                "IDN/Homograph": [k for k in features if k.startswith('idn_')],
                "Host Analysis": [k for k in features if k.startswith('host_')],
                "URL Patterns": [k for k in features if k.startswith('url_')],
                "Security": [k for k in features if k.startswith('ssl_') or k.startswith('tls_') or k.startswith('has_')],
                "TLS Analysis": [k for k in features if k.startswith('tls_')],
                "Risk Scores": [k for k in features if 'score' in k.lower()]
            }
            
            for cat, keys in categories.items():
                if keys:
                    self.print_substep(f"{cat}: {len(keys)} features")
            
            # Show top 5 most significant features
            print("\n  Top 5 Features:")
            sorted_feats = sorted(features.items(), key=lambda x: abs(x[1]) if isinstance(x[1], (int, float)) else 0, reverse=True)
            for i, (k, v) in enumerate(sorted_feats[:5], 1):
                print(f"    {i}. {k}: {v}")
            
            time.sleep(0.5)
            
            # STEP 3: Typosquatting detection
            self.print_header("STEP 3: TYPOSQUATTING DETECTION")
            from typosquatting_detector import TyposquattingDetector
            detector = TyposquattingDetector()
            typosquat_result = detector.analyze(url)
            
            if typosquat_result.get('is_typosquatting'):
                self.print_warning(f"Brand impersonation detected!")
                self.print_substep(f"Method: {typosquat_result.get('detection_method', 'unknown')}")
                self.print_substep(f"Brand: {typosquat_result.get('impersonated_brand', 'Unknown')}")
                self.print_substep(f"Similarity: {typosquat_result.get('similarity_score', 0)*100:.1f}%")
                self.print_substep(f"Risk increase: {typosquat_result.get('risk_increase', 0)}%")
                if typosquat_result.get('details'):
                    for detail in typosquat_result['details'][:3]:  # Show first 3 details
                        self.print_substep(f"- {detail}")
            else:
                self.print_success("No typosquatting detected")
            
            time.sleep(0.5)
            
            # STEP 4: ML Classification
            self.print_header("STEP 4: MACHINE LEARNING CLASSIFICATION")
            self.print_substep("Preparing feature vector...")
            self.print_substep(f"Feature vector size: {len(features)}")
            
            # Show ML prediction
            if hasattr(self.service, 'ml_model') and self.service.ml_model_loaded:
                self.print_substep("Running ML classifier...")
                ml_result, confidence = self.service._predict_with_ml(features)
                
                class_map = {0: "LEGITIMATE", 1: "PHISHING", 2: "AI_GENERATED_PHISHING", 3: "PHISHING_KIT"}
                ml_class = class_map.get(ml_result, "UNKNOWN")
                
                self.print_success(f"ML Prediction: {ml_class} (confidence: {confidence*100:.1f}%)")
            else:
                self.print_warning("ML model not loaded, skipping")
                ml_result, confidence = None, 0
            
            time.sleep(0.5)
            
            # STEP 5: Web scraping (if online)
            scraped_data = None
            if self.is_online:
                self.print_header("STEP 5: WEB CONTENT SCRAPING")
                from web_scraper import WebScraper
                scraper = WebScraper(headless=True)
                
                self.print_substep("Fetching webpage content...")
                try:
                    scraped_data = scraper.analyze(url)
                    
                    self.print_success("Scraping completed")
                    self.print_substep(f"Title: {scraped_data.get('title', 'N/A')[:50]}...")
                    self.print_substep(f"Forms found: {scraped_data.get('forms_count', 0)}")
                    self.print_substep(f"Suspicious forms: {scraped_data.get('suspicious_forms_count', 0)}")
                    self.print_substep(f"External domains: {scraped_data.get('external_domains_count', 0)}")
                    
                    # Toolkit detection
                    toolkits = scraped_data.get('toolkit_signatures', {})
                    if toolkits:
                        self.print_warning(f"Toolkit signatures: {', '.join(toolkits.keys())}")
                    
                except Exception as e:
                    self.print_warning(f"Scraping failed: {e}")
                    scraped_data = None
                
                time.sleep(0.5)
            
            # STEP 6: Full analysis orchestration
            self.print_header("STEP 6: FINAL ORCHESTRATION & VERDICT")
            
            # Use the service's full analysis
            self.print_substep("Running full detection pipeline...")
            result = self.service.analyze_url(url)
            
            classification = result.get("classification", "UNKNOWN")
            confidence = result.get("confidence", 0)
            risk = result.get("risk_score", 0)
            action = result.get("recommended_action", "unknown")
            explanation = result.get("explanation", "")
            
            # Final verdict
            print(f"\n  FINAL VERDICT:")
            class_colors = {
                "LEGITIMATE": "\033[92m",
                "PHISHING": "\033[91m",
                "AI_GENERATED_PHISHING": "\033[95m",
                "PHISHING_KIT": "\033[91m",
                "ERROR": "\033[91m"
            }
            color = class_colors.get(classification, "\033[97m")
            reset = "\033[0m"
            
            print(f"    {color}███{reset} Classification: {color}{classification}{reset}")
            print(f"    {color}███{reset} Confidence: {confidence*100:.1f}%")
            print(f"    {color}███{reset} Risk Score: {self.print_risk_meter(risk)}")
            print(f"    {color}███{reset} Action: {action.upper()}")
            
            print(f"\n  EXPLANATION:")
            print(f"    {explanation}")
            
            print(f"\n{'='*80}")
            print(f"  ANALYSIS COMPLETE - Time: {time.time()-start:.2f}s")
            print(f"{'='*80}\n")
            
            return result
            
        except Exception as e:
            print(f"\n[ERROR] Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def run(self):
        """Main interactive loop."""
        if not self.initialize():
            return
        
        print(f"{' '*30}READY FOR INPUT")
        print(f"{' '*20}Type a URL and press ENTER to analyze")
        print(f"{' '*20}Type 'quit' or 'exit' to leave\n")
        
        while True:
            try:
                url = input(f"\033[96m[INPUT]\033[0m Enter URL: ").strip()
                
                if url.lower() in ('quit', 'exit', 'q'):
                    print("\nThank you for using the Phishing Detection System!")
                    break
                
                if not url:
                    continue
                
                # Run analysis
                result = self.analyze_url(url)
                
                # Ask if they want to analyze another
                again = input(f"\n\033[90m[PRESS ENTER to analyze another URL, or type 'quit' to exit: \033[0m").strip()
                if again.lower() in ('quit', 'exit', 'q'):
                    break
                    
            except KeyboardInterrupt:
                print("\n\nInterrupted. Type 'quit' to exit.")
            except Exception as e:
                print(f"\n[ERROR] {e}")

def main():
    """Main entry point."""
    demo = InteractiveProof()
    demo.run()

if __name__ == "__main__":
    main()
