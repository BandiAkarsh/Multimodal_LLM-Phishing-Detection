#!/usr/bin/env python3
"""
Interactive Phishing Detection Tester - VERBOSE MODE
Tests the phishing detection system with your own URLs.
Shows exactly what happens under the hood for reviewers.

Usage:
    cd ~/college-final-yr-projects/phishing_detection_project
    python3 tests/test_interactive.py
"""

import os
import sys
import json
import time
from pathlib import Path

# ── PATH SETUP ──────────────────────────────────────────
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "04_inference"))
sys.path.insert(0, str(project_root / "05_utils"))
sys.path.insert(0, str(project_root / "03_training"))

# ── TEST URLS ───────────────────────────────────────────
TEST_URLS = [
    # Legitimate
    ("https://google.com", "legitimate"),
    ("https://github.com", "legitimate"),
    ("https://stackoverflow.com", "legitimate"),
    ("https://amazon.in", "legitimate"),
    ("https://microsoft.com", "legitimate"),
    # Suspicious / Phishing patterns
    ("http://192.168.1.1/login", "suspicious"),
    ("https://login-paypal-secure.com", "suspicious"),
    ("https://paypa1.com", "suspicious"),
    ("https://secure-update-verify.com/login", "suspicious"),
    ("http://free-prize-winner.tk/claim", "suspicious"),
]


def verbose_print(msg, indent=0):
    prefix = "   " * indent
    print(f"{prefix}{msg}")


def load_service():
    """Load the detection service with verbose output."""
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  STEP 1: Loading Detection Engine                          │")
    print("└─────────────────────────────────────────────────────────────┘")

    verbose_print("🔄 Importing PhishingDetectionService...")
    t0 = time.time()

    from service import PhishingDetectionService

    verbose_print(f"✅ Import OK ({time.time()-t0:.2f}s)")

    verbose_print("🔄 Initialising service (load_mllm=False for speed)...")
    t0 = time.time()

    service = PhishingDetectionService(load_mllm=False)

    verbose_print(f"✅ Service ready ({time.time()-t0:.2f}s)")
    verbose_print(f"   ML Model loaded : {service.ml_model_loaded}")
    verbose_print(f"   MLLM loaded     : {service.model_loaded}")
    verbose_print(f"   Online mode     : {service.is_online}")
    verbose_print(f"   Analysis mode   : {service.analysis_mode}")

    if not service.ml_model_loaded:
        print("\n❌  ML model failed to load. Cannot continue.")
        print("    Check that 02_models/ contains .joblib files.")
        sys.exit(1)

    return service


def analyze_url(service, url, verbose=True):
    """Analyse a single URL with full verbose output."""
    if verbose:
        print(f"\n{'─'*65}")
        verbose_print(f"🔍  URL: {url}")
        verbose_print(f"┌── STEP A: Extracting 93 features …")

    t0 = time.time()
    result = service.analyze_url(url)
    elapsed = (time.time() - t0) * 1000

    classification = result.get("classification", "unknown").lower()
    risk_score     = result.get("risk_score", 0)
    confidence     = result.get("confidence", 0)
    is_phishing    = classification in ("phishing", "ai_generated_phishing", "phishing_kit")
    mode           = result.get("analysis_mode", "unknown")

    if verbose:
        verbose_print(f"├── STEP B: ML model prediction …")
        verbose_print(f"├── STEP C: Risk scoring …")
        verbose_print(f"└── Done in {elapsed:.0f} ms")

        # Classification with colour
        if classification == "legitimate":
            tag = "\033[92m✅ LEGITIMATE\033[0m"
        elif classification in ("phishing", "ai_generated_phishing", "phishing_kit"):
            tag = f"\033[91m🚨 {classification.upper()}\033[0m"
        else:
            tag = f"\033[93m⚠️  {classification.upper()}\033[0m"

        verbose_print(f"   Result        : {tag}")
        verbose_print(f"   Confidence    : {confidence:.1%}")
        verbose_print(f"   Risk Score    : {risk_score}/100")
        verbose_print(f"   Is Phishing   : {is_phishing}")
        verbose_print(f"   Analysis Mode : {mode}")

        # Show interesting features when available
        features = result.get("features", {})
        if features:
            verbose_print(f"   ── Key Features ──")
            for key in ("url_length", "domain_entropy", "is_https",
                         "has_ip_address", "suspicious_word_count",
                         "num_subdomains", "has_punycode"):
                if key in features:
                    verbose_print(f"     {key}: {features[key]}")

        # Explanations
        explanation = result.get("explanation", "")
        if explanation:
            verbose_print(f"   ── Explanation ──")
            for line in explanation.split(". "):
                if line.strip():
                    verbose_print(f"     • {line.strip()}")

    return result, elapsed


def run_automated_tests(service):
    """Run the full test suite against known URLs."""
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  STEP 2: Automated Testing — 10 random URLs               │")
    print("└─────────────────────────────────────────────────────────────┘")

    results = []
    correct = 0

    for url, expected in TEST_URLS:
        result, elapsed = analyze_url(service, url, verbose=True)

        classification = result.get("classification", "unknown").lower()
        if expected == "legitimate":
            ok = classification == "legitimate"
        elif expected == "suspicious":
            ok = classification != "legitimate"
        else:
            ok = True

        if ok:
            correct += 1

        results.append({
            "url": url,
            "expected": expected,
            "got": classification,
            "correct": ok,
            "risk": result.get("risk_score", 0),
            "ms": elapsed,
        })

    # ── Summary table ───────────────────────────────────
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  RESULTS SUMMARY                                           │")
    print("├─────────────────────────────────────────────────────────────┤")
    print(f"│  {'URL':<35} {'Expected':<12} {'Got':<15} {'OK':>3} │")
    print(f"├─────────────────────────────────────────────────────────────┤")
    for r in results:
        mark = "✅" if r["correct"] else "❌"
        print(f"│  {r['url'][:35]:<35} {r['expected']:<12} {r['got']:<15} {mark:>3} │")
    print(f"├─────────────────────────────────────────────────────────────┤")

    accuracy = correct / len(results) * 100
    avg_ms = sum(r["ms"] for r in results) / len(results)
    print(f"│  Accuracy : {accuracy:5.1f}%  ({correct}/{len(results)})                         │")
    print(f"│  Avg time : {avg_ms:5.0f} ms                                       │")
    print(f"│  Status   : {'✅ PASS' if accuracy >= 70 else '❌ FAIL'}                                         │")
    print(f"└─────────────────────────────────────────────────────────────┘")

    return results


def interactive_mode(service):
    """Let user type their own URLs."""
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  INTERACTIVE MODE — type any URL                           │")
    print("│  Commands: help | examples | quit                          │")
    print("└─────────────────────────────────────────────────────────────┘")

    while True:
        try:
            user_input = input("\n🔍  Enter URL: ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("quit", "exit", "q"):
                print("👋  Bye!")
                break
            if user_input.lower() == "help":
                print("  Type a URL  → analyse it")
                print("  examples    → run built-in tests")
                print("  quit        → exit")
                continue
            if user_input.lower() == "examples":
                run_automated_tests(service)
                continue

            url = user_input if user_input.startswith("http") else f"https://{user_input}"
            analyze_url(service, url, verbose=True)

        except KeyboardInterrupt:
            print("\n👋  Bye!")
            break


def main():
    print("=" * 65)
    print("🛡️   PHISHING GUARD — Interactive & Verbose Testing")
    print("=" * 65)

    service = load_service()

    # Run automated tests first
    run_automated_tests(service)

    # Then drop into interactive mode
    interactive_mode(service)


if __name__ == "__main__":
    main()
