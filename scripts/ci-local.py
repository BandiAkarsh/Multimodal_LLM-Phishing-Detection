#!/usr/bin/env python3
"""
Local GitHub Actions Simulator
Run this before pushing to catch errors early
"""

import subprocess
import sys
import os
from pathlib import Path

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{'='*60}")
    print(f"{text}")
    print(f"{'='*60}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

def run_command(cmd, description, critical=True):
    """Run a shell command and return success status"""
    print(f"Running: {description}")
    print(f"Command: {cmd}")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.stdout:
            print(result.stdout)
        
        if result.returncode == 0:
            print_success(f"{description} passed")
            return True
        else:
            if critical:
                print_error(f"{description} failed")
            else:
                print_warning(f"{description} has issues")
            if result.stderr:
                print(f"Error: {result.stderr[:500]}")
            return False
    except subprocess.TimeoutExpired:
        print_error(f"{description} timed out")
        return False
    except Exception as e:
        print_error(f"{description} error: {e}")
        return False

def main():
    print_header("GitHub Actions CI - Local Simulator")
    print("Testing your code before pushing to GitHub...\n")
    
    failed = []
    warnings = []
    
    # Change to project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    print_header("JOB 1: Code Quality Checks")
    
    # 1.1 Black formatting check
    if not run_command(
        "black --check 04_inference/ 05_utils/ detect_enhanced.py email_scanner.py 2>&1",
        "Black formatting check",
        critical=False
    ):
        warnings.append("Black formatting issues (run: black 04_inference/ 05_utils/)")
    
    # 1.2 isort check
    if not run_command(
        "isort --check-only 04_inference/ 05_utils/ 2>&1",
        "Import sorting check",
        critical=False
    ):
        warnings.append("Import sorting issues (run: isort 04_inference/ 05_utils/)")
    
    # 1.3 Critical flake8 errors (E9, F63, F7, F82)
    print("\nChecking for critical flake8 errors (E9, F63, F7, F82)...")
    result = subprocess.run(
        "flake8 04_inference/ 05_utils/ --count --select=E9,F63,F7,F82 --show-source --statistics",
        shell=True,
        capture_output=True,
        text=True
    )
    
    if result.stdout:
        print(result.stdout)
    
    if "0" in result.stdout.split('\n')[-2] if len(result.stdout.split('\n')) > 1 else True:
        print_success("No critical flake8 errors")
    else:
        print_error("Critical flake8 errors found!")
        failed.append("Critical flake8 errors")
    
    # 1.4 Full flake8 (non-critical)
    if not run_command(
        "flake8 04_inference/ 05_utils/ --count --exit-zero --max-complexity=10 --max-line-length=127 2>&1",
        "Full flake8 linting",
        critical=False
    ):
        warnings.append("Flake8 style warnings")
    
    # 1.5 MyPy type checking
    if not run_command(
        "mypy 04_inference/ 05_utils/ --ignore-missing-imports 2>&1 | head -50",
        "Type checking with mypy",
        critical=False
    ):
        warnings.append("Type checking issues")
    
    print_header("JOB 2: Testing")
    
    # 2.1 Security tests
    if Path("test_security.py").exists():
        if not run_command(
            "python -m pytest test_security.py -v --tb=short 2>&1 | tail -30",
            "Security tests",
            critical=False
        ):
            warnings.append("Some security tests failed")
    else:
        print_warning("test_security.py not found")
    
    # 2.2 Comprehensive tests
    if Path("test_comprehensive.py").exists():
        if not run_command(
            "python -m pytest test_comprehensive.py -v --tb=short 2>&1 | tail -30",
            "Comprehensive tests",
            critical=False
        ):
            warnings.append("Some comprehensive tests failed")
    else:
        print_warning("test_comprehensive.py not found")
    
    print_header("JOB 3: Security Checks")
    
    # 3.1 Check for hardcoded secrets
    print("Checking for potential secrets in code...")
    secret_patterns = [
        (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
        (r"api_key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key"),
        (r"secret\s*=\s*['\"][^'\"]+['\"]", "Hardcoded secret"),
        (r"token\s*=\s*['\"][^'\"]{20,}['\"]", "Hardcoded token"),
    ]
    
    secrets_found = False
    for pattern, desc in secret_patterns:
        result = subprocess.run(
            f"grep -r '{pattern}' 04_inference/ 05_utils/ --include='*.py' 2>/dev/null | grep -v 'example\|test\|TODO\|#' || true",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.stdout.strip():
            print_error(f"Potential {desc} found!")
            print(result.stdout[:500])
            secrets_found = True
    
    if not secrets_found:
        print_success("No hardcoded secrets detected")
    
    # 3.2 Check .env files
    env_files = list(Path('.').glob('**/*.env'))
    if env_files:
        print_error(f"Found .env files that shouldn't be in git: {[f.name for f in env_files]}")
        failed.append(".env files in repository")
    else:
        print_success("No .env files in repository")
    
    print_header("Summary")
    
    print(f"\n{Colors.BLUE}Results:{Colors.END}\n")
    
    if failed:
        print_error(f"Failed checks: {len(failed)}")
        for f in failed:
            print(f"  - {f}")
    
    if warnings:
        print_warning(f"Warnings: {len(warnings)}")
        for w in warnings:
            print(f"  - {w}")
    
    if not failed and not warnings:
        print_success("All checks passed!")
        print("\n✓ Your code is ready to push to GitHub!")
        print("\nNext step: git push origin main")
        return 0
    elif not failed:
        print_warning("\nChecks passed with warnings")
        print("\nYou can push, but consider fixing warnings first:")
        print("  make format    # Fix formatting")
        print("  make lint      # Fix linting")
        return 0
    else:
        print_error("\nChecks failed! Please fix errors before pushing.")
        print("\nFix commands:")
        print("  make format    # Fix formatting")
        print("  make lint      # Fix linting")
        print("  make test      # Run tests")
        return 1

if __name__ == "__main__":
    sys.exit(main())
