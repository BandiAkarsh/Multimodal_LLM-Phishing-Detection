#!/bin/bash
#
# Local GitHub Actions Simulator
# Run this script locally to test your code before pushing to GitHub
# This mimics the GitHub Actions CI pipeline
#

set -e  # Exit on error

echo "=========================================="
echo "GitHub Actions CI - Local Simulator"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED=0

# Function to print section headers
print_header() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}✗ $1${NC}"
    FAILED=1
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

#######################################
# JOB 1: Code Quality (ci.yml)
#######################################
print_header "JOB 1: Code Quality Checks"

echo ""
echo "Installing dependencies..."
pip install -q black flake8 isort mypy pylint bandit 2>/dev/null || true

echo ""
echo "1.1 Checking code formatting with black..."
if black --check --diff 04_inference/ 05_utils/ detect_enhanced.py email_scanner.py 2>/dev/null; then
    print_success "Black formatting check passed"
else
    print_warning "Black formatting issues found (run 'make format' to fix)"
fi

echo ""
echo "1.2 Checking import sorting with isort..."
if isort --check-only --diff 04_inference/ 05_utils/ 2>/dev/null; then
    print_success "Import sorting check passed"
else
    print_warning "Import sorting issues found"
fi

echo ""
echo "1.3 Running flake8 linter (critical errors only)..."
if flake8 04_inference/ 05_utils/ --count --select=E9,F63,F7,F82 --show-source --statistics; then
    print_success "No critical flake8 errors"
else
    print_error "Critical flake8 errors found!"
fi

echo ""
echo "1.4 Running full flake8 linting..."
FLAKE8_OUTPUT=$(flake8 04_inference/ 05_utils/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics 2>&1)
FLAKE8_COUNT=$(echo "$FLAKE8_OUTPUT" | tail -1)
if [ "$FLAKE8_COUNT" = "0" ]; then
    print_success "Flake8 linting passed"
else
    print_warning "Flake8 found $FLAKE8_COUNT warnings (non-critical)"
    echo "$FLAKE8_OUTPUT"
fi

echo ""
echo "1.5 Type checking with mypy..."
if mypy 04_inference/ 05_utils/ --ignore-missing-imports 2>/dev/null; then
    print_success "Type checking passed"
else
    print_warning "Type checking issues found"
fi

echo ""
echo "1.6 Security lint with bandit..."
if bandit -r 04_inference/ 05_utils/ -f json -o /tmp/bandit-report.json 2>/dev/null; then
    print_success "Bandit security check passed"
else
    print_warning "Bandit security issues found (check /tmp/bandit-report.json)"
fi

#######################################
# JOB 2: Testing (ci.yml)
#######################################
print_header "JOB 2: Running Tests"

echo ""
echo "Installing test dependencies..."
pip install -q pytest pytest-cov pytest-asyncio pytest-mock 2>/dev/null || true

echo ""
echo "2.1 Running security tests..."
if [ -f "test_security.py" ]; then
    if python -m pytest test_security.py -v --tb=short 2>/dev/null; then
        print_success "Security tests passed"
    else
        print_error "Security tests failed"
    fi
else
    print_warning "test_security.py not found"
fi

echo ""
echo "2.2 Running comprehensive tests..."
if [ -f "test_comprehensive.py" ]; then
    if python -m pytest test_comprehensive.py -v --tb=short 2>/dev/null; then
        print_success "Comprehensive tests passed"
    else
        print_error "Comprehensive tests failed"
    fi
else
    print_warning "test_comprehensive.py not found"
fi

echo ""
echo "2.3 Running tests with coverage..."
if [ -d "tests/" ]; then
    if python -m pytest tests/ -v --cov=04_inference --cov=05_utils --cov-report=term-missing --cov-report=xml 2>/dev/null; then
        print_success "Tests with coverage passed"
    else
        print_warning "Some tests failed (check output above)"
    fi
else
    print_warning "tests/ directory not found"
fi

#######################################
# JOB 3: Security Scan (ci.yml)
#######################################
print_header "JOB 3: Security Scanning"

echo ""
echo "3.1 Checking for secrets with GitLeaks..."
if command -v gitleaks &> /dev/null; then
    if gitleaks detect --source . --verbose 2>/dev/null; then
        print_success "No secrets detected"
    else
        print_error "Potential secrets found!"
    fi
else
    print_warning "GitLeaks not installed (install with: brew install gitleaks)"
    echo "   Manual check: Search for 'password', 'secret', 'key', 'token' in code"
fi

echo ""
echo "3.2 Dependency vulnerability scan..."
if command -v safety &> /dev/null; then
    if safety check -r requirements.txt 2>/dev/null; then
        print_success "No dependency vulnerabilities found"
    else
        print_warning "Dependency vulnerabilities found (check output)"
    fi
else
    print_warning "Safety not installed (install with: pip install safety)"
fi

echo ""
echo "3.3 Manual secret check..."
# Search for potential secrets in Python files
echo "   Searching for potential secrets in code..."
if grep -r "password.*=.*['\"]" 04_inference/ 05_utils/ --include="*.py" 2>/dev/null | grep -v "example\|test\|TODO\|#"; then
    print_error "Potential hardcoded passwords found!"
else
    print_success "No hardcoded passwords detected"
fi

#######################################
# JOB 4: Docker Build (ci.yml)
#######################################
print_header "JOB 4: Docker Build Test"

if command -v docker &> /dev/null; then
    echo ""
    echo "4.1 Testing Docker build..."
    if docker build -t phishing-guard:test . 2>&1 | tail -20; then
        print_success "Docker build successful"
        
        echo ""
        echo "4.2 Testing Docker image..."
        if docker run --rm phishing-guard:test python --version 2>/dev/null; then
            print_success "Docker image runs successfully"
        else
            print_error "Docker image test failed"
        fi
    else
        print_error "Docker build failed"
    fi
else
    print_warning "Docker not installed, skipping Docker tests"
fi

#######################################
# Summary
#######################################
print_header "CI Summary"

echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All critical checks passed!${NC}"
    echo ""
    echo "Your code is ready to push to GitHub!"
    echo ""
    echo "Next steps:"
    echo "  git push origin main"
    exit 0
else
    echo -e "${RED}✗ Some checks failed!${NC}"
    echo ""
    echo "Please fix the errors above before pushing."
    echo ""
    echo "Common fixes:"
    echo "  make format          # Fix formatting"
    echo "  make lint            # Fix linting"
    echo "  make test            # Run tests"
    exit 1
fi
