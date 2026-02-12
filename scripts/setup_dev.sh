#!/bin/bash
# Setup script for development environment
# Run this script to set up pre-commit hooks and development dependencies

set -e

echo "=============================================="
echo "Phishing Detection Project - Development Setup"
echo "=============================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

if ! python3 -c "import sys; assert sys.version_info >= (3, 11)" 2>/dev/null; then
    echo -e "${RED}Error: Python 3.11+ is required${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python version check passed${NC}"

# Install/upgrade pip
echo -e "\n${YELLOW}Installing/upgrading pip...${NC}"
python3 -m pip install --upgrade pip

# Install development dependencies
echo -e "\n${YELLOW}Installing development dependencies...${NC}"
pip install \
    pre-commit \
    black \
    isort \
    flake8 \
    flake8-docstrings \
    flake8-bugbear \
    flake8-comprehensions \
    mypy \
    bandit \
    pytest \
    pytest-cov \
    pytest-asyncio \
    pytest-mock

echo -e "${GREEN}✓ Development dependencies installed${NC}"

# Install pre-commit hooks
echo -e "\n${YELLOW}Setting up pre-commit hooks...${NC}"
if [ -f ".pre-commit-config.yaml" ]; then
    pre-commit install
    echo -e "${GREEN}✓ Pre-commit hooks installed${NC}"
    
    # Run pre-commit on all files to initialize
    echo -e "\n${YELLOW}Running initial pre-commit check (this may take a while)...${NC}"
    pre-commit run --all-files || true
else
    echo -e "${RED}Warning: .pre-commit-config.yaml not found${NC}"
fi

# Create necessary directories
echo -e "\n${YELLOW}Creating necessary directories...${NC}"
mkdir -p .git/hooks
mkdir -p certs
mkdir -p logs
mkdir -p 08_logs

echo -e "${GREEN}✓ Directories created${NC}"

# Check for environment variables template
echo -e "\n${YELLOW}Setting up environment configuration...${NC}"
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file from template${NC}"
    echo -e "${YELLOW}⚠ Please edit .env file and set your JWT_SECRET${NC}"
else
    echo -e "${YELLOW}⚠ .env file already exists or template not found${NC}"
fi

# Generate JWT secret if not set
if [ -z "$JWT_SECRET" ]; then
    echo -e "\n${YELLOW}Generating JWT_SECRET for development...${NC}"
    jwt_secret=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "Generated JWT_SECRET: $jwt_secret"
    echo -e "${YELLOW}Add this to your .env file:${NC}"
    echo "JWT_SECRET=$jwt_secret"
fi

echo ""
echo "=============================================="
echo -e "${GREEN}✓ Development environment setup complete!${NC}"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Edit .env file and set required variables"
echo "  2. Run 'make install' to install project dependencies"
echo "  3. Run 'make test' to verify everything works"
echo "  4. Run 'pre-commit run --all-files' to check code quality"
echo ""
echo "Available make commands:"
echo "  make install     - Install all dependencies"
echo "  make test        - Run all tests"
echo "  make lint        - Run linters"
echo "  make format      - Format code with black and isort"
echo "  make security    - Run security checks"
echo "  make clean       - Clean build artifacts"
echo ""
