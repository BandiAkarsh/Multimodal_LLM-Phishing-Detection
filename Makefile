.PHONY: help install install-dev test test-unit test-integration test-security lint format security clean docker-build docker-run docs

# Default target
help:
	@echo "Phishing Detection Project - Development Commands"
	@echo "================================================="
	@echo ""
	@echo "Setup:"
	@echo "  make setup           - Set up development environment"
	@echo "  make install         - Install production dependencies"
	@echo "  make install-dev     - Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  make test            - Run all tests"
	@echo "  make test-unit       - Run unit tests only"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-security   - Run security tests"
	@echo "  make coverage        - Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint            - Run all linters (flake8, mypy)"
	@echo "  make format          - Format code with black and isort"
	@echo "  make format-check    - Check code formatting"
	@echo "  make security        - Run security scans (bandit, safety)"
	@echo ""
	@echo "Pre-commit:"
	@echo "  make precommit       - Run pre-commit hooks on all files"
	@echo "  make precommit-install - Install pre-commit hooks"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build    - Build Docker image"
	@echo "  make docker-run      - Run Docker container"
	@echo "  make docker-compose  - Run with docker-compose"
	@echo ""
	@echo "Development Server:"
	@echo "  make run             - Run development server"
	@echo "  make run-https       - Run with HTTPS"
	@echo "  make run-prod        - Run production server"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make clean-all       - Clean everything including venv"
	@echo "  make update          - Update dependencies"

# ==========================================
# Setup
# ==========================================
setup:
	chmod +x scripts/setup_dev.sh
	./scripts/setup_dev.sh

install:
	pip install -r requirements.txt

install-dev: install
	pip install pre-commit black isort flake8 flake8-docstrings flake8-bugbear mypy bandit pytest pytest-cov pytest-asyncio pytest-mock
	pre-commit install

# ==========================================
# Testing
# ==========================================
test:
	pytest tests/ -v --tb=short

test-unit:
	pytest tests/ -v -m unit --tb=short

test-integration:
	pytest tests/ -v -m integration --tb=short

test-security:
	pytest test_security.py -v --tb=short

test-comprehensive:
	pytest test_comprehensive.py -v --tb=short

coverage:
	pytest tests/ -v --cov=04_inference --cov=05_utils --cov-report=term-missing --cov-report=html
	@echo "Coverage report generated in htmlcov/"

# ==========================================
# Code Quality
# ==========================================
lint:
	@echo "Running flake8..."
	flake8 04_inference/ 05_utils/ detect_enhanced.py email_scanner.py --max-line-length=100 --extend-ignore=E203,W503
	@echo "Running mypy..."
	mypy 04_inference/ 05_utils/ --ignore-missing-imports

format:
	@echo "Running black..."
	black 04_inference/ 05_utils/ detect_enhanced.py email_scanner.py
	@echo "Running isort..."
	isort 04_inference/ 05_utils/

format-check:
	@echo "Checking black formatting..."
	black --check 04_inference/ 05_utils/ detect_enhanced.py email_scanner.py
	@echo "Checking isort formatting..."
	isort --check-only 04_inference/ 05_utils/

security:
	@echo "Running bandit..."
	bandit -r 04_inference/ 05_utils/ -f json -o bandit-report.json || true
	bandit -r 04_inference/ 05_utils/
	@echo "Running safety check..."
	safety check -r requirements.txt || true

# ==========================================
# Pre-commit
# ==========================================
precommit:
	pre-commit run --all-files

precommit-install:
	pre-commit install

# ==========================================
# Docker
# ==========================================
docker-build:
	docker build -t phishing-guard:latest .

docker-run:
	docker run -p 8000:8000 -e JWT_SECRET=$${JWT_SECRET} phishing-guard:latest

docker-compose:
	docker-compose up -d

docker-compose-down:
	docker-compose down

docker-compose-logs:
	docker-compose logs -f

# ==========================================
# Development Server
# ==========================================
run:
	cd 04_inference && uvicorn api:app --host 0.0.0.0 --port 8000 --reload

run-https:
	ENABLE_HTTPS=true cd 04_inference && python api.py

run-prod:
	cd 04_inference && uvicorn api:app --host 0.0.0.0 --port 8000 --workers 4

# ==========================================
# Maintenance
# ==========================================
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .eggs/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf bandit-report.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete

clean-all: clean
	rm -rf venv/
	rm -rf .venv/

update:
	pip install --upgrade -r requirements.txt

# ==========================================
# Browser Extension
# ==========================================
extension-pack:
	cd browser-extension && zip -r ../phishing-guard-extension.zip . -x "*.git*" -x "node_modules/*"
	@echo "Extension packed: phishing-guard-extension.zip"
