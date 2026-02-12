# 🤝 Contributing to Phishing Guard

Thank you for your interest in contributing to Phishing Guard! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Message Conventions](#commit-message-conventions)

## 📜 Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## 🚀 Development Setup

### Prerequisites

- **Python 3.11+**
- **Git**
- **Make** (optional, for convenience commands)
- **Docker** (optional, for containerized development)

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/phishing_detection_project.git
cd phishing_detection_project

# Add upstream remote
git remote add upstream https://github.com/BandiAkarsh/phishing_detection_project.git
```

### 2. Create Virtual Environment

```bash
# Using venv
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Using conda
conda create -n phishing-guard python=3.11
conda activate phishing-guard
```

### 3. Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Or use Make
make install-dev
```

### 4. Install Pre-commit Hooks

```bash
pre-commit install

# Or use Make
make precommit-install
```

### 5. Verify Setup

```bash
# Run tests to verify everything works
python test_security.py
python test_comprehensive.py

# Or use Make
make test
```

## 🎨 Code Style Guidelines

We use several tools to maintain code quality and consistency:

### Black - Code Formatting

We use **Black** for automatic code formatting:

```bash
# Format all code
black 04_inference/ 05_utils/ detect_enhanced.py email_scanner.py

# Check formatting without making changes
black --check 04_inference/ 05_utils/

# Or use Make
make format
make format-check
```

**Configuration:**
- Line length: 100 characters
- Target Python version: 3.11
- Configured in `pyproject.toml`

### isort - Import Sorting

We use **isort** for sorting imports:

```bash
# Sort imports
isort 04_inference/ 05_utils/

# Check import order
isort --check-only 04_inference/ 05_utils/
```

**Style:** Black-compatible profile

### Flake8 - Linting

We use **Flake8** for code linting:

```bash
# Run linter
flake8 04_inference/ 05_utils/ --max-line-length=100

# Or use Make
make lint
```

**Rules:**
- Max line length: 100
- Ignores: E203 (whitespace before ':'), W503 (line break before binary operator)

### mypy - Type Checking

We use **mypy** for static type checking:

```bash
# Run type checker
mypy 04_inference/ 05_utils/ --ignore-missing-imports
```

### Code Quality Checklist

Before submitting a PR, ensure:

- [ ] Code is formatted with Black
- [ ] Imports are sorted with isort
- [ ] No flake8 linting errors
- [ ] Type hints are added for new functions
- [ ] Docstrings follow Google style
- [ ] No bandit security warnings

## 🧪 Testing Requirements

### Test Structure

```
tests/
├── test_unit/           # Unit tests
├── test_integration/    # Integration tests
├── test_security/       # Security tests
└── conftest.py          # pytest fixtures
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test categories
pytest tests/ -v -m unit          # Unit tests only
pytest tests/ -v -m integration   # Integration tests
pytest tests/ -v -m security      # Security tests

# Run with coverage
pytest tests/ --cov=04_inference --cov=05_utils --cov-report=html

# Or use Make
make test
make test-unit
make test-integration
make test-security
make coverage
```

### Writing Tests

#### Unit Tests

```python
import pytest
from 05_utils.feature_extraction import URLFeatureExtractor

@pytest.mark.unit
def test_extract_features_basic():
    """Test basic feature extraction."""
    url = "https://example.com"
    features = URLFeatureExtractor.extract_features(url)
    
    assert 'url_length' in features
    assert features['is_https'] == 1
    assert features['url_length'] == len(url)
```

#### Security Tests

```python
import pytest
from 05_utils.security_validator import URLSecurityValidator

@pytest.mark.security
def test_ssrf_protection():
    """Test SSRF protection blocks private IPs."""
    validator = URLSecurityValidator()
    
    # Should block private IP
    is_valid, errors = validator.validate("http://192.168.1.1/admin")
    assert not is_valid
    assert any("private" in e.lower() for e in errors)
```

### Test Coverage

We aim for **minimum 80% code coverage** for critical paths. Run coverage reports:

```bash
pytest tests/ --cov=04_inference --cov=05_utils --cov-report=term-missing
```

## 🔄 Pull Request Process

### 1. Create a Branch

```bash
# Pull latest changes
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

**Branch Naming Conventions:**
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `security/description` - Security fixes

### 2. Make Changes

- Write clear, concise code
- Add tests for new functionality
- Update documentation as needed
- Follow code style guidelines

### 3. Commit Changes

```bash
git add .
git commit -m "feat: add new feature description"
```

See [Commit Message Conventions](#commit-message-conventions) for format.

### 4. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create PR via GitHub UI
```

### 5. PR Checklist

Before submitting, ensure:

- [ ] Branch is up to date with `main`
- [ ] All tests pass
- [ ] Code is formatted (Black, isort)
- [ ] Linting passes (flake8)
- [ ] Security scans pass (bandit)
- [ ] Documentation is updated
- [ ] PR description is clear and complete
- [ ] Linked to related issue(s)

### 6. PR Review Process

1. **Automated Checks:** CI runs tests, linting, and security scans
2. **Code Review:** Maintainers review code quality and design
3. **Feedback:** Address any requested changes
4. **Approval:** At least one approval required
5. **Merge:** Maintainers merge approved PRs

## 📝 Commit Message Conventions

We follow **Conventional Commits** specification:

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style changes (formatting, no logic change) |
| `refactor` | Code refactoring |
| `perf` | Performance improvements |
| `test` | Adding or updating tests |
| `chore` | Build process or auxiliary tool changes |
| `security` | Security fixes |

### Scopes

Common scopes for this project:
- `api` - API endpoints
- `auth` - Authentication
- `ml` - Machine learning models
- `features` - Feature extraction
- `security` - Security validators
- `docs` - Documentation
- `ci` - CI/CD workflows

### Examples

```bash
# Feature
feat(api): add batch URL analysis endpoint

# Bug fix
fix(security): prevent SSRF via IPv6 localhost

# Documentation
docs: update API authentication guide

# Security fix
security(auth): fix JWT token validation bypass

# With body
feat(ml): add 93rd feature - domain entropy

Added domain entropy calculation to improve detection
of algorithmically generated domains used in phishing.

Closes #123
```

### Breaking Changes

For breaking changes, add `!` or `BREAKING CHANGE:` in footer:

```
feat(api)!: change response format for analyze endpoint

BREAKING CHANGE: Response now returns nested 'result' object
instead of flat structure. Update client code accordingly.
```

## 🔧 Development Workflow

### Daily Development

```bash
# Start of day - sync with upstream
git fetch upstream
git checkout main
git merge upstream/main
git push origin main

# Make changes
git checkout -b feature/my-feature
# ... edit code ...

# Before committing - run quality checks
make format
make lint
make test

# Commit and push
git add .
git commit -m "feat: add my feature"
git push origin feature/my-feature
```

### Pre-commit Hooks

Pre-commit hooks run automatically on each commit:

1. **Trailing whitespace** removal
2. **JSON/YAML validation**
3. **Black** formatting
4. **isort** import sorting
5. **Flake8** linting
6. **Bandit** security scan
7. **Secrets detection**

To skip hooks temporarily (not recommended):
```bash
git commit -m "WIP" --no-verify
```

To run hooks manually:
```bash
pre-commit run --all-files
# Or
make precommit
```

## 🐛 Reporting Issues

### Bug Reports

Include:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)
- Relevant logs or error messages

### Feature Requests

Include:
- Clear description of the feature
- Use case and motivation
- Proposed implementation (if any)
- Alternatives considered

## 📚 Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [scikit-learn Documentation](https://scikit-learn.org/)
- [Black Documentation](https://black.readthedocs.io/)
- [Conventional Commits](https://www.conventionalcommits.org/)

## 💬 Questions?

- Open an issue for questions
- Contact: akarshbandi82@gmail.com
- LinkedIn: [bandi-akarsh-b9339330a](https://www.linkedin.com/in/bandi-akarsh-b9339330a/)

---

Thank you for contributing to Phishing Guard! 🛡️
