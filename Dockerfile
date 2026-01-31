# Phishing Guard v2.0 - API Server Docker Image
# Author: Akarsh <akarshbandi82@gmail.com>
# GitHub: https://github.com/BandiAkarsh
# LinkedIn: https://www.linkedin.com/in/bandi-akarsh-b9339330a/
#
# This is the FULL FastAPI server for development/testing.
# For lightweight 24/7 background protection, use the Daemon instead:
#   sudo dpkg -i ~/phishing-guard_2.0.0-1_all.deb
#
# Related Projects:
# - Daemon Service: ~/phishing-guard-daemon/ (166KB, systemd service)
# - Tauri GUI: ~/phishing-guard-tauri/ (3.8MB, desktop app)
# - Main Project: ~/phishing_detection_project/ (this repo)
#
# Features:
# - 93 ML features with 99.7% accuracy
# - Full FastAPI with authentication & security
# - MLLM support (Qwen/Ollama)
# - Web scraping with Playwright
# - Swagger UI at /docs

FROM python:3.11-slim

# Metadata
LABEL maintainer="Akarsh <akarshbandi82@gmail.com>"
LABEL version="2.0.0"
LABEL description="Phishing Guard API - AI-powered phishing detection"
LABEL github="https://github.com/BandiAkarsh"
LABEL project="IEEE Final Year Project"

# Set working directory
WORKDIR /app

# Install system dependencies including Playwright requirements
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    wget \
    # Playwright dependencies for web scraping
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libatspi2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libgtk-3-0 \
    libwebkit2gtk-4.0-37 \
    # Clean up to reduce image size
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first (for better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright and browsers for web scraping
RUN pip install playwright && \
    playwright install chromium && \
    playwright install-deps chromium

# Copy application code
# 01_data: TLD lists for domain validation
# 02_models: Trained ML models (Random Forest)
# 04_inference: FastAPI server, auth, security
# 05_utils: Feature extraction, TLS analysis, security validators
# 07_configs: Configuration files
COPY 01_data/ ./01_data/
COPY 02_models/ ./02_models/
COPY 04_inference/ ./04_inference/
COPY 05_utils/ ./05_utils/
COPY 07_configs/ ./07_configs/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOAD_MLLM=false
ENV PORT=8000
ENV HOST=0.0.0.0

# Create non-root user for security
RUN groupadd -r phishing && useradd -r -g phishing appuser \
    && chown -R appuser:phishing /app
USER appuser

# Expose port
EXPOSE 8000

# Health check - ensures container is healthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API server
WORKDIR /app/04_inference
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
