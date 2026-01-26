# Phishing Detection API - Docker Image
# Full-featured image with web scraping support

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies including Playwright requirements
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    # Playwright dependencies
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
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright and browsers
RUN pip install playwright && playwright install chromium

# Copy application code
COPY 02_models/ ./02_models/
COPY 04_inference/ ./04_inference/
COPY 05_utils/ ./05_utils/
COPY 07_configs/ ./07_configs/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOAD_MLLM=false
ENV PORT=8000

# Expose port
EXPOSE 8000

# Health check with connectivity status
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API
WORKDIR /app/04_inference
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
