# Phishing Detection API - Docker Image
# Lightweight image for production deployment

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API
WORKDIR /app/04_inference
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
