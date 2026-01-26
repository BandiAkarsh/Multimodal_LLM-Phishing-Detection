# Docker Deployment Documentation

## Overview

This document explains how to deploy the phishing detection system using Docker. Docker allows you to run the application in an isolated container with all dependencies included.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Builds the Docker image |
| `docker-compose.yml` | Orchestrates multiple containers |
| `.dockerignore` | Files to exclude from build |

---

## Quick Start

```bash
# Build and run
docker-compose up --build

# Access API at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

---

## Dockerfile Explained

```dockerfile
# Base image with Python 3.11
FROM python:3.11-slim
```
**Line 1:** Start with a lightweight Python image.

```dockerfile
# Set working directory
WORKDIR /app
```
**Line 4:** All commands will run from `/app`.

```dockerfile
# Install system dependencies including Playwright requirements
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    # ... more libraries for Playwright
    && rm -rf /var/lib/apt/lists/*
```
**Lines 7-22:** Install system libraries needed for:
- Building Python packages
- Running Playwright browser
- Making HTTP requests for health checks

```dockerfile
# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright and browsers
RUN pip install playwright && playwright install chromium
```
**Lines 24-28:** Install Python dependencies:
- All packages from `requirements.txt`
- Playwright for web scraping
- Chromium browser for scraping

```dockerfile
# Copy application code
COPY 02_models/ ./02_models/
COPY 04_inference/ ./04_inference/
COPY 05_utils/ ./05_utils/
COPY 07_configs/ ./07_configs/
```
**Lines 30-34:** Copy only necessary folders (not training data or notebooks).

```dockerfile
# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOAD_MLLM=false
ENV PORT=8000
```
**Lines 36-39:** Configure the application:
- `PYTHONUNBUFFERED`: Real-time logging
- `LOAD_MLLM`: Don't load heavy MLLM model by default
- `PORT`: API port

```dockerfile
# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
```
**Lines 44-45:** Automatic health monitoring:
- Check every 30 seconds
- Wait 10 seconds for startup
- Mark unhealthy after 3 failures

```dockerfile
# Run the API
WORKDIR /app/04_inference
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
```
**Lines 47-48:** Start the FastAPI server when container runs.

---

## docker-compose.yml Explained

```yaml
version: '3.8'

services:
  # Main API Service
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
```
**Lines 1-10:** Define the main API service:
- Build from Dockerfile
- Expose port 8000

```yaml
    environment:
      - LOAD_MLLM=false
      - PORT=8000
      - CONNECTIVITY_CHECK_INTERVAL=30
      - SCRAPING_TIMEOUT=30000
```
**Lines 11-16:** Environment configuration:
- Don't load MLLM (saves memory)
- Check connectivity every 30 seconds
- 30-second timeout for scraping

```yaml
    volumes:
      - ./02_models:/app/02_models:ro
```
**Lines 17-18:** Mount models folder read-only. This allows updating models without rebuilding.

```yaml
    dns:
      - 8.8.8.8
      - 1.1.1.1
```
**Lines 20-22:** Configure DNS servers for internet connectivity checks.

```yaml
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
```
**Lines 23-28:** Health check configuration.

```yaml
  # Redis Cache
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
```
**Lines 31-37:** Redis cache service for production caching (optional).

```yaml
networks:
  phishing_net:
    name: phishing_detection_network
    driver: bridge
```
**Lines 53-56:** Create isolated network for containers.

---

## Deployment Commands

### Build Image

```bash
# Build the Docker image
docker build -t phishing-detector .

# Build with docker-compose
docker-compose build
```

### Run Container

```bash
# Run with docker-compose (recommended)
docker-compose up

# Run in background
docker-compose up -d

# Run single container
docker run -p 8000:8000 phishing-detector
```

### View Logs

```bash
# All services
docker-compose logs -f

# Just API
docker-compose logs -f api
```

### Stop Services

```bash
# Stop and remove containers
docker-compose down

# Stop and remove volumes too
docker-compose down -v
```

### Check Health

```bash
# Check container status
docker-compose ps

# Check API health
curl http://localhost:8000/health
```

---

## Production Deployment

### With HTTPS (Using Nginx)

Uncomment the nginx service in `docker-compose.yml` and create `nginx.conf`:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### With GPU (For MLLM)

```yaml
services:
  api:
    # ... other config ...
    environment:
      - LOAD_MLLM=true
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

### Scaling

```bash
# Run 3 instances of API
docker-compose up --scale api=3
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs api

# Common issues:
# - Port 8000 already in use
# - Model files missing
# - Out of memory
```

### Health check failing

```bash
# Check if API is responding
curl http://localhost:8000/health

# Check inside container
docker-compose exec api curl http://localhost:8000/health
```

### No internet connectivity

```bash
# Check DNS resolution inside container
docker-compose exec api ping 8.8.8.8

# Verify DNS settings in docker-compose.yml
```

### Models not found

```bash
# Ensure models are mounted
docker-compose exec api ls -la /app/02_models/

# Should show:
# phishing_classifier.joblib
# feature_scaler.joblib
# feature_columns.joblib
```

---

## Resource Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 2 GB | 4 GB |
| Disk | 2 GB | 5 GB |
| GPU | Not required | Optional (for MLLM) |

---

*This documentation explains Docker deployment for beginners.*
