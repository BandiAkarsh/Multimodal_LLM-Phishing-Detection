# 🚀 Deployment Guide

Complete guide for deploying Phishing Guard to production environments.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Docker Deployment](#docker-deployment)
- [Environment Variables](#environment-variables)
- [SSL/HTTPS Configuration](#sslhttps-configuration)
- [Redis Configuration](#redis-configuration)
- [Scaling Considerations](#scaling-considerations)
- [Monitoring and Logging](#monitoring-and-logging)

## 📋 Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 10 GB | 20+ GB SSD |
| Network | 10 Mbps | 100+ Mbps |

### Software Requirements

- Docker 20.10+
- Docker Compose 2.0+
- (Optional) Kubernetes 1.24+

## 🐳 Docker Deployment

### Quick Start (Production)

```bash
# 1. Clone repository
git clone https://github.com/BandiAkarsh/phishing_detection_project.git
cd phishing_detection_project

# 2. Create production environment file
cp .env.example .env

# 3. Generate secure secrets
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
echo "JWT_SECRET=$JWT_SECRET" >> .env

# 4. Start services
docker-compose up -d

# 5. Verify deployment
curl http://localhost:8000/health
```

### Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    container_name: phishing-guard-api
    ports:
      - "8000:8000"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - JWT_EXPIRATION_HOURS=24
      - RATE_LIMIT_REQUESTS=100
      - RATE_LIMIT_WINDOW=60
      - REDIS_URL=redis://redis:6379/0
      - ENVIRONMENT=production
      - LOG_LEVEL=INFO
      - ENABLE_HTTPS=false
    volumes:
      - ./02_models:/app/02_models:ro
      - ./08_logs:/app/08_logs
    depends_on:
      - redis
    restart: unless-stopped
    networks:
      - frontend
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  redis:
    image: redis:7-alpine
    container_name: phishing-guard-redis
    volumes:
      - redis_data:/data
    restart: unless-stopped
    networks:
      - backend
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru

  nginx:
    image: nginx:alpine
    container_name: phishing-guard-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - api
    restart: unless-stopped
    networks:
      - frontend

volumes:
  redis_data:

networks:
  frontend:
    driver: bridge
  backend:
    internal: true
```

### Production Dockerfile

```dockerfile
# Dockerfile
FROM python:3.11-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy virtual environment
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Run application
CMD ["uvicorn", "04_inference.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Docker Commands Reference

```bash
# Build and start
docker-compose up -d --build

# View logs
docker-compose logs -f api
docker-compose logs -f redis

# Scale API instances
docker-compose up -d --scale api=3

# Restart services
docker-compose restart api
docker-compose restart redis

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Update images
docker-compose pull
docker-compose up -d

# Execute commands in container
docker-compose exec api python detect_enhanced.py https://example.com
docker-compose exec redis redis-cli
```

## 🔧 Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing secret (min 32 chars) | `a1b2c3d4e5f6...` |
| `ENVIRONMENT` | Deployment environment | `production` |

### Security Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_EXPIRATION_HOURS` | `24` | JWT token lifetime |
| `RATE_LIMIT_REQUESTS` | `100` | Requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8000` | Server port |
| `ENABLE_HTTPS` | `false` | Enable HTTPS |
| `SSL_CERT_PATH` | - | SSL certificate path |
| `SSL_KEY_PATH` | - | SSL private key path |

### Redis Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | - | Redis connection URL |
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database |

### Feature Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOAD_MLLM` | `false` | Enable MLLM analysis |
| `ENABLE_SCRAPING` | `true` | Enable web scraping |
| `ENABLE_TLS_ANALYSIS` | `true` | Enable TLS certificate checks |

### Complete Production .env

```bash
# ==========================================
# Phishing Guard - Production Environment
# ==========================================

# Security (REQUIRED)
JWT_SECRET=your-256-bit-secret-key-here-change-in-production
JWT_EXPIRATION_HOURS=24

# Server
HOST=0.0.0.0
PORT=8000
ENVIRONMENT=production
ENABLE_HTTPS=true
SSL_CERT_PATH=/certs/server.crt
SSL_KEY_PATH=/certs/server.key

# Rate Limiting
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=60

# Redis (Production Required)
REDIS_URL=redis://redis:6379/0

# Features
LOAD_MLLM=false
ENABLE_SCRAPING=true
ENABLE_TLS_ANALYSIS=true

# Logging
LOG_LEVEL=WARNING
LOG_FILE=/var/log/phishing-guard/api.log

# MLflow
MLFLOW_TRACKING_URI=./08_logs/mlruns
MLFLOW_EXPERIMENT_NAME=phishing_detection_prod

# Browser Extension
EXTENSION_API_URL=https://api.yourdomain.com
```

## 🔒 SSL/HTTPS Configuration

### Using Let's Encrypt

```bash
# 1. Install Certbot
sudo apt-get install certbot

# 2. Obtain certificate
sudo certbot certonly --standalone -d yourdomain.com

# 3. Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./certs/server.crt
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./certs/server.key

# 4. Set permissions
sudo chown $USER:$USER ./certs/*
chmod 600 ./certs/server.key

# 5. Auto-renewal (add to crontab)
0 12 * * * certbot renew --quiet --deploy-hook "docker-compose restart nginx"
```

### Using Nginx as Reverse Proxy

```nginx
# nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Upstream API
    upstream api_servers {
        server api:8000;
        keepalive 32;
    }

    # HTTP → HTTPS redirect
    server {
        listen 80;
        server_name yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name yourdomain.com;

        # SSL
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        # API endpoints
        location / {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://api_servers;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # Health check (no rate limit)
        location /health {
            proxy_pass http://api_servers/health;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
        }
    }
}
```

### Using Cloudflare

```bash
# 1. Update DNS to point to Cloudflare
# 2. Enable SSL/TLS encryption mode: Full (strict)
# 3. Create Origin Certificate in Cloudflare
# 4. Download and install on server

# Cloudflare configuration in nginx
server {
    listen 443 ssl http2;
    
    # Cloudflare Origin Certificate
    ssl_certificate /etc/nginx/certs/cloudflare_origin.crt;
    ssl_certificate_key /etc/nginx/certs/cloudflare_origin.key;
    
    # Verify Cloudflare connections
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    # ... add all Cloudflare IPs
    real_ip_header CF-Connecting-IP;
}
```

## 🔄 Redis Configuration

### Production Redis Setup

```yaml
# docker-compose.redis.yml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: phishing-guard-redis
    command: >
      redis-server
      --appendonly yes
      --appendfsync everysec
      --maxmemory 512mb
      --maxmemory-policy allkeys-lru
      --requirepass ${REDIS_PASSWORD}
      --bind 0.0.0.0
      --protected-mode yes
    volumes:
      - redis_data:/data
      - ./redis.conf:/usr/local/etc/redis/redis.conf:ro
    restart: always
    networks:
      - backend

volumes:
  redis_data:
    driver: local

networks:
  backend:
    internal: true
```

### Redis Configuration File

```conf
# redis.conf
# Memory management
maxmemory 512mb
maxmemory-policy allkeys-lru

# Persistence
appendonly yes
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# Security
requirepass your-strong-redis-password
rename-command FLUSHDB ""
rename-command FLUSHALL ""

# Performance
tcp-keepalive 300
timeout 0
tcp-backlog 511

# Logging
loglevel notice
```

### Redis Connection URL Format

```bash
# Basic
REDIS_URL=redis://localhost:6379/0

# With password
REDIS_URL=redis://:password@localhost:6379/0

# With username and password (Redis 6+)
REDIS_URL=redis://username:password@localhost:6379/0

# With SSL
REDIS_URL=rediss://:password@localhost:6379/0
```

## 📈 Scaling Considerations

### Horizontal Scaling with Docker Swarm

```yaml
# docker-compose.swarm.yml
version: '3.8'

services:
  api:
    image: phishing-guard:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        failure_action: rollback
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          cpus: '1'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - REDIS_URL=redis://redis:6379/0
    networks:
      - backend

  redis:
    image: redis:7-alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    volumes:
      - redis_data:/data
    networks:
      - backend

  nginx:
    image: nginx:alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    ports:
      - "80:80"
      - "443:443"
    networks:
      - backend

networks:
  backend:
    driver: overlay

volumes:
  redis_data:
    driver: local
```

```bash
# Initialize Docker Swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.swarm.yml phishing-guard

# Scale service
docker service scale phishing-guard_api=5

# View services
docker service ls

# View logs
docker service logs phishing-guard_api
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phishing-guard-api
  labels:
    app: phishing-guard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: phishing-guard
  template:
    metadata:
      labels:
        app: phishing-guard
    spec:
      containers:
      - name: api
        image: ghcr.io/bandiakarsh/phishing-guard:latest
        ports:
        - containerPort: 8000
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: phishing-guard-secrets
              key: jwt-secret
        - name: REDIS_URL
          value: "redis://redis:6379/0"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 📊 Monitoring and Logging

### Health Checks

```bash
# Basic health check
curl -f http://localhost:8000/health || echo "API is down"

# Detailed health check with jq
curl -s http://localhost:8000/health | jq

# Automated health monitoring script
#!/bin/bash
while true; do
    if ! curl -sf http://localhost:8000/health > /dev/null; then
        echo "$(date): API is down, restarting..."
        docker-compose restart api
    fi
    sleep 30
done
```

### Logging Configuration

```python
# 07_configs/logging.conf
[loggers]
keys=root,api

[handlers]
keys=console,file

[formatters]
keys=standard

[logger_root]
level=WARNING
handlers=console

[logger_api]
level=INFO
handlers=console,file
qualname=api
propagate=0

[handler_console]
class=StreamHandler
level=INFO
formatter=standard
args=(sys.stdout,)

[handler_file]
class=handlers.RotatingFileHandler
level=INFO
formatter=standard
args=('/var/log/phishing-guard/api.log', 'maxBytes=10485760', 'backupCount=5')

[formatter_standard]
format=%(asctime)s [%(levelname)s] %(name)s: %(message)s
datefmt=%Y-%m-%d %H:%M:%S
```

### Prometheus Metrics (Optional)

```python
# Add to api.py
from prometheus_client import Counter, Histogram, generate_latest

REQUEST_COUNT = Counter('api_requests_total', 'Total requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('api_request_duration_seconds', 'Request duration')

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    REQUEST_COUNT.labels(method=request.method, endpoint=request.url.path).inc()
    with REQUEST_DURATION.time():
        response = await call_next(request)
    return response

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### Log Rotation

```bash
# /etc/logrotate.d/phishing-guard
/var/log/phishing-guard/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 appuser appuser
    sharedscripts
    postrotate
        docker-compose kill -s USR1 api
    endscript
}
```

## 🔄 Backup and Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/phishing-guard"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup Redis
docker-compose exec -T redis redis-cli BGSAVE
docker cp phishing-guard-redis:/data/dump.rdb "$BACKUP_DIR/redis_$DATE.rdb"

# Backup models
tar -czf "$BACKUP_DIR/models_$DATE.tar.gz" 02_models/

# Backup logs
tar -czf "$BACKUP_DIR/logs_$DATE.tar.gz" 08_logs/

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.rdb" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### Recovery Procedure

```bash
#!/bin/bash
# restore.sh

BACKUP_FILE=$1

# Stop services
docker-compose down

# Restore Redis
docker-compose up -d redis
docker cp "$BACKUP_FILE" phishing-guard-redis:/data/dump.rdb
docker-compose restart redis

# Restore models
tar -xzf models_backup.tar.gz

# Start services
docker-compose up -d

echo "Restore completed"
```

## 🚨 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Port 8000 in use | `sudo lsof -i :8000` to find process |
| Permission denied | `sudo chown -R $USER:$USER 02_models/` |
| Redis connection failed | Check `REDIS_URL` and Redis container |
| Out of memory | Increase Docker memory limit |
| Model not found | Ensure models are in `02_models/` |

### Debug Commands

```bash
# Check container status
docker-compose ps
docker-compose logs api

# Check resource usage
docker stats

# Test API manually
curl -v http://localhost:8000/health

# Check network connectivity
docker-compose exec api ping redis
docker-compose exec api curl http://localhost:8000/health

# Inspect container
docker-compose exec api bash
```

---

**Deployment Version:** 2.0.0  
**Last Updated:** 2024-01-01
