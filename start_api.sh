#!/bin/bash
# Start script for Phishing Detection API
# Usage: ./start_api.sh

export JWT_SECRET="testsecret123456789012345678901234567890"  # 32+ chars
export LOAD_MLLM=false

cd "$(dirname "$0")"

echo "Starting Phishing Detection API..."
echo "JWT_SECRET set (demo mode)"
echo "MLLM disabled for faster startup"
echo ""
echo "API will be available at: http://localhost:8000"
echo "Swagger docs at: http://localhost:8000/docs"
echo ""

uvicorn 04_inference.api:app --host 0.0.0.0 --port 8000 --reload
