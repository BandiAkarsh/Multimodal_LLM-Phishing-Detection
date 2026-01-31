#!/bin/bash
# Setup script for MLflow and Tauri

echo "=================================="
echo "Phishing Guard v2.0 - Setup Script"
echo "=================================="
echo ""

# Check Python packages
echo "[1] Checking Python packages..."
python3 -c "import mlflow; print('✓ MLflow:', mlflow.__version__)" 2>/dev/null || echo "✗ MLflow not installed"
python3 -c "import bentoml; print('✓ BentoML:', bentoml.__version__)" 2>/dev/null || echo "✗ BentoML not installed"

echo ""
echo "[2] Checking Tauri installation..."
if command -v cargo &> /dev/null; then
    echo "✓ Rust/Cargo installed"
    cargo --version
else
    echo "✗ Rust not installed"
    echo "  Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi

if command -v tauri &> /dev/null; then
    echo "✓ Tauri CLI installed"
else
    echo "✗ Tauri CLI not installed"
    echo "  Install: cargo install tauri-cli"
fi

echo ""
echo "[3] Checking MLflow tracking..."
if [ -d "./mlruns" ]; then
    echo "✓ MLflow runs directory exists"
    echo "  Runs: $(ls -1 ./mlruns | wc -l)"
else
    echo "ℹ No MLflow runs yet (will be created on first training)"
fi

echo ""
echo "=================================="
echo "Setup Status"
echo "=================================="
echo ""
echo "To use MLflow model management:"
echo "  python 03_training/train_with_mlflow.py"
echo ""
echo "To view MLflow UI:"
echo "  mlflow ui --backend-store-uri ./mlruns"
echo ""
echo "To install Tauri (requires ~600MB):"
echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
echo "  cargo install tauri-cli"
echo "  cd gui-tauri && npm install && npm run tauri dev"
echo ""
