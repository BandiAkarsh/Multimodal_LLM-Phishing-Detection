#!/bin/bash
# Build script for Phishing Guard Desktop App
# Run this after installing system dependencies

echo "=================================="
echo "Phishing Guard Desktop Build Script"
echo "=================================="
echo ""

# Check if dependencies are installed
echo "Checking system dependencies..."
MISSING_DEPS=()

if ! pkg-config --exists gtk+-3.0; then
    MISSING_DEPS+=("libgtk-3-dev")
fi

if ! pkg-config --exists webkit2gtk-4.0; then
    MISSING_DEPS+=("libwebkit2gtk-4.0-dev")
fi

if ! pkg-config --exists appindicator3-0.1; then
    MISSING_DEPS+=("libappindicator3-dev")
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "⚠️  Missing system dependencies:"
    printf '  - %s\n' "${MISSING_DEPS[@]}"
    echo ""
    echo "Install with:"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y ${MISSING_DEPS[*]} librsvg2-dev patchelf"
    echo ""
    echo "After installing, run this script again."
    exit 1
fi

echo "✓ All system dependencies found"
echo ""

# Navigate to project
cd "$(dirname "$0")/gui-tauri"

# Install Node dependencies
echo "[1/3] Installing Node dependencies..."
npm install

# Build frontend
echo "[2/3] Building frontend..."
npm run build

# Build Tauri app
echo "[3/3] Building Tauri desktop app..."
npm run tauri build

echo ""
echo "=================================="
echo "Build Complete!"
echo "=================================="
echo ""
echo "Your app is at:"
echo "  src-tauri/target/release/bundle/"
echo ""
echo "To run the app:"
echo "  ./src-tauri/target/release/bundle/appimage/Phishing*.AppImage"
echo ""
