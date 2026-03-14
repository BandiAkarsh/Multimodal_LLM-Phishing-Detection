#!/bin/bash
# Phishing Guard Desktop Launcher

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXEC_DIR="$SCRIPT_DIR"

# Check if executable exists
if [ ! -f "$EXEC_DIR/phishing-guard-desktop" ]; then
    echo "Error: phishing-guard-desktop not found!"
    echo "Please download the latest release from GitHub."
    exit 1
fi

# Make sure it's executable
chmod +x "$EXEC_DIR/phishing-guard-desktop"

# Run the app
exec "$EXEC_DIR/phishing-guard-desktop" "$@"
