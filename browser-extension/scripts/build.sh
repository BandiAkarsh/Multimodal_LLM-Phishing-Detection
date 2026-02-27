#!/bin/bash

# Phishing Guard Extension Build Script (Bash Version)
# Alternative to Node.js build script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
EXTENSION_NAME="phishing-guard"
VERSION="2.0.0"
DIST_DIR="dist"
ASSETS_DIR="store-assets"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       Phishing Guard Extension Build System               ║"
echo "║              Chrome Web Store Ready                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if running from correct directory
if [ ! -f "manifest.json" ]; then
    echo -e "${RED}[ERROR]${NC} manifest.json not found. Please run from browser-extension directory."
    exit 1
fi

# Parse arguments
CLEAN_FIRST=false
CREATE_ZIP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN_FIRST=true
            shift
            ;;
        --zip|--dist)
            CREATE_ZIP=true
            shift
            ;;
        *)
            echo -e "${YELLOW}[WARNING]${NC} Unknown option: $1"
            shift
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN_FIRST" = true ]; then
    echo -e "${BLUE}[INFO]${NC} Cleaning dist directory..."
    rm -rf "$DIST_DIR"
fi

# Create dist directory
mkdir -p "$DIST_DIR"
echo -e "${BLUE}[INFO]${NC} Created dist directory"

# Files to include
declare -a FILES=(
    "manifest.json"
    "background.js"
    "content.js"
    "popup.html"
    "popup.js"
    "popup.css"
    "styles.css"
)

# Copy files
echo -e "${BLUE}[INFO]${NC} Copying extension files..."
COPIED=0
MISSING=0

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        cp "$file" "$DIST_DIR/"
        echo -e "${GREEN}[OK]${NC} Copied: $file"
        ((COPIED++))
    else
        echo -e "${YELLOW}[MISSING]${NC} $file"
        ((MISSING++))
    fi
done

# Copy images
echo -e "${BLUE}[INFO]${NC} Copying images..."
mkdir -p "$DIST_DIR/images"

for size in 16 48 128; do
    if [ -f "images/icon${size}.png" ]; then
        cp "images/icon${size}.png" "$DIST_DIR/images/"
        echo -e "${GREEN}[OK]${NC} Copied: icon${size}.png"
        ((COPIED++))
    else
        echo -e "${YELLOW}[MISSING]${NC} icon${size}.png"
        ((MISSING++))
    fi
done

# Validate manifest
echo -e "${BLUE}[INFO]${NC} Validating manifest.json..."
if [ ! -f "$DIST_DIR/manifest.json" ]; then
    echo -e "${RED}[ERROR]${NC} manifest.json not found in dist"
    exit 1
fi

# Check manifest_version
MANIFEST_VERSION=$(grep -o '"manifest_version": *[0-9]*' "$DIST_DIR/manifest.json" | grep -o '[0-9]*')
if [ "$MANIFEST_VERSION" != "3" ]; then
    echo -e "${YELLOW}[WARNING]${NC} manifest_version should be 3 for Chrome Web Store"
else
    echo -e "${GREEN}[OK]${NC} manifest_version is 3"
fi

# Calculate size
echo -e "${BLUE}[INFO]${NC} Calculating package size..."
SIZE=$(du -sh "$DIST_DIR" | cut -f1)
echo -e "${BLUE}[INFO]${NC} Package size: $SIZE"

# Create build info
cat > "$DIST_DIR/build-info.json" << EOF
{
  "version": "$VERSION",
  "buildDate": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "files": $(printf '%s\n' "${FILES[@]}" | jq -R . | jq -s .),
  "builtBy": "bash"
}
EOF
echo -e "${GREEN}[OK]${NC} Created build-info.json"

# Create ZIP if requested
if [ "$CREATE_ZIP" = true ]; then
    echo -e "${BLUE}[INFO]${NC} Creating ZIP package..."
    
    ZIP_NAME="${EXTENSION_NAME}-v${VERSION}.zip"
    
    cd "$DIST_DIR"
    zip -r "$ZIP_NAME" . -x "*.zip"
    cd ..
    
    if [ -f "$DIST_DIR/$ZIP_NAME" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Created: $DIST_DIR/$ZIP_NAME"
        
        # Calculate ZIP size
        ZIP_SIZE=$(du -h "$DIST_DIR/$ZIP_NAME" | cut -f1)
        echo -e "${BLUE}[INFO]${NC} ZIP size: $ZIP_SIZE"
    else
        echo -e "${RED}[ERROR]${NC} Failed to create ZIP"
        exit 1
    fi
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  BUILD SUCCESSFUL!                        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Distribution package: $DIST_DIR/$ZIP_NAME"
    echo ""
    echo "Next steps:"
    echo "  1. Upload to Chrome Web Store Developer Dashboard"
    echo "  2. Or distribute the ZIP file directly"
    echo "  3. Update store-assets/ with screenshots"
    echo ""
else
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║              BUILD COMPLETED SUCCESSFULLY                 ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Output directory: $DIST_DIR/"
    echo ""
    echo "To create a ZIP package, run:"
    echo "  ./build.sh --zip"
    echo ""
fi

echo -e "${GREEN}Files copied: $COPIED${NC}"
if [ $MISSING -gt 0 ]; then
    echo -e "${YELLOW}Files missing: $MISSING${NC}"
fi
