#!/bin/bash
# Convert LaTeX Beamer to PowerPoint (PPTX) via Pandoc

set -e

echo "=== Converting to PowerPoint (PPTX) ==="
echo

# Check pandoc exists
if ! command -v pandoc &> /dev/null; then
    echo "ERROR: pandoc not found!"
    echo "Install: https://pandoc.org/installing.html"
    exit 1
fi

# Convert to PPTX
echo "Converting presentation.tex → presentation.pptx..."
pandoc presentation.tex \
    --slide-level 2 \
    -t pptx \
    -o presentation.pptx \
    --variable fontsize=24pt \
    2>&1 | grep -v "\\[WARNING\\]" || true

if [ -f "presentation.pptx" ]; then
    echo "✓ Created: presentation.pptx"
    echo
    echo "Note: PPTX conversion is approximate. Review and tweak in PowerPoint."
else
    echo "Conversion may have issues. Check output above."
fi
