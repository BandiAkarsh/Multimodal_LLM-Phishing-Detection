#!/bin/bash
# Build script for Viva Materials
# Converts LaTeX to PDF and optionally to PPTX

set -e

echo "================================"
echo "Viva Materials Build Script"
echo "================================"
echo

# Check if LaTeX is installed
if ! command -v pdflatex &> /dev/null; then
    echo "Error: pdflatex not found. Install TeX Live or MikTeX."
    exit 1
fi

# Check if pandoc is installed (for PPTX conversion)
PANDOC_AVAILABLE=false
if command -v pandoc &> /dev/null; then
    PANDOC_AVAILABLE=true
    echo "✓ Pandoc found (can convert to PPTX)"
else
    echo "⚠ Pandoc not found (PPTX conversion disabled)"
fi

cd "$(dirname "$0")"

# Build PDF from LaTeX source
echo
echo "Building PDF presentation..."
pdflatex -interaction=nonstopmode viva_presentation.tex
pdflatex -interaction=nonstopmode viva_presentation.tex  # Run twice for TOC
echo "✓ Created: viva_presentation.pdf"

echo
echo "Building PDF report..."
pdflatex -interaction=nonstopmode viva_report.tex
pdflatex -interaction=nonstopmode viva_report.tex  # Run twice for references
echo "✓ Created: viva_report.pdf"

# Optionally convert to PPTX via Pandoc
if [ "$PANDOC_AVAILABLE" = true ]; then
    echo
    read -p "Convert to PPTX? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Converting to PPTX..."
        pandoc viva_presentation.tex -t pptx -o viva_presentation.pptx
        echo "✓ Created: viva_presentation.pptx"
        
        echo "Converting report to PPTX..."
        pandoc viva_report.tex -t pptx -o viva_report.pptx
        echo "✓ Created: viva_report.pptx"
    fi
fi

echo
echo "================================"
echo "Build Complete!"
echo "================================"
echo
echo "Files created:"
echo "  - viva_presentation.pdf (30-slide presentation)"
echo "  - viva_report.pdf (comprehensive report)"
if [ "$PANDOC_AVAILABLE" = true ]; then
    echo "  - viva_presentation.pptx (optional)"
    echo "  - viva_report.pptx (optional)"
fi
echo
echo "Next steps:"
echo "  1. Review PDFs for formatting"
echo "  2. Customize with your specific details"
echo "  3. For PPTX: May need manual tweaking in PowerPoint"
