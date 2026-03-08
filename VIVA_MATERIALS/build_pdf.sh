#!/bin/bash
# Convert LaTeX Beamer to PDF (for viva presentation)

set -e

echo "=== Building PDF Presentation ==="
echo

# Check pdflatex exists
if ! command -v pdflatex &> /dev/null; then
    echo "ERROR: pdflatex not found!"
    echo "Install: sudo apt-get install texlive-latex-base"
    exit 1
fi

# Compile (2 passes for TOC)
echo "Pass 1..."
pdflatex -interaction=nonstopmode presentation.tex > /dev/null
echo "Pass 2 (TOC)..."
pdflatex -interaction=nonstopmode presentation.tex > /dev/null

echo
echo "✓ Created: presentation.pdf"
echo
echo "Open presentation.pdf for your viva slides!"
