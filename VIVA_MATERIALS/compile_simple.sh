#!/bin/bash
# Simple LaTeX to PDF compile (should work on Overleaf or local)

echo "Compiling viva_presentation.tex..."
pdflatex viva_presentation.tex
echo "✓ viva_presentation.pdf created"

echo
echo "Compiling viva_report.tex..."
pdflatex viva_report.tex
echo "✓ viva_report.pdf created"

echo
echo "Done! Open the PDF files in your folder."
