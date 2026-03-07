# Viva Materials - Phishing Detection System

This folder contains professional presentation and report materials for your final year project viva.

## Contents

| File | Purpose | Output Format |
|------|---------|---------------|
| `viva_presentation.tex` | 30-slide presentation (Beamer) | PDF (recommended) or PPTX |
| `viva_report.tex` | Comprehensive technical report | PDF (IEEE format) |
| `build.sh` | Build script to compile LaTeX | PDFs (+ PPTX optional) |

---

## Quick Start

### Option 1: Overleaf (Recommended)

1. Go to [overleaf.com](https://overleaf.com) and create a new project
2. Upload these files:
   - `viva_presentation.tex` (for slides)
   - `viva_report.tex` (for report)
3. Click "Recompile" (top right)
4. PDFs will auto-download

**Note**: These files use only standard LaTeX packages (no TikZ, no external dependencies). Will compile without issues.

If you want PowerPoint format, install Pandoc first:

```bash
# Install Pandoc
sudo apt-get install pandoc  # Ubuntu/Debian
# or brew install pandoc     # macOS
# or download from pandoc.org

# Run build script, answer 'y' when asked about PPTX conversion
./build.sh
```

Produces:
- `viva_presentation.pptx`
- `viva_report.pptx`

---

## Customization

### 1. Update Personal Info

In both `.tex` files, edit:
```latex
\author{Your Name \\ \small{\{your.email@domain.com\}}}
\institute{Your College/University}
```

### 2. Add Real Architecture Diagram

Currently `\includegraphics[width=0.9\textwidth]{architecture_diagram.png}` expects a diagram file.

**Create your own**:
- Use draw.io, Lucidchart, or Excalidraw
- Save as `architecture_diagram.png` in this folder
- Already referenced in `viva_report.tex` (Figure 1)

### 3. Customize Content

The content is based on your actual project:
- 93 features ✓
- 99.82% F1-score ✓
- 4 categories ✓
- Security hardening ✓

Feel free to tweak numbers if your results differ.

---

## What to Present

### For Viva (15-20 min):

1. **Start with PDF presentation** (`viva_presentation.pdf`)
   - 30 slides total
   - Covers: problem, architecture, ML algorithms, results, future work
   - Speaker notes included in comments (in `.tex` source)

2. **Show Interactive Demo** (2-3 min):
   ```bash
   cd ~/phishing_detection_project
   export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   python proof_of_working.py
   ```
   - Type a URL (e.g., `google.com`, `paypa1.com`)
   - Shows step-by-step mechanism

3. **Answer Questions**:
   - Refer to `viva_report.pdf` for detailed technical answers
   - Emphasize security fixes, 93 features, 99.82% accuracy

---

## Troubleshooting

### "File not found: IEEEtran.cls"
Install TeX Live full:
```bash
sudo apt-get install texlive-full  # Ubuntu (large, ~5GB)
```
Or minimal:
```bash
sudo apt-get install texlive-latex-base texlive-latex-recommended
```

### "Missing tikz libraries"
```bash
sudo apt-get install texlive-pictures
```

### Pandoc PPTX conversion poor quality
- PPTX conversion from LaTeX is approximate
- **Better**: Use PDF in viva; create PPT manually from the outline
- Or use the `.tex` as reference and build PPT slide-by-slide

### Overfull \hbox warnings
Normal in LaTeX. Review output PDF; if text clipped, adjust margins or font size in `.tex`.

---

## Why LaTeX?

LaTeX produces **publication-quality PDFs** with:
- Precise typography
- Professional math/typesetting
- IEEE-standard formatting
- Better than PowerPoint for academic reports

**For viva presentation**: PDF slides are perfectly acceptable (many IITs use beamer).

---

## Custom Slide Designs (Optional)

Want to change Beamer theme? Edit first line of `viva_presentation.tex`:

```latex
\usetheme{Madrid}       % Default
\usetheme{Berlin}      % With section/subsection headers
\usetheme{Singapore}   % Minimal
\usetheme{Antibes}     % Rounded
\usetheme{CambridgeUS} % Red/white theme
```

---

## Files Overview

### viva_presentation.tex
- Beamer class (IEEE-compatible)
- 30 slides ready
- Architecture diagram placeholder
- Code listings with syntax highlighting
- Tables for metrics

### viva_report.tex
- IEEEtran conference format
- 10+ pages
- Abstract, keywords, sections
- Bibliography with 10+ references
- Tables: features, hyperparameters, results

---

## Timeline

- **Now**: Review PDFs, customize name/college
- **1 day before**: Test build on viva computer (if bringing your own)
- **Viva day**: Have PDF ready on USB + laptop backup

---

## Support

Issues? Check:
1. TeX Live installation complete? (`pdflatex --version`)
2. All dependencies installed? (`texlive-pictures` for TikZ, `texlive-latex-recommended`)
3. Build again: `pdflatex viva_presentation.tex` (twice)

---

**Good luck with your viva!** 🎓
