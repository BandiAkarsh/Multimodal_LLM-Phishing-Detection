#!/usr/bin/env python3
"""
Add page numbers to existing PDF
Title page: no number
TOC: no number  
Introduction: Page 1 (physical page 4)
"""
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from PyPDF2 import PdfReader, PdfWriter
import os

input_pdf = "viva/Phishing_Guard_Complete_Documentation.pdf"
output_pdf = "viva/Phishing_Guard_Complete_Documentation.pdf"

# Read existing PDF
reader = PdfReader(input_pdf)
writer = PdfWriter()

# Page numbers start from physical page 4 (which should show as page 1)
for i, page in enumerate(reader.pages):
    # Add page number to all pages except first 3 (title, TOC)
    if i >= 3:  # Physical page 4 onwards
        # Create overlay with page number
        packet = io.BytesIO()
        c = canvas.Canvas(packet, pagesize=A4)
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.gray)
        page_num = i - 3 + 1  # Start from 1
        c.drawRightString(200*mm, 10*mm, f"Page {page_num}")
        c.save()
        
        packet.seek(0)
        overlay = PdfReader(packet)
        page.merge_page(overlay.pages[0])
    
    writer.add_page(page)

with open(output_pdf, "wb") as f:
    writer.write(f)

print(f"✓ Added page numbers to {output_pdf}")
print(f"  Physical pages: {len(reader.pages)}")
print(f"  Page 1 starts at physical page 4")
