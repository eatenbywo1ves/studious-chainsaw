#!/usr/bin/env python3
"""
Simple HTML to PDF converter using alternative methods
"""

import os
import sys

def try_reportlab_conversion(html_file, pdf_file):
    """Try conversion using reportlab and html2text"""
    try:
        # First try to install required packages
        os.system("pip install reportlab html2text")
        
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.units import inch
        import html2text
        
        # Read HTML content
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Convert HTML to text
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.body_width = 80
        text_content = h.handle(html_content)
        
        # Create PDF
        doc = SimpleDocTemplate(pdf_file, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Split content into paragraphs
        paragraphs = text_content.split('\n\n')
        
        for para in paragraphs:
            if para.strip():
                if para.startswith('#'):
                    # Header
                    story.append(Paragraph(para.strip('#').strip(), styles['Heading1']))
                elif para.startswith('##'):
                    # Subheader
                    story.append(Paragraph(para.strip('#').strip(), styles['Heading2']))
                else:
                    # Normal text
                    story.append(Paragraph(para.strip(), styles['Normal']))
                story.append(Spacer(1, 12))
        
        doc.build(story)
        return True
        
    except Exception as e:
        print(f"ReportLab conversion failed: {e}")
        return False

def try_browser_print(html_file, pdf_file):
    """Try using browser printing capabilities"""
    try:
        import subprocess
        
        # Try using Edge browser (available on Windows)
        cmd = [
            "msedge",
            "--headless",
            "--disable-gpu",
            "--print-to-pdf=" + pdf_file,
            html_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and os.path.exists(pdf_file):
            return True
        else:
            print(f"Browser print failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"Browser printing failed: {e}")
        return False

def manual_text_pdf(html_file, pdf_file):
    """Create a simple text-based PDF from HTML"""
    try:
        os.system("pip install reportlab")
        
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        import re
        
        # Read and clean HTML
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove HTML tags and extract text
        clean_text = re.sub('<[^<]+?>', '', content)
        clean_text = clean_text.replace('&nbsp;', ' ')
        clean_text = clean_text.replace('&lt;', '<')
        clean_text = clean_text.replace('&gt;', '>')
        clean_text = clean_text.replace('&amp;', '&')
        
        # Create PDF
        c = canvas.Canvas(pdf_file, pagesize=letter)
        width, height = letter
        
        # Set up text
        y_position = height - 50
        line_height = 12
        margin = 50
        
        lines = clean_text.split('\n')
        
        for line in lines:
            if y_position < 50:  # New page
                c.showPage()
                y_position = height - 50
            
            # Wrap long lines
            if len(line) > 100:
                words = line.split(' ')
                current_line = ""
                for word in words:
                    if len(current_line + word) < 100:
                        current_line += word + " "
                    else:
                        c.drawString(margin, y_position, current_line.strip())
                        y_position -= line_height
                        current_line = word + " "
                        
                        if y_position < 50:
                            c.showPage()
                            y_position = height - 50
                
                if current_line.strip():
                    c.drawString(margin, y_position, current_line.strip())
                    y_position -= line_height
            else:
                c.drawString(margin, y_position, line)
                y_position -= line_height
        
        c.save()
        return True
        
    except Exception as e:
        print(f"Manual text PDF failed: {e}")
        return False

def main():
    html_file = r"C:\Users\Corbin\healthcare_law_discussion.html"
    pdf_file = r"C:\Users\Corbin\healthcare_law_discussion.pdf"
    
    print("Attempting HTML to PDF conversion using multiple methods...")
    
    # Method 1: Browser printing
    print("\nTrying browser printing...")
    if try_browser_print(html_file, pdf_file):
        print("✓ Success with browser printing!")
        return
    
    # Method 2: ReportLab with html2text
    print("\nTrying ReportLab conversion...")
    if try_reportlab_conversion(html_file, pdf_file):
        print("✓ Success with ReportLab!")
        return
    
    # Method 3: Manual text PDF
    print("\nTrying manual text conversion...")
    if manual_text_pdf(html_file, pdf_file):
        print("✓ Success with manual text conversion!")
        return
    
    print("\n✗ All conversion methods failed.")
    print("You can try opening the HTML file in a browser and printing to PDF manually.")

if __name__ == "__main__":
    main()