#!/usr/bin/env python3
"""
Convert HTML document to PDF using WeasyPrint
"""

import weasyprint
import os

def convert_html_to_pdf(html_file, pdf_file):
    """Convert HTML file to PDF"""
    try:
        # Check if HTML file exists
        if not os.path.exists(html_file):
            print(f"Error: HTML file '{html_file}' not found")
            return False
        
        # Convert HTML to PDF
        print(f"Converting {html_file} to {pdf_file}...")
        html_document = weasyprint.HTML(filename=html_file)
        html_document.write_pdf(pdf_file)
        
        print(f"Successfully created PDF: {pdf_file}")
        
        # Check file size
        file_size = os.path.getsize(pdf_file)
        print(f"PDF file size: {file_size:,} bytes")
        
        return True
        
    except Exception as e:
        print(f"Error converting to PDF: {e}")
        return False

if __name__ == "__main__":
    html_file = r"C:\Users\Corbin\healthcare_law_discussion.html"
    pdf_file = r"C:\Users\Corbin\healthcare_law_discussion.pdf"
    
    success = convert_html_to_pdf(html_file, pdf_file)
    
    if success:
        print("\n✓ Conversion completed successfully!")
        print(f"PDF saved as: {pdf_file}")
    else:
        print("\n✗ Conversion failed!")