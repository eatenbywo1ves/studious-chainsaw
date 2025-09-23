#!/usr/bin/env python3
"""
Final HTML to PDF converter using ReportLab
"""

import os
import sys
import re

def create_pdf_from_html():
    """Convert HTML to PDF using ReportLab"""
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        
        html_file = r"C:\Users\Corbin\healthcare_law_discussion.html"
        pdf_file = r"C:\Users\Corbin\healthcare_law_discussion.pdf"
        
        print("Converting HTML to PDF using ReportLab...")
        
        # Read HTML content
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Extract content from HTML
        content_sections = []
        
        # Extract title
        title_match = re.search(r'<h1>(.*?)</h1>', html_content, re.DOTALL)
        if title_match:
            content_sections.append(('title', title_match.group(1).strip()))
        
        # Extract all messages
        message_pattern = r'<div class="message (user-message|assistant-message)".*?<div class="message-label">(.*?)</div>(.*?)</div>\s*</div>'
        messages = re.findall(message_pattern, html_content, re.DOTALL)
        
        for msg_type, label, content in messages:
            # Clean up the content
            clean_content = re.sub(r'<[^>]+>', '', content)
            clean_content = clean_content.replace('&nbsp;', ' ')
            clean_content = clean_content.replace('&lt;', '<')
            clean_content = clean_content.replace('&gt;', '>')
            clean_content = clean_content.replace('&amp;', '&')
            clean_content = re.sub(r'\s+', ' ', clean_content).strip()
            
            content_sections.append((msg_type, label.strip(), clean_content))
        
        # Create PDF
        doc = SimpleDocTemplate(pdf_file, pagesize=A4, 
                              topMargin=1*inch, bottomMargin=1*inch,
                              leftMargin=1*inch, rightMargin=1*inch)
        
        styles = getSampleStyleSheet()
        story = []
        
        # Title page
        story.append(Paragraph("Healthcare Law Discussion", styles['Title']))
        story.append(Paragraph("Ethical Issues in Managed Healthcare Systems", styles['Heading2']))
        story.append(Paragraph("Generated: September 10, 2025", styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        story.append(PageBreak())
        
        # Add content
        for i, section in enumerate(content_sections):
            if section[0] == 'title':
                continue  # Skip, already added
            
            msg_type, label, content = section
            
            # Add question/response label
            story.append(Paragraph(f"<b>{label}</b>", styles['Heading3']))
            story.append(Spacer(1, 12))
            
            # Split content into smaller chunks for better formatting
            paragraphs = content.split('\n')
            
            for para in paragraphs:
                if para.strip():
                    # Handle different content types
                    if para.strip().startswith('•'):
                        # Bullet point
                        story.append(Paragraph(para.strip(), styles['Normal']))
                    elif len(para) > 500:
                        # Long paragraph, split it
                        words = para.split(' ')
                        current_chunk = []
                        for word in words:
                            current_chunk.append(word)
                            if len(' '.join(current_chunk)) > 400:
                                story.append(Paragraph(' '.join(current_chunk), styles['Normal']))
                                story.append(Spacer(1, 6))
                                current_chunk = []
                        
                        if current_chunk:
                            story.append(Paragraph(' '.join(current_chunk), styles['Normal']))
                    else:
                        story.append(Paragraph(para.strip(), styles['Normal']))
                    
                    story.append(Spacer(1, 6))
            
            story.append(Spacer(1, 18))
            
            # Add page break between major sections
            if i < len(content_sections) - 1:
                story.append(PageBreak())
        
        # Build PDF
        doc.build(story)
        
        print(f"SUCCESS: PDF created at {pdf_file}")
        
        # Check file size
        size = os.path.getsize(pdf_file)
        size_kb = size / 1024
        print(f"File size: {size_kb:.1f} KB")
        
        return True
        
    except Exception as e:
        print(f"ERROR: PDF conversion failed: {e}")
        return False

if __name__ == "__main__":
    create_pdf_from_html()