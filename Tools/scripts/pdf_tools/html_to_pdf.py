import os
import sys
from pathlib import Path
from weasyprint import HTML, CSS

def convert_html_to_pdf(html_file, output_pdf=None):
    """Convert HTML file to PDF with embedded images"""
    
    if not os.path.exists(html_file):
        print(f"[ERROR] HTML file not found: {html_file}")
        return False
    
    # Generate output filename if not provided
    if output_pdf is None:
        output_pdf = html_file.replace('.html', '.pdf')
    
    try:
        print(f"Converting: {html_file} -> {output_pdf}")
        
        # Get the base directory for resolving relative paths
        base_url = Path(html_file).parent.absolute().as_uri() + '/'
        
        # Custom CSS for better PDF rendering
        css = CSS(string="""
            @page {
                size: A4;
                margin: 1cm;
            }
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
            }
            img {
                max-width: 100%;
                height: auto;
                display: block;
                margin: 10px auto;
                page-break-inside: avoid;
            }
            h1, h2, h3 {
                page-break-after: avoid;
            }
            .placeholder {
                page-break-inside: avoid;
            }
        """)
        
        # Convert HTML to PDF
        HTML(filename=html_file, base_url=base_url).write_pdf(
            output_pdf,
            stylesheets=[css]
        )
        
        print(f"[SUCCESS] PDF created: {output_pdf}")
        
        # Get file size
        size = os.path.getsize(output_pdf)
        size_mb = size / (1024 * 1024)
        print(f"[INFO] File size: {size_mb:.2f} MB")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Conversion failed: {str(e)}")
        return False

def batch_convert(pattern="*.html"):
    """Convert multiple HTML files to PDF"""
    import glob
    
    html_files = glob.glob(pattern)
    
    if not html_files:
        print(f"[WARNING] No HTML files found matching pattern: {pattern}")
        return
    
    print(f"Found {len(html_files)} HTML file(s) to convert")
    print("=" * 50)
    
    success_count = 0
    for html_file in html_files:
        print(f"\nProcessing: {html_file}")
        if convert_html_to_pdf(html_file):
            success_count += 1
    
    print("\n" + "=" * 50)
    print(f"Conversion complete: {success_count}/{len(html_files)} successful")

if __name__ == "__main__":
    print("HTML to PDF Converter")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        # Convert specific file
        html_file = sys.argv[1]
        if not html_file.endswith('.html'):
            html_file += '.html'
        
        # Check for optional output PDF name
        output_pdf = sys.argv[2] if len(sys.argv) > 2 else None
        
        convert_html_to_pdf(html_file, output_pdf)
    else:
        # Convert the generated HTML with images
        if os.path.exists("image_placeholder_template_with_images.html"):
            print("Converting the generated HTML file with images...")
            convert_html_to_pdf("image_placeholder_template_with_images.html")
        else:
            print("No specific file provided. Converting all HTML files...")
            batch_convert()
    
    print("\nNote: Make sure the 'renamed_images' folder is accessible")
    print("from the HTML file location for images to appear in the PDF.")