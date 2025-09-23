import os
import sys
import subprocess
from pathlib import Path

def create_print_ready_html(input_file, output_file=None):
    """Create a print-optimized version of the HTML"""
    
    if output_file is None:
        output_file = input_file.replace('.html', '_print_ready.html')
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Add print-friendly CSS
    print_css = """
    <style>
        @media print {
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 0;
            }
            img {
                max-width: 100%;
                height: auto;
                page-break-inside: avoid;
                display: block;
                margin: 10px 0;
            }
            h1, h2, h3 {
                page-break-after: avoid;
            }
            .placeholder {
                page-break-inside: avoid;
            }
            /* Hide any unnecessary elements */
            .no-print {
                display: none;
            }
        }
        /* Screen styles */
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        img {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 20px 0;
            border: 1px solid #ddd;
            padding: 5px;
        }
    </style>
    """
    
    # Insert CSS before closing </head> or at the beginning
    if '</head>' in content:
        content = content.replace('</head>', print_css + '</head>')
    else:
        content = print_css + content
    
    # Save the print-ready version
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"[SUCCESS] Print-ready HTML created: {output_file}")
    return output_file

def open_in_browser(html_file):
    """Open HTML file in default browser for manual PDF conversion"""
    
    abs_path = os.path.abspath(html_file)
    file_url = Path(abs_path).as_uri()
    
    print(f"Opening in browser: {file_url}")
    print("\nTo convert to PDF:")
    print("1. Press Ctrl+P (or Cmd+P on Mac)")
    print("2. Select 'Save as PDF' as the printer")
    print("3. Click 'Save' and choose your location")
    
    # Open in default browser
    if sys.platform.startswith('win'):
        os.startfile(abs_path)
    elif sys.platform.startswith('darwin'):
        subprocess.run(['open', abs_path])
    else:
        subprocess.run(['xdg-open', abs_path])

def main():
    print("HTML to PDF Converter (Browser Method)")
    print("=" * 50)
    
    # Find the HTML file with images
    target_file = "image_placeholder_template_with_images.html"
    
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        if not target_file.endswith('.html'):
            target_file += '.html'
    
    if not os.path.exists(target_file):
        print(f"[ERROR] File not found: {target_file}")
        print("\nAvailable HTML files:")
        for file in Path('.').glob('*.html'):
            print(f"  - {file}")
        return
    
    # Create print-ready version
    print_ready = create_print_ready_html(target_file)
    
    # Open in browser
    open_in_browser(print_ready)
    
    print("\n" + "=" * 50)
    print("HTML file opened in browser for PDF conversion")

if __name__ == "__main__":
    main()