import subprocess
import sys

def install_and_import(package_name):
    """Try to import a package, install if not found"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        print(f"Installing {package_name}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package_name, "--break-system-packages"])
            __import__(package_name)
            return True
        except:
            print(f"Failed to install {package_name}")
            return False

print("ASCII Portraits to PDF Converter")
print("=" * 40)

# Method 1: Try using pdfkit with wkhtmltopdf
if install_and_import("pdfkit"):
    try:
        import pdfkit

        # Read markdown file
        with open('ascii_portraits_collection.md', 'r', encoding='utf-8') as f:
            content = f.read()

        # Create HTML with better formatting
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
    @page {{ size: A4; margin: 1cm; }}
    body {{
        font-family: 'Courier New', monospace;
        font-size: 8pt;
        line-height: 1.1;
        white-space: pre-wrap;
    }}
    h1 {{ font-family: Arial; font-size: 18pt; }}
    h2 {{ font-family: Arial; font-size: 14pt; margin-top: 20pt; }}
    pre {{
        font-size: 7pt;
        line-height: 1.0;
        page-break-inside: avoid;
    }}
</style>
</head>
<body>
<h1>ASCII Self-Portrait Collection: Claude Sonnet 4</h1>
<pre>{content}</pre>
</body>
</html>"""

        # Save HTML
        with open('ascii_portraits.html', 'w', encoding='utf-8') as f:
            f.write(html)

        # Try to convert with pdfkit
        options = {
            'page-size': 'A4',
            'margin-top': '0.5in',
            'margin-right': '0.5in',
            'margin-bottom': '0.5in',
            'margin-left': '0.5in',
            'encoding': "UTF-8",
            'no-outline': None
        }

        pdfkit.from_file('ascii_portraits.html', 'ascii_portraits_collection.pdf', options=options)
        print("✓ PDF created successfully: ascii_portraits_collection.pdf")
    except Exception as e:
        print(f"pdfkit method failed: {e}")

# Method 2: Create a batch file for manual conversion
batch_content = """@echo off
echo Opening HTML file in default browser...
echo.
echo To create PDF:
echo 1. Press Ctrl+P in the browser
echo 2. Select "Save as PDF" or "Microsoft Print to PDF"
echo 3. Save as: ascii_portraits_collection.pdf
echo.
start ascii_portraits_collection.html
pause
"""

with open('convert_to_pdf.bat', 'w') as f:
    f.write(batch_content)

print("\n" + "="*40)
print("Files created:")
print("- ascii_portraits_collection.html")
print("- convert_to_pdf.bat")
print("\nTo create the PDF:")
print("1. Run convert_to_pdf.bat")
print("2. Or open ascii_portraits_collection.html in your browser")
print("3. Press Ctrl+P and save as PDF")
