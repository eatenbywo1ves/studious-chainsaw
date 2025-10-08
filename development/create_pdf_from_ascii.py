
# Simple approach - convert markdown to HTML then to PDF
print("Creating PDF from ASCII portraits...")

# Read the markdown file
with open('ascii_portraits_collection.md', 'r', encoding='utf-8') as f:
    content = f.read()

# Create a simple HTML with monospace font for ASCII art
html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ASCII Self-Portrait Collection: Claude Sonnet 4</title>
    <style>
        body {
            font-family: 'Courier New', Courier, monospace;
            font-size: 10px;
            line-height: 1.2;
            margin: 20px;
            white-space: pre-wrap;
        }
        h1, h2 {
            font-family: Arial, sans-serif;
            page-break-after: avoid;
        }
        h1 {
            font-size: 20px;
            margin-top: 0;
        }
        h2 {
            font-size: 16px;
            margin-top: 30px;
        }
        pre {
            margin: 10px 0;
            page-break-inside: avoid;
        }
        hr {
            margin: 20px 0;
            border: 0;
            border-top: 1px solid #ccc;
        }
        @media print {
            body {
                font-size: 8px;
            }
        }
    </style>
</head>
<body>
"""

# Convert markdown to HTML (basic conversion)
lines = content.split('\n')
in_code_block = False
for line in lines:
    if line.startswith('```'):
        if in_code_block:
            html_content += '</pre>\n'
            in_code_block = False
        else:
            html_content += '<pre>\n'
            in_code_block = True
    elif line.startswith('# '):
        html_content += f'<h1>{line[2:]}</h1>\n'
    elif line.startswith('## '):
        html_content += f'<h2>{line[3:]}</h2>\n'
    elif line.startswith('---'):
        html_content += '<hr>\n'
    elif in_code_block:
        html_content += line + '\n'
    else:
        html_content += line + '\n'

html_content += """
</body>
</html>
"""

# Save HTML file
with open('ascii_portraits_collection.html', 'w', encoding='utf-8') as f:
    f.write(html_content)

print("HTML file created: ascii_portraits_collection.html")
print("\nTo convert to PDF, you can:")
print("1. Open the HTML file in a web browser")
print("2. Press Ctrl+P to print")
print("3. Select 'Save as PDF' as the printer")
print("4. Adjust settings (recommend: A4, Portrait, Scale 80%)")
print("5. Save the PDF file")
