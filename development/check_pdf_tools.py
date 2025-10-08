import subprocess
import sys

# First, let's check what's available
print("Checking for PDF creation tools...")

# Try to import reportlab first
try:
    import reportlab
    print("reportlab is available")
except ImportError:
    print("reportlab not found, installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab", "--break-system-packages"])

# Try markdown2
try:
    import markdown2
    print("markdown2 is available")
except ImportError:
    print("markdown2 not found, installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "markdown2", "--break-system-packages"])

# Try weasyprint as an alternative
try:
    import weasyprint
    print("weasyprint is available")
except ImportError:
    print("weasyprint not found, trying to install...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "weasyprint", "--break-system-packages"])
        print("weasyprint installed successfully")
    except:
        print("weasyprint installation failed - using alternative method")

print("\nTools check complete!")
