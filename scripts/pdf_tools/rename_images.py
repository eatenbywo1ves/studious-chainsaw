import os
import shutil
from pathlib import Path

# Define the mapping based on pages
# Note: Page 11 doesn't have images in the extraction, using Page 12 instead
image_mapping = {
    # Page 5 (extracted_004.jpg)
    "extracted_004.jpg": "network-cluster.png",
    
    # Page 12 (extracted_005.jpg) - assuming this is what was meant by Page 11
    "extracted_005.jpg": "nmap-interface.png",
    
    # Page 60 (extracted_088.jpg and extracted_089.jpg)
    "extracted_088.jpg": "camera1.png",
    "extracted_089.jpg": "camera2.png",
    
    # Additional mappings for the remaining 13 images
    # Using descriptive names based on common security/network documentation patterns
    "extracted_000.jpg": "system-overview1.png",
    "extracted_001.jpg": "system-overview2.png",
    "extracted_002.jpg": "system-overview3.png",
    "extracted_003.jpg": "system-overview4.png",
    "extracted_006.jpg": "network-diagram1.png",
    "extracted_007.jpg": "network-diagram2.png",
    "extracted_008.jpg": "security-architecture.png",
    "extracted_009.jpg": "threat-model1.png",
    "extracted_010.jpg": "threat-model2.png",
    "extracted_011.jpg": "vulnerability-scan1.png",
    "extracted_012.jpg": "vulnerability-scan2.png",
    "extracted_013.jpg": "security-dashboard.png",
}

# Source and destination directories
source_dir = "extracted_images"
dest_dir = "renamed_images"

# Create destination directory
os.makedirs(dest_dir, exist_ok=True)

print("Starting image renaming process...")
print("=" * 50)

renamed_count = 0
skipped_count = 0

for old_name, new_name in image_mapping.items():
    source_path = os.path.join(source_dir, old_name)
    dest_path = os.path.join(dest_dir, new_name)
    
    if os.path.exists(source_path):
        shutil.copy2(source_path, dest_path)
        print(f"[OK] Renamed: {old_name} -> {new_name}")
        renamed_count += 1
    else:
        print(f"[SKIP] Skipped: {old_name} (file not found)")
        skipped_count += 1

print("=" * 50)
print(f"Renaming complete!")
print(f"Files renamed: {renamed_count}")
print(f"Files skipped: {skipped_count}")
print(f"Renamed images saved to: {dest_dir}/")

# Create an HTML template showing the image placeholders
html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Placeholder Template</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .placeholder { 
            border: 2px dashed #ccc; 
            padding: 20px; 
            margin: 10px 0; 
            background: #f9f9f9;
        }
        .placeholder code { 
            background: #e0e0e0; 
            padding: 2px 5px; 
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <h1>Image Placeholders to Replace</h1>
    
    <div class="placeholder">
        <p>Replace this with: <code>&lt;img src="renamed_images/network-cluster.png" alt="Network Cluster"&gt;</code></p>
        <div>[PLACEHOLDER: network-cluster]</div>
    </div>
    
    <div class="placeholder">
        <p>Replace this with: <code>&lt;img src="renamed_images/nmap-interface.png" alt="Nmap Interface"&gt;</code></p>
        <div>[PLACEHOLDER: nmap-interface]</div>
    </div>
    
    <div class="placeholder">
        <p>Replace this with: <code>&lt;img src="renamed_images/camera1.png" alt="Camera 1"&gt;</code></p>
        <div>[PLACEHOLDER: camera1]</div>
    </div>
    
    <div class="placeholder">
        <p>Replace this with: <code>&lt;img src="renamed_images/camera2.png" alt="Camera 2"&gt;</code></p>
        <div>[PLACEHOLDER: camera2]</div>
    </div>
    
    <!-- Add more placeholders as needed -->
    
</body>
</html>
"""

# Save the HTML template
with open("image_placeholder_template.html", "w", encoding="utf-8") as f:
    f.write(html_template)

print(f"\nHTML template created: image_placeholder_template.html")
print("\nYou can now use the renamed images in your HTML by replacing")
print("the placeholder divs with the appropriate <img> tags.")