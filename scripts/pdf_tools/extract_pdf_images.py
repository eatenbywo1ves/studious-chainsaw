import fitz  # PyMuPDF
import os
from pathlib import Path

pdf_path = "Downloads/oznakomitelnoe_rukovodstvo__dxdyJA3.pdf"
output_dir = "extracted_images"

# Create output directory
os.makedirs(output_dir, exist_ok=True)

# Open PDF
pdf_document = fitz.open(pdf_path)

print(f"Processing PDF: {pdf_path}")
print(f"Total pages: {len(pdf_document)}")

image_count = 0
image_info = []

# Iterate through pages
for page_num in range(len(pdf_document)):
    page = pdf_document[page_num]
    image_list = page.get_images()
    
    if image_list:
        print(f"\nPage {page_num + 1}: Found {len(image_list)} image(s)")
        
        for img_index, img in enumerate(image_list):
            # Extract image
            xref = img[0]
            pix = fitz.Pixmap(pdf_document, xref)
            
            # Convert CMYK to RGB if necessary
            if pix.n - pix.alpha > 3:
                pix = fitz.Pixmap(fitz.csRGB, pix)
            
            # Save image
            if pix.alpha:
                # Remove alpha channel for JPEG
                pix = fitz.Pixmap(pix, 0)  # Remove alpha
                image_filename = f"extracted_{image_count:03d}.jpg"
            else:
                image_filename = f"extracted_{image_count:03d}.jpg"
            
            image_path = os.path.join(output_dir, image_filename)
            pix.save(image_path)
            
            image_info.append({
                'filename': image_filename,
                'page': page_num + 1,
                'index_on_page': img_index
            })
            
            print(f"  Saved: {image_filename} (from page {page_num + 1})")
            image_count += 1
            
            pix = None

pdf_document.close()

print(f"\n{'='*50}")
print(f"Total images extracted: {image_count}")
print(f"Images saved to: {output_dir}/")
print(f"\nImage mapping for renaming:")
print(f"{'='*50}")

for info in image_info:
    print(f"Page {info['page']:3d} -> {info['filename']}")