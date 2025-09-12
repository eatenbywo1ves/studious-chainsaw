import os
import re

# Define placeholder to image mappings
placeholder_mappings = {
    # Main mappings from your requirements
    '[PLACEHOLDER: network-cluster]': '<img src="renamed_images/network-cluster.png" alt="Network Cluster">',
    '[PLACEHOLDER: nmap-interface]': '<img src="renamed_images/nmap-interface.png" alt="Nmap Interface">',
    '[PLACEHOLDER: camera1]': '<img src="renamed_images/camera1.png" alt="Camera 1">',
    '[PLACEHOLDER: camera2]': '<img src="renamed_images/camera2.png" alt="Camera 2">',
    
    # Additional mappings for other renamed images
    '[PLACEHOLDER: system-overview1]': '<img src="renamed_images/system-overview1.png" alt="System Overview 1">',
    '[PLACEHOLDER: system-overview2]': '<img src="renamed_images/system-overview2.png" alt="System Overview 2">',
    '[PLACEHOLDER: system-overview3]': '<img src="renamed_images/system-overview3.png" alt="System Overview 3">',
    '[PLACEHOLDER: system-overview4]': '<img src="renamed_images/system-overview4.png" alt="System Overview 4">',
    '[PLACEHOLDER: network-diagram1]': '<img src="renamed_images/network-diagram1.png" alt="Network Diagram 1">',
    '[PLACEHOLDER: network-diagram2]': '<img src="renamed_images/network-diagram2.png" alt="Network Diagram 2">',
    '[PLACEHOLDER: security-architecture]': '<img src="renamed_images/security-architecture.png" alt="Security Architecture">',
    '[PLACEHOLDER: threat-model1]': '<img src="renamed_images/threat-model1.png" alt="Threat Model 1">',
    '[PLACEHOLDER: threat-model2]': '<img src="renamed_images/threat-model2.png" alt="Threat Model 2">',
    '[PLACEHOLDER: vulnerability-scan1]': '<img src="renamed_images/vulnerability-scan1.png" alt="Vulnerability Scan 1">',
    '[PLACEHOLDER: vulnerability-scan2]': '<img src="renamed_images/vulnerability-scan2.png" alt="Vulnerability Scan 2">',
    '[PLACEHOLDER: security-dashboard]': '<img src="renamed_images/security-dashboard.png" alt="Security Dashboard">',
}

def replace_placeholders_in_file(input_file, output_file=None):
    """Replace placeholders in HTML file with image tags"""
    
    if output_file is None:
        output_file = input_file.replace('.html', '_with_images.html')
    
    try:
        # Read the HTML file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count replacements
        replacement_count = 0
        
        # Replace each placeholder
        for placeholder, img_tag in placeholder_mappings.items():
            if placeholder in content:
                content = content.replace(placeholder, img_tag)
                replacement_count += 1
                print(f"[REPLACED] {placeholder}")
        
        # Write the modified content
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"\n[SUCCESS] File processed: {input_file}")
        print(f"[SUCCESS] Output saved to: {output_file}")
        print(f"[INFO] Total replacements made: {replacement_count}")
        
        return True
        
    except FileNotFoundError:
        print(f"[ERROR] File not found: {input_file}")
        return False
    except Exception as e:
        print(f"[ERROR] An error occurred: {str(e)}")
        return False

def process_multiple_files(file_pattern="*.html"):
    """Process multiple HTML files in the current directory"""
    import glob
    
    html_files = glob.glob(file_pattern)
    
    if not html_files:
        print(f"[WARNING] No HTML files found matching pattern: {file_pattern}")
        return
    
    print(f"Found {len(html_files)} HTML file(s) to process:")
    print("=" * 50)
    
    for html_file in html_files:
        print(f"\nProcessing: {html_file}")
        print("-" * 30)
        replace_placeholders_in_file(html_file)

# Main execution
if __name__ == "__main__":
    import sys
    
    print("HTML Placeholder Replacement Tool")
    print("=" * 50)
    
    # Check for command line argument
    if len(sys.argv) > 1:
        specific_file = sys.argv[1]
        if not specific_file.endswith('.html'):
            specific_file += '.html'
        replace_placeholders_in_file(specific_file)
    else:
        # Process all HTML files in current directory
        process_multiple_files()
    
    print("\n" + "=" * 50)
    print("Processing complete!")
    print("\nNote: Make sure the 'renamed_images' folder is in the same")
    print("directory as your HTML file(s) for the images to display correctly.")