#!/usr/bin/env python3
"""
Direct Ghidra downloader using Python
Downloads the pre-built release from GitHub
"""

import os
import sys
import urllib.request
import zipfile
from pathlib import Path

def download_file(url, destination):
    """Download file with progress indicator"""
    def download_hook(block_num, block_size, total_size):
        downloaded = block_num * block_size
        percent = min(downloaded * 100 / total_size, 100)
        mb_downloaded = downloaded / 1024 / 1024
        mb_total = total_size / 1024 / 1024
        sys.stdout.write(f'\rDownloading: {percent:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)')
        sys.stdout.flush()
    
    print(f"Downloading from: {url}")
    urllib.request.urlretrieve(url, destination, download_hook)
    print(f"\nSaved to: {destination}")

def extract_zip(zip_path, extract_to):
    """Extract zip file with progress"""
    print(f"\nExtracting {zip_path}...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print(f"Extracted to: {extract_to}")

def main():
    # Configuration
    ghidra_url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20241105.zip"
    download_dir = Path("C:/Users/Corbin/development")
    zip_path = download_dir / "ghidra_11.2_PUBLIC.zip"
    
    print("=" * 50)
    print("Ghidra Direct Download Script")
    print("=" * 50)
    
    # Download
    try:
        download_file(ghidra_url, str(zip_path))
    except Exception as e:
        print(f"\nError downloading: {e}")
        print("\nAlternative: Download manually from:")
        print(ghidra_url)
        return 1
    
    # Extract
    try:
        extract_zip(zip_path, download_dir)
    except Exception as e:
        print(f"\nError extracting: {e}")
        return 1
    
    # Create launcher
    launcher_path = download_dir / "launch_ghidra.bat"
    launcher_content = """@echo off
echo Starting Ghidra...
cd /d "C:\\Users\\Corbin\\development\\ghidra_11.2_PUBLIC"
call ghidraRun.bat
pause
"""
    launcher_path.write_text(launcher_content)
    
    print("\n" + "=" * 50)
    print("SUCCESS! Ghidra is ready to use")
    print("=" * 50)
    print(f"\nInstalled to: {download_dir / 'ghidra_11.2_PUBLIC'}")
    print(f"Launch with: {launcher_path}")
    print("\nFirst time setup:")
    print("1. Run launch_ghidra.bat")
    print("2. Accept the license agreement")
    print("3. Create a new project")
    print("4. Import a binary to analyze")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())