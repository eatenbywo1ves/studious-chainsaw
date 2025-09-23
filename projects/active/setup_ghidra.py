#!/usr/bin/env python3
"""
Ghidra Installation Script for Windows
Downloads and sets up Ghidra reverse engineering framework
"""

import os
import sys
import urllib.request
import zipfile
import subprocess
from pathlib import Path

def check_java():
    """Check if Java is installed and meets requirements"""
    try:
        result = subprocess.run(['java', '-version'], 
                              capture_output=True, 
                              text=True, 
                              shell=True)
        if result.returncode == 0:
            print("✓ Java is installed")
            return True
        else:
            print("✗ Java not found. Installing OpenJDK 17...")
            return False
    except Exception as e:
        print(f"✗ Error checking Java: {e}")
        return False

def download_ghidra():
    """Download latest Ghidra release"""
    url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20241105.zip"
    output_path = Path("C:/Users/Corbin/development/ghidra_latest.zip")
    
    print(f"Downloading Ghidra from {url}")
    print("This may take a few minutes (file size ~350MB)...")
    
    try:
        # Download with progress indicator
        def download_progress(block_num, block_size, total_size):
            downloaded = block_num * block_size
            percent = min(downloaded * 100 / total_size, 100)
            sys.stdout.write(f'\rProgress: {percent:.1f}%')
            sys.stdout.flush()
        
        urllib.request.urlretrieve(url, output_path, download_progress)
        print("\n✓ Download complete")
        return output_path
    except Exception as e:
        print(f"\n✗ Download failed: {e}")
        return None

def extract_ghidra(zip_path):
    """Extract Ghidra zip file"""
    extract_path = Path("C:/Users/Corbin/development/ghidra_11.2")
    
    print(f"Extracting to {extract_path}...")
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(Path("C:/Users/Corbin/development/"))
        print("✓ Extraction complete")
        return extract_path
    except Exception as e:
        print(f"✗ Extraction failed: {e}")
        return None

def create_launcher():
    """Create a batch file to launch Ghidra"""
    launcher_content = """@echo off
echo Starting Ghidra...
cd /d "C:\\Users\\Corbin\\development\\ghidra_11.2_PUBLIC"
call ghidraRun.bat
pause
"""
    
    launcher_path = Path("C:/Users/Corbin/development/launch_ghidra.bat")
    launcher_path.write_text(launcher_content)
    print(f"✓ Created launcher: {launcher_path}")
    
    # Also create a PowerShell launcher
    ps_launcher_content = """
Write-Host "Starting Ghidra..." -ForegroundColor Green
Set-Location "C:\\Users\\Corbin\\development\\ghidra_11.2_PUBLIC"
& .\\ghidraRun.bat
"""
    
    ps_launcher_path = Path("C:/Users/Corbin/development/launch_ghidra.ps1")
    ps_launcher_path.write_text(ps_launcher_content)
    print(f"✓ Created PowerShell launcher: {ps_launcher_path}")
    
    return launcher_path

def install_java_if_needed():
    """Install OpenJDK if Java is not present"""
    print("Installing OpenJDK 17 using winget...")
    try:
        result = subprocess.run(['winget', 'install', 'Microsoft.OpenJDK.17'], 
                              capture_output=True, 
                              text=True, 
                              shell=True)
        if result.returncode == 0:
            print("✓ OpenJDK 17 installed successfully")
            print("Please restart your terminal for Java to be available in PATH")
            return True
        else:
            print(f"✗ Failed to install Java: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error installing Java: {e}")
        return False

def main():
    """Main installation process"""
    print("=== Ghidra Installation Script ===\n")
    
    # Step 1: Check Java
    if not check_java():
        if not install_java_if_needed():
            print("\nPlease install Java 17+ manually from:")
            print("https://adoptium.net/temurin/releases/")
            return
    
    # Step 2: Download Ghidra
    zip_path = download_ghidra()
    if not zip_path:
        print("\nPlease download Ghidra manually from:")
        print("https://github.com/NationalSecurityAgency/ghidra/releases")
        return
    
    # Step 3: Extract Ghidra
    ghidra_path = extract_ghidra(zip_path)
    if not ghidra_path:
        return
    
    # Step 4: Create launcher
    launcher = create_launcher()
    
    print("\n=== Installation Complete ===")
    print(f"Ghidra is installed at: C:\\Users\\Corbin\\development\\ghidra_11.2_PUBLIC")
    print(f"Launch Ghidra using: {launcher}")
    print("\nYou can also run Ghidra directly:")
    print("  cd C:\\Users\\Corbin\\development\\ghidra_11.2_PUBLIC")
    print("  ghidraRun.bat")

if __name__ == "__main__":
    main()