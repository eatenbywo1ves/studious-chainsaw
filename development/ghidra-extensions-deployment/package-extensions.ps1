# PowerShell script to package Ghidra extensions
param(
    [string]$BuildVersion = "1.0.0",
    [string]$GhidraVersion = "11.4.2",
    [switch]$Install
)

Write-Host "Catalytic Computing - Ghidra Extensions Build System" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

if (-not $env:GHIDRA_INSTALL_DIR) {
    Write-Host "ERROR: GHIDRA_INSTALL_DIR environment variable not set!" -ForegroundColor Red
    Write-Host "Please set it to your Ghidra installation directory." -ForegroundColor Yellow
    Write-Host "Example: `$env:GHIDRA_INSTALL_DIR = 'C:\ghidra_11.4.2_PUBLIC'" -ForegroundColor Yellow
    exit 1
}

Write-Host "Using Ghidra installation: $env:GHIDRA_INSTALL_DIR" -ForegroundColor Green
Write-Host "Build Version: $BuildVersion" -ForegroundColor Green
Write-Host "Target Ghidra Version: $GhidraVersion" -ForegroundColor Green
Write-Host ""

# Create output directories
$OutputDir = "build\catalytic-ghidra-extensions"
$DistDir = "$OutputDir\dist"
$DocsDir = "$OutputDir\docs"

if (Test-Path "build") {
    Remove-Item "build" -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
New-Item -ItemType Directory -Force -Path $DocsDir | Out-Null

Write-Host "Building all Ghidra extensions..." -ForegroundColor Yellow
Write-Host ""

# Build GhidraCtrlP
Write-Host "[1/4] Building GhidraCtrlP..." -ForegroundColor Cyan
Set-Location "..\GhidraCtrlP"

Write-Host "Using manual packaging for GhidraCtrlP..." -ForegroundColor Yellow
$CtrlTemp = "..\ghidra-extensions-deployment\build\temp\GhidraCtrlP"
New-Item -ItemType Directory -Force -Path $CtrlTemp | Out-Null

# Copy extension files
Copy-Item -Path "ghidra_scripts" -Destination "$CtrlTemp\ghidra_scripts" -Recurse -Force
if (Test-Path "docs") { Copy-Item -Path "docs" -Destination "$CtrlTemp\docs" -Recurse -Force }
if (Test-Path "data") { Copy-Item -Path "data" -Destination "$CtrlTemp\data" -Recurse -Force }
if (Test-Path "README.md") { Copy-Item -Path "README.md" -Destination "$CtrlTemp\" -Force }
if (Test-Path "extension.properties") { Copy-Item -Path "extension.properties" -Destination "$CtrlTemp\" -Force }
if (Test-Path "Module.manifest") { Copy-Item -Path "Module.manifest" -Destination "$CtrlTemp\" -Force }

# Create ZIP package
$CtrlZipDir = "..\ghidra-extensions-deployment\$DistDir\GhidraCtrlP"
New-Item -ItemType Directory -Force -Path $CtrlZipDir | Out-Null
$CtrlZip = "$CtrlZipDir\ghidra_${GhidraVersion}_PUBLIC_$(Get-Date -Format 'yyyyMMdd')_GhidraCtrlP.zip"
Compress-Archive -Path "$CtrlTemp\*" -DestinationPath $CtrlZip -Force

# Build GhidraLookup
Write-Host "[2/4] Building GhidraLookup..." -ForegroundColor Cyan
Set-Location "..\GhidraLookup"
if (Test-Path "dist") {
    $LookupDistDir = "..\ghidra-extensions-deployment\$DistDir\GhidraLookup"
    New-Item -ItemType Directory -Force -Path $LookupDistDir | Out-Null
    Copy-Item -Path "dist\*.zip" -Destination $LookupDistDir -Force
    if (Test-Path "README.md") { 
        Copy-Item -Path "README.md" -Destination "..\ghidra-extensions-deployment\$DocsDir\GhidraLookup-README.md" -Force 
    }
    Write-Host "GhidraLookup: Using existing build" -ForegroundColor Green
} else {
    Write-Host "GhidraLookup: No distribution found - skipping" -ForegroundColor Yellow
}

# Build GhidrAssist
Write-Host "[3/4] Building GhidrAssist..." -ForegroundColor Cyan
Set-Location "..\GhidrAssist"
if (Test-Path "dist") {
    $AssistDistDir = "..\ghidra-extensions-deployment\$DistDir\GhidrAssist"
    New-Item -ItemType Directory -Force -Path $AssistDistDir | Out-Null
    Copy-Item -Path "dist\*.zip" -Destination $AssistDistDir -Force
    if (Test-Path "README.md") { 
        Copy-Item -Path "README.md" -Destination "..\ghidra-extensions-deployment\$DocsDir\GhidrAssist-README.md" -Force 
    }
    Write-Host "GhidrAssist: Using existing build" -ForegroundColor Green
} else {
    Write-Host "GhidrAssist: No distribution found - skipping" -ForegroundColor Yellow
}

# Build Ghidrathon
Write-Host "[4/4] Building Ghidrathon..." -ForegroundColor Cyan
Set-Location "..\Ghidrathon"
if (Test-Path "dist") {
    $ThonDistDir = "..\ghidra-extensions-deployment\$DistDir\Ghidrathon"
    New-Item -ItemType Directory -Force -Path $ThonDistDir | Out-Null
    Copy-Item -Path "dist\*.zip" -Destination $ThonDistDir -Force
    if (Test-Path "README.md") { 
        Copy-Item -Path "README.md" -Destination "..\ghidra-extensions-deployment\$DocsDir\Ghidrathon-README.md" -Force 
    }
    Write-Host "Ghidrathon: Using existing build" -ForegroundColor Green
} else {
    Write-Host "Ghidrathon: No distribution found - skipping" -ForegroundColor Yellow
}

Set-Location "..\ghidra-extensions-deployment"

Write-Host ""
Write-Host "Generating documentation..." -ForegroundColor Yellow

# Generate master documentation
$MasterDoc = @"
# Catalytic Computing - Ghidra Extensions Suite

A comprehensive collection of professional Ghidra extensions designed to enhance reverse engineering workflows.

## Version Information
- **Suite Version**: $BuildVersion
- **Target Ghidra Version**: $GhidraVersion
- **Build Date**: $(Get-Date)

## Extensions Overview

### GhidraCtrlP
Fast navigation and command palette for Ghidra - VS Code style Ctrl+P functionality

### GhidraLookup
Win32 API documentation lookup functionality with automatic constant analysis

### GhidrAssist
AI-assisted reverse engineering with LLM integration and automation features

### Ghidrathon
Python 3 integration for Ghidra scripting with modern library support

## Features Highlights

- **GhidraCtrlP**: Fuzzy search through functions, data, labels, bookmarks, windows, scripts, and actions
- **GhidraLookup**: Context-sensitive Win32 API documentation with parameter constants
- **GhidrAssist**: LLM-powered code explanation, analysis automation, and MCP tool integration
- **Ghidrathon**: Full Python 3.8+ environment with modern libraries like NumPy, scikit-learn, etc.

## Installation

See INSTALLATION_GUIDE.md for detailed setup instructions.

## Architecture

This suite follows Ghidra extension best practices:
- Modular design with clean interfaces
- Comprehensive documentation and examples
- Support for both GUI and headless modes
- Seamless integration with existing workflows

## Support

For issues, feature requests, or contributions, refer to individual extension documentation and the Catalytic Computing development repository.

---
*Generated by Catalytic Computing Build System v$BuildVersion*
"@

$MasterDoc | Out-File -FilePath "$DocsDir\README.md" -Encoding UTF8

# Generate installation guide
$InstallGuide = @"
# Installation Guide - Catalytic Computing Ghidra Extensions

## Prerequisites
- **Ghidra**: $GhidraVersion or later
- **Java**: 17 or later (required by Ghidra)
- **Python**: 3.8+ (required for Ghidrathon)
- **Operating System**: Windows, Linux, or macOS

## Environment Setup

### Windows
``````powershell
`$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"
``````

### Linux/macOS
``````bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
``````

## Quick Install

1. Run the installation script:
   - Windows: ``.\package-extensions.ps1 -Install``
   - Linux/macOS: ``./build-all.sh install``

2. Start Ghidra and enable extensions via **File > Install Extensions**

## Manual Installation

1. Copy ZIP files from ``dist\`` directory to: ``GHIDRA_INSTALL_DIR\Extensions\Ghidra\``
2. Restart Ghidra
3. Go to **File > Install Extensions** and select the ZIP files

## Extension Configuration

### GhidraCtrlP
- **Setup**: No additional configuration required
- **Usage**: Add keyboard shortcut (Ctrl+P recommended)
- **Access**: Window → Script Manager → CtrlPQuicklaunchScript
- **Features**: Search functions, data, labels, bookmarks, windows, scripts, actions

### GhidraLookup
- **Setup**: Enable in File → Configure → Miscellaneous
- **Usage**: Right-click on Win32 API functions for documentation
- **Features**: Automatic constant analysis, MSDN integration, parameter documentation

### GhidrAssist
- **Setup**: Configure API keys in Tools → GhidrAssist Settings
- **Requirements**: OpenAI API, local LLM (Ollama/LMStudio), or compatible service
- **Features**: Code explanation, automated analysis, RAG, MCP tool integration

### Ghidrathon
- **Setup**: Run configuration after installation:
  ``````bash
  python ghidrathon_configure.py /path/to/ghidra
  ``````
- **Requirements**: Python 3.8+, Jep library (``pip install jep==4.2.0``)
- **Features**: Full Python 3 scripting, modern library support, interactive console

## Verification

After installation:
1. Launch Ghidra
2. Go to **Help → About Ghidra**
3. Verify all extensions appear in the list
4. Test basic functionality

## Troubleshooting

### Common Issues

1. **Extensions not appearing**
   - Ensure ZIP files are in ``Extensions/Ghidra/`` directory
   - Check Ghidra version compatibility
   - Restart Ghidra after installation

2. **Java version errors**
   - Verify Java 17+ is installed and JAVA_HOME is set

3. **Python errors (Ghidrathon)**
   - Ensure Python 3.8+ is installed
   - Install Jep: ``pip install jep==4.2.0``
   - Run configuration script

4. **API errors (GhidrAssist)**
   - Configure valid API keys in settings
   - Check network connectivity
   - Verify LLM service is running (for local models)

### Getting Help

- Review individual extension README files
- Check Ghidra application logs
- Verify all prerequisites are met
- Contact Catalytic Computing support

---
*Installation Guide v$BuildVersion*
"@

$InstallGuide | Out-File -FilePath "$DocsDir\INSTALLATION_GUIDE.md" -Encoding UTF8

Write-Host ""
Write-Host "Creating master distribution package..." -ForegroundColor Yellow
$MasterZip = "build\CatalyticComputing-GhidraExtensions-$BuildVersion.zip"
Compress-Archive -Path "$OutputDir\*" -DestinationPath $MasterZip -Force

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "Output directory: $OutputDir" -ForegroundColor Green
Write-Host "Master package: $MasterZip" -ForegroundColor Green

$ExtensionCount = (Get-ChildItem -Path $DistDir -Filter "*.zip" -Recurse).Count
Write-Host "Extensions packaged: $ExtensionCount" -ForegroundColor Green

$MasterSize = [math]::Round((Get-Item $MasterZip).Length / 1MB, 2)
Write-Host "Package size: $MasterSize MB" -ForegroundColor Green

Write-Host ""
Write-Host "To install extensions:" -ForegroundColor Yellow
Write-Host "1. Ensure GHIDRA_INSTALL_DIR environment variable is set" -ForegroundColor Yellow
Write-Host "2. Run: .\package-extensions.ps1 -Install" -ForegroundColor Yellow
Write-Host "3. Or manually copy ZIP files to Ghidra\Extensions\Ghidra\" -ForegroundColor Yellow
Write-Host ""

# Handle install command
if ($Install) {
    Write-Host "Installing extensions to Ghidra..." -ForegroundColor Cyan
    $GhidraExtDir = Join-Path $env:GHIDRA_INSTALL_DIR "Extensions\Ghidra"
    
    if (-not (Test-Path $GhidraExtDir)) {
        Write-Host "ERROR: Ghidra extensions directory not found: $GhidraExtDir" -ForegroundColor Red
        Write-Host "Please verify GHIDRA_INSTALL_DIR is correct." -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Copying extensions to: $GhidraExtDir" -ForegroundColor Green
    $ZipFiles = Get-ChildItem -Path $DistDir -Filter "*.zip" -Recurse
    foreach ($ZipFile in $ZipFiles) {
        Copy-Item -Path $ZipFile.FullName -Destination $GhidraExtDir -Force
        Write-Host "Installed: $($ZipFile.Name)" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Extensions installed successfully!" -ForegroundColor Green
    Write-Host "Please restart Ghidra and use File > Install Extensions to enable them." -ForegroundColor Yellow
}