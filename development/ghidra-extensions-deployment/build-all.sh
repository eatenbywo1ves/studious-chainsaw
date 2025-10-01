#!/bin/bash
# Catalytic Computing - Ghidra Extensions Build Script (Linux/macOS)

echo "Catalytic Computing - Ghidra Extensions Build System"
echo "====================================================="

BUILD_VERSION=${BUILD_VERSION:-"1.0.0"}
GHIDRA_VERSION=${GHIDRA_VERSION:-"11.4.2"}

if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "ERROR: GHIDRA_INSTALL_DIR environment variable not set!"
    echo "Please set it to your Ghidra installation directory."
    echo "Example: export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    exit 1
fi

echo "Using Ghidra installation: $GHIDRA_INSTALL_DIR"
echo "Build Version: $BUILD_VERSION"
echo "Target Ghidra Version: $GHIDRA_VERSION"
echo

# Create output directories
OUTPUT_DIR="build/catalytic-ghidra-extensions"
DIST_DIR="$OUTPUT_DIR/dist"
DOCS_DIR="$OUTPUT_DIR/docs"

rm -rf build
mkdir -p "$OUTPUT_DIR" "$DIST_DIR" "$DOCS_DIR"

echo "Building all Ghidra extensions..."
echo

# Build GhidraCtrlP
echo "[1/4] Building GhidraCtrlP..."
cd ../GhidraCtrlP

if [ -f "./gradlew" ]; then
    ./gradlew clean build
else
    echo "Using manual packaging for GhidraCtrlP..."
    CTRL_TEMP="../ghidra-extensions-deployment/build/temp/GhidraCtrlP"
    mkdir -p "$CTRL_TEMP"
    
    # Copy extension files
    cp -r ghidra_scripts "$CTRL_TEMP/"
    [ -d docs ] && cp -r docs "$CTRL_TEMP/"
    [ -d data ] && cp -r data "$CTRL_TEMP/"
    cp README.md "$CTRL_TEMP/" 2>/dev/null || true
    cp extension.properties "$CTRL_TEMP/" 2>/dev/null || true
    cp Module.manifest "$CTRL_TEMP/" 2>/dev/null || true
    
    # Create ZIP package
    CTRL_ZIP="../ghidra-extensions-deployment/$DIST_DIR/GhidraCtrlP/ghidra_${GHIDRA_VERSION}_PUBLIC_$(date +%Y%m%d)_GhidraCtrlP.zip"
    mkdir -p "$(dirname "$CTRL_ZIP")"
    (cd "$CTRL_TEMP" && zip -r "$CTRL_ZIP" *)
fi

# Build GhidraLookup
echo "[2/4] Building GhidraLookup..."
cd ../GhidraLookup
if [ -d dist ]; then
    mkdir -p "../ghidra-extensions-deployment/$DIST_DIR/GhidraLookup"
    cp dist/*.zip "../ghidra-extensions-deployment/$DIST_DIR/GhidraLookup/"
    cp README.md "../ghidra-extensions-deployment/$DOCS_DIR/GhidraLookup-README.md" 2>/dev/null || true
    echo "GhidraLookup: Using existing build"
else
    echo "GhidraLookup: No distribution found - skipping"
fi

# Build GhidrAssist
echo "[3/4] Building GhidrAssist..."
cd ../GhidrAssist
if [ -d dist ]; then
    mkdir -p "../ghidra-extensions-deployment/$DIST_DIR/GhidrAssist"
    cp dist/*.zip "../ghidra-extensions-deployment/$DIST_DIR/GhidrAssist/"
    cp README.md "../ghidra-extensions-deployment/$DOCS_DIR/GhidrAssist-README.md" 2>/dev/null || true
    echo "GhidrAssist: Using existing build"
else
    echo "GhidrAssist: No distribution found - skipping"
fi

# Build Ghidrathon
echo "[4/4] Building Ghidrathon..."
cd ../Ghidrathon
if [ -d dist ]; then
    mkdir -p "../ghidra-extensions-deployment/$DIST_DIR/Ghidrathon"
    cp dist/*.zip "../ghidra-extensions-deployment/$DIST_DIR/Ghidrathon/"
    cp README.md "../ghidra-extensions-deployment/$DOCS_DIR/Ghidrathon-README.md" 2>/dev/null || true
    echo "Ghidrathon: Using existing build"
else
    echo "Ghidrathon: No distribution found - skipping"
fi

cd ../ghidra-extensions-deployment

echo
echo "Generating documentation..."

# Generate master documentation
cat > "$DOCS_DIR/README.md" << EOF
# Catalytic Computing - Ghidra Extensions Suite

A comprehensive collection of professional Ghidra extensions designed to enhance reverse engineering workflows.

## Version Information
- **Suite Version**: $BUILD_VERSION
- **Target Ghidra Version**: $GHIDRA_VERSION
- **Build Date**: $(date)

## Extensions Overview

### GhidraCtrlP
Fast navigation and command palette for Ghidra - VS Code style Ctrl+P functionality

### GhidraLookup
Win32 API documentation lookup functionality with automatic constant analysis

### GhidrAssist
AI-assisted reverse engineering with LLM integration and automation features

### Ghidrathon
Python 3 integration for Ghidra scripting with modern library support

## Installation

See INSTALLATION_GUIDE.md for detailed setup instructions.

## Support

For issues and support, refer to individual extension documentation.
EOF

# Generate installation guide
cat > "$DOCS_DIR/INSTALLATION_GUIDE.md" << EOF
# Installation Guide - Catalytic Computing Ghidra Extensions

## Prerequisites
- Ghidra $GHIDRA_VERSION or later
- Java 17 or later
- Python 3.8+ (for Ghidrathon)

## Quick Install

1. Set GHIDRA_INSTALL_DIR environment variable:
   \`\`\`
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   \`\`\`

2. Run the installer:
   \`\`\`
   ./build-all.sh install
   \`\`\`

3. Start Ghidra and enable extensions via File > Install Extensions

## Manual Installation

1. Copy ZIP files from dist/ directory to:
   GHIDRA_INSTALL_DIR/Extensions/Ghidra/

2. Restart Ghidra

3. Go to File > Install Extensions and select the ZIP files

## Extension Configuration

- **GhidraCtrlP**: Add keyboard shortcut (Ctrl+P recommended)
- **GhidraLookup**: Enable in File > Configure > Miscellaneous
- **GhidrAssist**: Configure API keys in Tools > GhidrAssist Settings
- **Ghidrathon**: Run python ghidrathon_configure.py after installation
EOF

echo
echo "Creating master distribution package..."
MASTER_ZIP="build/CatalyticComputing-GhidraExtensions-$BUILD_VERSION.zip"
(cd "$OUTPUT_DIR" && zip -r "../CatalyticComputing-GhidraExtensions-$BUILD_VERSION.zip" *)

echo
echo "====================================================="
echo "BUILD COMPLETED SUCCESSFULLY!"
echo "====================================================="
echo "Output directory: $OUTPUT_DIR"
echo "Master package: $MASTER_ZIP"

EXTENSION_COUNT=$(find "$DIST_DIR" -name "*.zip" 2>/dev/null | wc -l)
echo "Extensions packaged: $EXTENSION_COUNT"

echo
echo "To install extensions:"
echo "1. Set GHIDRA_INSTALL_DIR environment variable"
echo "2. Run: ./build-all.sh install"
echo "3. Or manually copy ZIP files to Ghidra/Extensions/Ghidra/"
echo

# Handle install command
if [ "$1" = "install" ]; then
    echo "Installing extensions to Ghidra..."
    GHIDRA_EXT_DIR="$GHIDRA_INSTALL_DIR/Extensions/Ghidra"
    
    if [ ! -d "$GHIDRA_EXT_DIR" ]; then
        echo "ERROR: Ghidra extensions directory not found: $GHIDRA_EXT_DIR"
        echo "Please verify GHIDRA_INSTALL_DIR is correct."
        exit 1
    fi
    
    echo "Copying extensions to: $GHIDRA_EXT_DIR"
    find "$DIST_DIR" -name "*.zip" -exec cp {} "$GHIDRA_EXT_DIR/" \;
    
    echo
    echo "Extensions installed successfully!"
    echo "Please restart Ghidra and use File > Install Extensions to enable them."
fi