#!/bin/bash

echo "==================================="
echo "Plugin Installation Script"
echo "==================================="

GHIDRA_PATH="/c/Users/Corbin/Downloads/ghidra-master/build/ghidra_12.0_DEV"
GHIDRA_EXTENSIONS="$HOME/.ghidra/.ghidra_12.0_DEV/Extensions"

# Create directories
mkdir -p "$GHIDRA_EXTENSIONS"

echo ""
echo "Installing Ghidra Plugins..."
echo "----------------------------"

# Install GhidraEmu (Python-based, no build needed)
echo "Installing GhidraEmu..."
if [ -d ~/ghidra-plugins/GhidraEmu ]; then
    cp ~/ghidra-plugins/GhidraEmu/ghidra_emu.py "$GHIDRA_PATH/Ghidra/Features/Base/ghidra_scripts/"
    echo "✓ GhidraEmu installed"
fi

# Install LazyGhidra
echo "Installing LazyGhidra..."
if [ -d ~/ghidra-plugins/LazyGhidra ]; then
    cp -r ~/ghidra-plugins/LazyGhidra/ghidra_scripts/* "$GHIDRA_PATH/Ghidra/Features/Base/ghidra_scripts/" 2>/dev/null
    echo "✓ LazyGhidra installed"
fi

# Build Ghidrathon
echo "Building Ghidrathon..."
if [ -d ~/ghidra-plugins/Ghidrathon ]; then
    cd ~/ghidra-plugins/Ghidrathon
    export GHIDRA_INSTALL_DIR="$GHIDRA_PATH"
    gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_PATH" 2>/dev/null
    if [ -f dist/*.zip ]; then
        cp dist/*.zip "$GHIDRA_EXTENSIONS/"
        echo "✓ Ghidrathon built and installed"
    fi
fi

# Build Kaiju
echo "Building Kaiju..."
if [ -d ~/ghidra-plugins/kaiju ]; then
    cd ~/ghidra-plugins/kaiju/ghidra
    export GHIDRA_INSTALL_DIR="$GHIDRA_PATH"
    gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_PATH" 2>/dev/null
    if [ -f dist/*.zip ]; then
        cp dist/*.zip "$GHIDRA_EXTENSIONS/"
        echo "✓ Kaiju built and installed"
    fi
fi

# Build C++ Class Analyzer
echo "Building C++ Class Analyzer..."
if [ -d ~/ghidra-plugins/Ghidra-Cpp-Class-Analyzer ]; then
    cd ~/ghidra-plugins/Ghidra-Cpp-Class-Analyzer
    export GHIDRA_INSTALL_DIR="$GHIDRA_PATH"
    gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_PATH" 2>/dev/null
    if [ -f dist/*.zip ]; then
        cp dist/*.zip "$GHIDRA_EXTENSIONS/"
        echo "✓ C++ Class Analyzer built and installed"
    fi
fi

# Build GhidraSwitch
echo "Building GhidraSwitch..."
if [ -d ~/ghidra-plugins/GhidraSwitch ]; then
    cd ~/ghidra-plugins/GhidraSwitch
    export GHIDRA_INSTALL_DIR="$GHIDRA_PATH"
    gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_PATH" 2>/dev/null
    if [ -f dist/*.zip ]; then
        cp dist/*.zip "$GHIDRA_EXTENSIONS/"
        echo "✓ GhidraSwitch built and installed"
    fi
fi

# Install ret-sync
echo "Installing ret-sync..."
if [ -d ~/ghidra-plugins/ret-sync ]; then
    cp -r ~/ghidra-plugins/ret-sync/ext_ghidra/dist/*.zip "$GHIDRA_EXTENSIONS/" 2>/dev/null
    echo "✓ ret-sync installed"
fi

echo ""
echo "==================================="
echo "Wireshark Plugin Setup"
echo "==================================="

# Check if Wireshark is installed
WIRESHARK_PATH="/c/Program Files/Wireshark"
if [ -d "$WIRESHARK_PATH" ]; then
    echo "✓ Wireshark found at: $WIRESHARK_PATH"

    # Create plugin directories
    mkdir -p "$APPDATA/Wireshark/plugins"
    mkdir -p "$APPDATA/Wireshark/profiles"

    echo "Plugin directories created:"
    echo "  - $APPDATA/Wireshark/plugins"
    echo "  - $APPDATA/Wireshark/profiles"
else
    echo "⚠ Wireshark not found. Please install it first."
fi

echo ""
echo "==================================="
echo "Installation Summary"
echo "==================================="
echo "Ghidra Extensions: $GHIDRA_EXTENSIONS"
echo "Ghidra Scripts: $GHIDRA_PATH/Ghidra/Features/Base/ghidra_scripts/"
echo ""
echo "To activate plugins in Ghidra:"
echo "1. Restart Ghidra"
echo "2. Go to File → Install Extensions"
echo "3. Select the plugins you want to enable"
echo ""
echo "For scripts:"
echo "1. Open CodeBrowser"
echo "2. Window → Script Manager"
echo "3. Refresh script list"
echo ""
echo "Done! 🎉"