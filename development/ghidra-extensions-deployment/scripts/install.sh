#!/bin/bash

# Ghidra Extensions Installer for Unix/Linux/macOS
# Automatically installs CryptoDetect and RetSync extensions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================"
echo "   Ghidra Extensions Installer - Unix/Linux"
echo "============================================"
echo

# Function to print colored output
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Step 1: Check Ghidra installation
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    print_error "GHIDRA_INSTALL_DIR environment variable not set"
    echo
    echo "Searching for Ghidra installation..."
    
    # Search common locations - user directories first, then system directories
    SEARCH_PATHS="$HOME/development/ghidra* $HOME/dev/ghidra* $HOME/Downloads/ghidra* $HOME/ghidra* $HOME/tools/ghidra* /opt/ghidra* /usr/local/ghidra* /Applications/ghidra*"

    for path_pattern in $SEARCH_PATHS; do
        for path in $path_pattern; do
            if [ -d "$path" ] && [ -f "$path/ghidraRun" ]; then
                GHIDRA_INSTALL_DIR="$path"
                echo "Found Ghidra at: $path"
                break 2
            fi
        done
    done
    
    if [ -z "$GHIDRA_INSTALL_DIR" ]; then
        echo
        echo "Could not find Ghidra installation automatically."
        echo "Please set GHIDRA_INSTALL_DIR manually:"
        echo
        echo "Example: export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0_DEV"
        echo
        exit 1
    fi
fi

echo "Using Ghidra installation: $GHIDRA_INSTALL_DIR"
echo

# Step 2: Detect Ghidra version
if [ -f "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" ]; then
    GHIDRA_VERSION=$(grep "application.version" "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" | cut -d'=' -f2)
else
    print_warning "Could not detect Ghidra version"
    GHIDRA_VERSION="unknown"
fi

echo "Detected Ghidra version: $GHIDRA_VERSION"
echo

# Step 3: Detect version suffix and create Extensions directory
echo "Detecting Ghidra user directory..."
GHIDRA_BASE_DIR="$HOME/.ghidra"
VERSION_SUFFIX=""

# Try different version suffixes in order of preference
for suffix in "_DEV" "_PUBLIC" "_build" ""; do
    TEST_DIR="$GHIDRA_BASE_DIR/.ghidra_${GHIDRA_VERSION}${suffix}"
    if [ -d "$TEST_DIR" ]; then
        VERSION_SUFFIX="$suffix"
        break
    fi
done

if [ -z "$VERSION_SUFFIX" ]; then
    echo "Using default _DEV suffix"
    VERSION_SUFFIX="_DEV"
fi

EXTENSIONS_DIR="$GHIDRA_BASE_DIR/.ghidra_${GHIDRA_VERSION}${VERSION_SUFFIX}/Extensions"
echo "Using extensions directory: $EXTENSIONS_DIR"

if [ ! -d "$EXTENSIONS_DIR" ]; then
    echo "Creating Extensions directory..."
    mkdir -p "$EXTENSIONS_DIR"
fi

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# Step 4: Install CryptoDetect
echo "Installing CryptoDetect Extension..."
echo "----------------------------------------"

CRYPTO_SOURCE="$BASE_DIR/extensions/crypto_detect/source"
CRYPTO_DEST="$EXTENSIONS_DIR/crypto_detect"

if [ -d "$CRYPTO_DEST" ]; then
    echo "Removing existing CryptoDetect installation..."
    rm -rf "$CRYPTO_DEST"
fi

echo "Copying CryptoDetect files..."
cp -r "$CRYPTO_SOURCE" "$CRYPTO_DEST"

if [ $? -eq 0 ]; then
    print_success "CryptoDetect installed successfully"
else
    print_error "Failed to install CryptoDetect"
fi
echo

# Step 5: Install RetSync
echo "Installing RetSync Extension..."
echo "----------------------------------------"

RETSYNC_SOURCE="$BASE_DIR/extensions/retsync/ghidra_10.2"
RETSYNC_DEST="$EXTENSIONS_DIR/retsync"

if [ -d "$RETSYNC_DEST" ]; then
    echo "Removing existing RetSync installation..."
    rm -rf "$RETSYNC_DEST"
fi

echo "Copying RetSync files..."
cp -r "$RETSYNC_SOURCE" "$RETSYNC_DEST"

if [ $? -eq 0 ]; then
    print_success "RetSync installed successfully"
else
    print_error "Failed to install RetSync"
fi
echo

# Step 6: Set permissions
echo "Setting file permissions..."
chmod -R 755 "$EXTENSIONS_DIR"

# Step 7: Verify installation
echo "Verifying Installation..."
echo "----------------------------------------"

INSTALL_SUCCESS=1

if [ -f "$CRYPTO_DEST/extension.properties" ]; then
    echo -e "${GREEN}[OK]${NC} CryptoDetect extension files found"
else
    echo -e "${RED}[FAIL]${NC} CryptoDetect extension files missing"
    INSTALL_SUCCESS=0
fi

if [ -f "$RETSYNC_DEST/extension.properties" ]; then
    echo -e "${GREEN}[OK]${NC} RetSync extension files found"
else
    echo -e "${RED}[FAIL]${NC} RetSync extension files missing"
    INSTALL_SUCCESS=0
fi

echo
echo "============================================"
if [ $INSTALL_SUCCESS -eq 1 ]; then
    echo "   INSTALLATION COMPLETED SUCCESSFULLY"
    echo
    echo "Extensions have been installed to:"
    echo "$EXTENSIONS_DIR"
    echo
    echo "Next steps:"
    echo "1. Start Ghidra"
    echo "2. Navigate to File -> Configure -> Extensions"
    echo "3. Enable the installed extensions"
    echo "4. Restart Ghidra to activate"
else
    echo "   INSTALLATION COMPLETED WITH ERRORS"
    echo
    echo "Please check the error messages above and try again."
fi
echo "============================================"
echo

# Step 8: Optional - Create desktop entry (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -n "Would you like to create a desktop entry for Ghidra? (y/n): "
    read CREATE_DESKTOP
    
    if [ "$CREATE_DESKTOP" = "y" ] || [ "$CREATE_DESKTOP" = "Y" ]; then
        DESKTOP_FILE="$HOME/.local/share/applications/ghidra.desktop"
        
        cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=Ghidra
Comment=Software Reverse Engineering Suite
Exec=$GHIDRA_INSTALL_DIR/ghidraRun
Icon=$GHIDRA_INSTALL_DIR/support/ghidra.ico
Terminal=false
Type=Application
Categories=Development;ReverseEngineering;
EOF
        
        chmod +x "$DESKTOP_FILE"
        print_success "Desktop entry created"
    fi
fi

# Step 9: Add to PATH (optional)
echo
echo -n "Would you like to add Ghidra to your PATH? (y/n): "
read ADD_TO_PATH

if [ "$ADD_TO_PATH" = "y" ] || [ "$ADD_TO_PATH" = "Y" ]; then
    # Detect shell
    if [ -n "$BASH_VERSION" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        SHELL_RC="$HOME/.zshrc"
    else
        SHELL_RC="$HOME/.profile"
    fi
    
    # Check if already in PATH
    if ! grep -q "GHIDRA_INSTALL_DIR" "$SHELL_RC"; then
        echo "" >> "$SHELL_RC"
        echo "# Ghidra installation" >> "$SHELL_RC"
        echo "export GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> "$SHELL_RC"
        echo "export PATH=\$PATH:\$GHIDRA_INSTALL_DIR" >> "$SHELL_RC"
        
        print_success "Added Ghidra to PATH in $SHELL_RC"
        echo "Please run: source $SHELL_RC"
    else
        print_warning "Ghidra already in PATH"
    fi
fi

echo
echo "Installation complete!"