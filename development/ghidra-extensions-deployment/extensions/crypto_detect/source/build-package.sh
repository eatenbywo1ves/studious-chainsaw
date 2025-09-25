#!/bin/bash
# Build script for CryptoDetect extension on Linux/Mac

echo "Building CryptoDetect Extension..."
echo

# Check if GHIDRA_INSTALL_DIR is set
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "ERROR: GHIDRA_INSTALL_DIR environment variable not set"
    echo "Please set it to your Ghidra installation directory"
    echo "Example: export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    exit 1
fi

echo "Using Ghidra installation: $GHIDRA_INSTALL_DIR"
echo

# Clean previous build
echo "Cleaning previous build..."
rm -rf build lib

# Build the extension
echo "Building extension..."
./gradlew clean build
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Create distribution package
echo "Creating distribution package..."
mkdir -p dist
rm -f dist/crypto_detect.zip

# Copy files for packaging
mkdir -p temp/crypto_detect
cp -r src temp/crypto_detect/
cp extension.properties temp/crypto_detect/
cp Module.manifest temp/crypto_detect/
cp LICENSE temp/crypto_detect/
cp README.md temp/crypto_detect/
cp INSTALL.md temp/crypto_detect/
cp CHANGELOG.md temp/crypto_detect/
mkdir -p temp/crypto_detect/lib
if [ -f build/libs/*.jar ]; then
    cp build/libs/*.jar temp/crypto_detect/lib/
fi

# Create zip package
cd temp
zip -r ../dist/crypto_detect.zip crypto_detect/
cd ..

# Clean up temp directory
rm -rf temp

echo
echo "Build completed successfully!"
echo "Extension package created: dist/crypto_detect.zip"
echo