# CryptoDetect Installation Guide

## Prerequisites

- Ghidra 12.0 or later
- Java 17 or later
- Gradle (for building from source)

## Installation Methods

### Method 1: Pre-built Extension (Recommended)

1. Download the latest `crypto_detect.zip` from releases
2. Extract to a temporary directory
3. Copy the `crypto_detect` folder to your Ghidra extensions directory:
   ```
   Windows: %USERPROFILE%\.ghidra\.ghidra_12.0_DEV\Extensions\
   Linux/Mac: ~/.ghidra/.ghidra_12.0_DEV/Extensions/
   ```
4. Start Ghidra
5. Go to **File → Configure → Miscellaneous**
6. Check the box next to **CryptoDetect** to enable the extension
7. Restart Ghidra

### Method 2: Build from Source

1. Clone or download the source code
2. Navigate to the extension directory:
   ```bash
   cd crypto_detect
   ```
3. Set the GHIDRA_INSTALL_DIR environment variable:
   ```bash
   # Windows
   set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
   
   # Linux/Mac
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```
4. Build the extension:
   ```bash
   gradle build
   ```
5. Copy the built extension to Ghidra extensions directory
6. Enable in Ghidra as described in Method 1

## Verification

After installation and enabling:

1. Open Ghidra
2. Load any binary file
3. Check if **Window → CryptoDetect** menu item is available
4. If available, the extension is successfully installed

## Troubleshooting

### Extension not appearing in Configure dialog
- Verify the extension is in the correct Extensions directory
- Check that all required files are present (extension.properties, Module.manifest, etc.)
- Ensure file permissions allow Ghidra to read the extension files

### Build failures
- Verify GHIDRA_INSTALL_DIR is set correctly
- Ensure Java 17+ is being used
- Check that Gradle can access Ghidra's build files

### Runtime errors
- Check Ghidra's console for error messages
- Verify Ghidra version compatibility
- Ensure all dependencies are available

## Uninstallation

1. Go to **File → Configure → Miscellaneous**
2. Uncheck **CryptoDetect**
3. Restart Ghidra
4. Delete the `crypto_detect` folder from the Extensions directory

## Support

For issues and bug reports, please refer to the project documentation or contact the extension maintainers.