# CryptoDetect - Ghidra Extension

## Overview
CryptoDetect is an advanced Ghidra extension designed to automatically identify and analyze cryptographic routines in binary files. This extension helps reverse engineers and security researchers quickly locate and understand cryptographic implementations.

## Features
- **Automatic Crypto Detection**: Identifies common cryptographic algorithms (AES, DES, RSA, SHA, MD5, etc.)
- **Pattern Recognition**: Uses signature-based detection for crypto constants and structures
- **Interactive Analysis**: Provides detailed analysis results with cross-references
- **Extensible Framework**: Modular design allows for custom crypto detectors

## Installation
1. Copy the `crypto_detect` directory to your Ghidra extensions folder:
   ```
   ~/.ghidra/.ghidra_12.0_DEV/Extensions/
   ```
2. Start Ghidra and enable the extension via File → Configure → Miscellaneous → CryptoDetect

## Usage
1. Open a binary file in Ghidra
2. Access the CryptoDetect panel via Window → CryptoDetect
3. Click "Analyze" to scan for cryptographic routines
4. Review results in the analysis panel

## Development
This extension is built using Gradle and follows Ghidra's extension development standards.

### Building
```bash
gradle build
```

### Testing
```bash
gradle test
```

## License
MIT License - See LICENSE file for details

## Version
1.0.0-SNAPSHOT