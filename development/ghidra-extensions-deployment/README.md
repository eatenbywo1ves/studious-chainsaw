# Ghidra Extensions Deployment

This repository provides production-ready Ghidra extensions with automated deployment, installation scripts, and comprehensive documentation.

## Available Extensions

### 1. CryptoDetect Extension
Advanced cryptographic routine detection for Ghidra 12.0+

**Features:**
- Multi-algorithm detection (AES, DES, SHA, MD5, RSA)
- Pattern matching with confidence scoring
- Entropy analysis for encrypted data detection
- Interactive UI with sortable results table
- Real-time background processing
- Direct navigation to detected crypto routines

**Version:** 1.0.0-SNAPSHOT  
**Compatibility:** Ghidra 12.0+

### 2. RetSync Extension
Real-time synchronization between Ghidra and debuggers (IDA Pro, x64dbg, OllyDbg, WinDbg)

**Features:**
- Bidirectional synchronization of cursor position
- Synchronized breakpoints across tools
- Comments and label synchronization
- Real-time collaboration support

**Version:** 10.2  
**Compatibility:** Ghidra 9.1.2 - 10.2+

## Quick Start

### Prerequisites
- Ghidra 12.0 or later installed
- Java 17+ runtime environment
- Windows, Linux, or macOS operating system

### Installation

#### Windows
```batch
# Set Ghidra installation directory
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra

# Run installation script
scripts\install.bat
```

#### Linux/macOS
```bash
# Set Ghidra installation directory
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Run installation script
chmod +x scripts/install.sh
./scripts/install.sh
```

## Directory Structure

```
ghidra-extensions-deployment/
├── extensions/
│   ├── crypto_detect/         # CryptoDetect extension
│   │   ├── source/            # Source code
│   │   ├── releases/          # Built packages
│   │   └── docs/              # Documentation
│   └── retsync/              # RetSync extension
│       ├── ghidra_10.2/      # Version-specific builds
│       ├── releases/         # Built packages
│       └── docs/             # Documentation
├── scripts/                  # Installation and utility scripts
│   ├── install.bat          # Windows installer
│   ├── install.sh           # Unix/Linux installer
│   └── verify.py            # Installation verification
├── .github/
│   └── workflows/           # GitHub Actions CI/CD
│       └── build-and-release.yml
└── README.md                # This file
```

## Building from Source

### CryptoDetect Extension

```batch
cd extensions\crypto_detect\source
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
build-package.bat
```

The built package will be available in `extensions/crypto_detect/source/dist/`

### RetSync Extension

RetSync is provided as a pre-built binary. To rebuild from source, visit the [RetSync GitHub repository](https://github.com/bootleg/ret-sync).

## Installation Methods

### Method 1: Script Installation (Recommended)
Use the provided installation scripts for automatic setup.

### Method 2: Manual Installation
1. Download the extension package from `releases/`
2. Open Ghidra
3. Navigate to File → Install Extensions
4. Click the green "+" button
5. Select the extension ZIP file
6. Restart Ghidra

### Method 3: Development Installation
1. Copy extension folder to `~/.ghidra/.ghidra_<version>/Extensions/`
2. Restart Ghidra
3. Enable in Window → Script Manager

## Extension Configuration

### CryptoDetect
After installation:
1. Open a binary in Ghidra
2. Navigate to Window → CryptoDetect
3. Click "Analyze" to start detection
4. Double-click results to navigate to code

### RetSync
Configuration steps:
1. Install the corresponding plugin in your debugger
2. Start the sync server in Ghidra (Tools → RetSync)
3. Connect from your debugger
4. Synchronization begins automatically

## Compatibility Matrix

| Extension     | Ghidra 9.x | Ghidra 10.x | Ghidra 11.x | Ghidra 12.x |
|--------------|------------|-------------|-------------|-------------|
| CryptoDetect | ❌         | ❌          | ⚠️          | ✅          |
| RetSync      | ✅         | ✅          | ⚠️          | 🔄          |

Legend:
- ✅ Fully supported
- ⚠️ Partially supported (may require modifications)
- ❌ Not supported
- 🔄 In development

## Troubleshooting

### Common Issues

**Issue: Extension not appearing in Ghidra**
- Verify GHIDRA_INSTALL_DIR is set correctly
- Check extension compatibility with your Ghidra version
- Ensure Java 17+ is installed

**Issue: Build fails with Gradle errors**
- Update Gradle to version 7.5+
- Verify GHIDRA_INSTALL_DIR environment variable
- Check network connectivity for dependency downloads

**Issue: RetSync connection fails**
- Ensure both tools are using the same port (default: 9100)
- Check firewall settings
- Verify debugger plugin is installed correctly

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

- **CryptoDetect**: MIT License (see extensions/crypto_detect/source/LICENSE)
- **RetSync**: MIT License (see extensions/retsync/ghidra_10.2/LICENCE)

## Support

For issues, feature requests, or questions:
- Open an issue on GitHub
- Check existing documentation in `docs/`
- Review extension-specific README files

## Acknowledgments

- CryptoDetect: Developed for advanced cryptographic analysis in reverse engineering
- RetSync: Created by [bootleg](https://github.com/bootleg/ret-sync) for multi-tool synchronization

---

*Last updated: 2025-01-24*