# Catalytic Computing - Ghidra Extensions Deployment System

A comprehensive build and deployment system for packaging and distributing professional Ghidra extensions.

## Overview

This deployment system automates the building, packaging, validation, and installation of four powerful Ghidra extensions:

- **GhidraCtrlP**: VS Code-style Ctrl+P navigation with fuzzy search
- **GhidraLookup**: Win32 API documentation lookup with automatic constant analysis  
- **GhidrAssist**: AI-powered reverse engineering with LLM integration
- **Ghidrathon**: Full Python 3 scripting environment for Ghidra

## Features

- ✅ **Automated Building**: Build all extensions with a single command
- ✅ **Cross-Platform**: Works on Windows, Linux, and macOS
- ✅ **Validation Suite**: Comprehensive testing of packaged extensions
- ✅ **Master Distribution**: Single ZIP containing all extensions
- ✅ **Auto-Installation**: Direct installation to Ghidra
- ✅ **Documentation Generation**: Automatic creation of user guides
- ✅ **CI/CD Ready**: Designed for automated deployment pipelines

## Quick Start

### Prerequisites

1. **Set Environment Variable**:
   ```powershell
   # Windows
   $env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_11.4.2_PUBLIC"
   
   # Linux/macOS
   export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.2_PUBLIC
   ```

2. **Requirements**:
   - Ghidra 11.4.2 or later
   - Java 17+ (required by Ghidra)
   - Python 3.8+ (for Ghidrathon)

### Build and Deploy

**Windows:**
```powershell
# Build all extensions
.\package-extensions.ps1

# Build and install to Ghidra
.\package-extensions.ps1 -Install

# Validate extensions
.\validate-extensions.ps1
```

**Linux/macOS:**
```bash
# Build all extensions
./build-all.sh

# Build and install to Ghidra  
./build-all.sh install

# Validate (use PowerShell script or manual testing)
```

### Manual Installation

1. Run the build script to create packages
2. Copy ZIP files from `build/catalytic-ghidra-extensions/dist/` to `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/`
3. Launch Ghidra → **File** → **Install Extensions**
4. Select the copied ZIP files and restart Ghidra

## Build System Architecture

### Directory Structure
```
ghidra-extensions-deployment/
├── build-all.gradle          # Gradle-based master build
├── build-all.sh             # Linux/macOS shell script
├── build-all.bat            # Windows batch script  
├── package-extensions.ps1    # PowerShell build script (recommended)
├── validate-extensions.ps1   # Validation test suite
├── build/                    # Build output directory
│   ├── catalytic-ghidra-extensions/
│   │   ├── dist/            # Individual extension packages
│   │   │   ├── GhidraCtrlP/
│   │   │   ├── GhidraLookup/
│   │   │   ├── GhidrAssist/
│   │   │   └── Ghidrathon/
│   │   └── docs/            # Generated documentation
│   ├── CatalyticComputing-GhidraExtensions-1.0.0.zip  # Master package
│   └── validation-report.json  # Test results
└── build-infrastructure/     # Advanced Gradle configurations
```

### Build Process

1. **Extension Analysis**: Detect existing builds and extension types
2. **Package Creation**: Create proper ZIP files for each extension
3. **Documentation Generation**: Auto-generate installation guides
4. **Master Package**: Combine all extensions into single distribution
5. **Validation**: Run comprehensive tests on all packages
6. **Installation**: Optional direct installation to Ghidra

## Extension Details

### GhidraCtrlP
- **Type**: Script-based extension
- **Size**: ~0.3 MB
- **Features**: Fuzzy search, keyboard shortcuts, command palette
- **Installation**: Copy scripts to ghidra_scripts directory

### GhidraLookup  
- **Type**: Java-based extension with resources
- **Size**: ~1.1 MB
- **Features**: Win32 API docs, constant analysis, MSDN integration
- **Dependencies**: JSON library for API data

### GhidrAssist
- **Type**: Complex Java extension
- **Size**: ~35 MB (includes AI libraries)
- **Features**: LLM integration, code explanation, RAG, MCP tools
- **Dependencies**: Jackson, Lucene, OkHttp, MCP libraries

### Ghidrathon
- **Type**: Java extension with Python integration
- **Size**: ~0.7 MB
- **Features**: Python 3.8+ scripting, Jep integration, modern libraries
- **Requirements**: Python runtime and Jep library

## Validation Suite

The validation system performs comprehensive testing:

- ✅ **Package Integrity**: ZIP files exist and are properly formatted
- ✅ **Size Validation**: Packages are reasonable size (not corrupted)
- ✅ **Structure Testing**: Extensions contain required files
- ✅ **Documentation Verification**: All guides are present and complete
- ✅ **Master Package**: Distribution bundle is properly created

### Running Validation

```powershell
.\validate-extensions.ps1
```

Sample output:
```
Validating GhidraCtrlP...
  PASS: ZIP file exists
  PASS: ZIP file not empty (Size: 0.26 MB)
  PASS: ZIP structure valid (Entries: 9)

Tests Passed: 18 / 18 (100%)
ALL TESTS PASSED! Extensions are ready for deployment.
```

## Advanced Usage

### Custom Build Versions
```powershell
.\package-extensions.ps1 -BuildVersion "2.0.0" -GhidraVersion "11.5.0"
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Build Ghidra Extensions
  run: |
    $env:GHIDRA_INSTALL_DIR = "${{ github.workspace }}/ghidra"
    .\package-extensions.ps1
    .\validate-extensions.ps1

- name: Upload Extensions
  uses: actions/upload-artifact@v3
  with:
    name: ghidra-extensions
    path: build/CatalyticComputing-GhidraExtensions-*.zip
```

### Gradle Integration
```bash
# Use advanced Gradle build system
gradle -f build-all.gradle buildAll packageAll
```

## Troubleshooting

### Common Issues

1. **GHIDRA_INSTALL_DIR not set**
   ```
   Solution: Set the environment variable before running scripts
   ```

2. **PowerShell execution policy**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Missing ZIP files**
   ```
   Solution: Ensure individual extensions have been built first
   Check: ../GhidraExtensionName/dist/ directories
   ```

4. **Validation failures**
   ```
   Check: build/validation-report.json for detailed error info
   ```

### Getting Help

- Review individual extension README files
- Check build logs for error messages  
- Verify all prerequisites are installed
- Ensure GHIDRA_INSTALL_DIR points to valid installation

## Development

### Adding New Extensions

1. Create extension directory in parent folder
2. Add entry to build scripts' extension lists
3. Ensure proper `extension.properties` and `Module.manifest` files
4. Update validation tests if needed

### Modifying Build Process

- **PowerShell Script**: Best for Windows, most features
- **Shell Script**: Good for Linux/macOS
- **Gradle Build**: Most flexible, requires Gradle installation
- **Batch Script**: Windows fallback option

## Release History

- **v1.0.0**: Initial release with all four extensions
- **v1.1.0**: Added comprehensive validation suite  
- **v1.2.0**: PowerShell build system with enhanced features

## Support

For issues, feature requests, or contributions:
- Check individual extension documentation
- Review build logs and validation reports
- Contact Catalytic Computing development team

---

*Catalytic Computing - Enhancing Reverse Engineering Through Automation*

**Build System Version**: 1.0.0  
**Compatible Ghidra Version**: 11.4.2+  
**Last Updated**: September 29, 2024