# GhidraGo v2.1.0 - Production Release

**Automatic Go Binary Analysis for Ghidra 11.4.2**

[![Download Latest Release](https://img.shields.io/badge/Download-v2.1.0-blue)](https://github.com/eatenbywo1ves/studious-chainsaw/releases/latest)

## Overview

GhidraGo is a professional-grade toolkit for reverse engineering Go binaries in Ghidra. Version 2.1.0 introduces **automatic analysis** with full Ghidra 11.4.2 API compatibility.

### Key Features

✅ **Automatic Analysis** - Go binaries analyzed automatically on import (NEW!)
✅ **Function Recovery** - Automatically extract function names from PCLNTAB
✅ **Type Extraction** - Recover struct definitions, interfaces, and types
✅ **Security-Hardened** - Production-grade exception handling
✅ **KeyboardInterrupt Safe** - Emergency exit works during malware analysis
✅ **Detailed Logging** - Debug information for incident response
✅ **D3FEND Compliant** - Follows defensive security best practices

## What's New in v2.1.0

### Auto-Analyzer Restored

✅ **Zero Manual Steps** - Import Go binary → Automatic analysis → Complete!
✅ **Ghidra 11.4.2 Compatible** - Fully updated to modern API
✅ **Robust Error Handling** - Comprehensive logging and fallback mechanisms

See [V2.1.0_RELEASE_NOTES.md](V2.1.0_RELEASE_NOTES.md) for complete details.

## Installation

### Extension Install (Recommended - v2.1.0)

1. **Download** the latest release: [ghidra_11.4.2_PUBLIC_20251004_GhidraGo.zip](https://github.com/eatenbywo1ves/studious-chainsaw/releases/latest)
2. Open Ghidra → **File → Install Extensions**
3. Click **"+"** → Select downloaded ZIP
4. **Restart Ghidra**
5. Import any Go binary - analysis runs automatically!

### Script Install (Manual - Advanced Users)

```bash
cd GhidraGo
./deploy-production.sh
```

Or manually:

```bash
cp -r ghidra_scripts/ghidrago ~/.ghidra/.ghidra_*/ghidra_scripts/
cp ghidra_scripts/RecoverGoFunctions.py ~/.ghidra/.ghidra_*/ghidra_scripts/
cp ghidra_scripts/RecoverGoFunctionsAndTypes.py ~/.ghidra/.ghidra_*/ghidra_scripts/
```

## Usage

### With Extension (v2.1.0)
1. Import Go binary
2. Analysis runs automatically
3. Functions and types recovered!

### With Scripts (Manual)
In Ghidra: **Window → Script Manager → RecoverGoFunctionsAndTypes.py**

## Documentation

- [Security Exception Handling](SECURITY_EXCEPTION_HANDLING.md)
- [Exception API](ghidra_scripts/ghidrago/exceptions.py)
- [Deployment Guide](deploy-production.sh)

## Version 2.0.0 - Production Ready

✅ Security-hardened exception handling  
✅ KeyboardInterrupt preservation  
✅ Production deployment automation  
✅ D3FEND compliance  

Developed by Catalytic Computing for defensive security operations.
