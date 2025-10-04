# GhidraGo v2.0.0 - Production Release

**Security-Hardened Go Binary Analysis for Ghidra**

## Overview

GhidraGo is a professional-grade toolkit for reverse engineering Go binaries in Ghidra. Version 2.0.0 introduces **production-ready exception handling** following defensive security principles.

### Key Features

✅ **Function Recovery** - Automatically extract function names from PCLNTAB  
✅ **Type Extraction** - Recover struct definitions, interfaces, and types  
✅ **Security-Hardened** - Production-grade exception handling  
✅ **KeyboardInterrupt Safe** - Emergency exit works during malware analysis  
✅ **Detailed Logging** - Debug information for incident response  
✅ **D3FEND Compliant** - Follows defensive security best practices  

## What's New in v2.0.0

### Security-Critical Improvements

See [SECURITY_EXCEPTION_HANDLING.md](SECURITY_EXCEPTION_HANDLING.md) for complete details.

## Installation

### Quick Install (Recommended)

```bash
cd GhidraGo
./deploy-production.sh
```

### Manual Install

```bash
cp -r ghidra_scripts/ghidrago ~/.ghidra/.ghidra_*/ghidra_scripts/
cp ghidra_scripts/RecoverGoFunctions.py ~/.ghidra/.ghidra_*/ghidra_scripts/
cp ghidra_scripts/RecoverGoFunctionsAndTypes.py ~/.ghidra/.ghidra_*/ghidra_scripts/
```

## Usage

In Ghidra: **Analysis → Golang → Recover Functions**

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
