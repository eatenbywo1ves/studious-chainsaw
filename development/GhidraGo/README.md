# GhidraGo v2.2.0 - Performance Optimization Release 🚀

**Automatic Go Binary Analysis for Ghidra 11.4.2**

[![Download Latest Release](https://img.shields.io/badge/Download-v2.2.0-blue)](https://github.com/eatenbywo1ves/studious-chainsaw/releases/latest)
[![Performance](https://img.shields.io/badge/Re--Analysis-64%25%20Faster-brightgreen)](V2.2.0_RELEASE_NOTES.md)

## Overview

GhidraGo is a professional-grade toolkit for reverse engineering Go binaries in Ghidra. Version 2.2.0 delivers **intelligent performance caching** for 64% faster re-analysis workflows.

### Key Features

⚡ **Performance Caching** - 64% faster re-analysis (NEW in v2.2.0!)
🗄️ **Moduledata Caching** - 40-60% speedup on unchanged binaries (NEW!)
🧠 **Type Memoization** - 30-50% faster type extraction (NEW!)
✅ **Automatic Analysis** - Go binaries analyzed automatically on import
✅ **Function Recovery** - Automatically extract function names from PCLNTAB
✅ **Type Extraction** - Recover struct definitions, interfaces, and types
✅ **Security-Hardened** - Production-grade exception handling
✅ **D3FEND Compliant** - Follows defensive security best practices

## What's New in v2.2.0 🚀

### Performance Optimization

⚡ **64% Faster Re-Analysis** - Intelligent caching for iterative workflows
🗄️ **Moduledata Caching** - SHA256-based binary fingerprinting (40-60% speedup)
🧠 **Type Memoization** - Eliminate redundant type parsing (30-50% speedup)
📊 **Performance Metrics** - Built-in cache hit rate tracking

**Benchmark: Hugo.exe (20MB)**
- v2.1.0: 49.6 seconds
- v2.2.0 (re-analysis): **18.0 seconds** (64.4% faster! ⚡)

See [V2.2.0_RELEASE_NOTES.md](V2.2.0_RELEASE_NOTES.md) for complete benchmarks and technical details.

### Previous Releases

- **v2.1.0** - Auto-Analyzer + Help System + GitHub Release ([notes](V2.1.0_RELEASE_NOTES.md))
- **v2.0.0** - Type Extraction + Security Hardening

## Installation

### Extension Install (Recommended - v2.2.0)

1. **Download** the latest release: [ghidra_11.4.2_PUBLIC_20251004_GhidraGo.zip](https://github.com/eatenbywo1ves/studious-chainsaw/releases/latest)
2. Open Ghidra → **File → Install Extensions**
3. Click **"+"** → Select downloaded ZIP
4. **Restart Ghidra**
5. Import any Go binary - analysis runs automatically with caching!

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

### With Extension (v2.2.0)
1. Import Go binary
2. Analysis runs automatically (first run: builds cache)
3. Functions and types recovered!
4. Re-run analysis → **64% faster** (cache hit! ⚡)

### With Scripts (Manual)
In Ghidra: **Window → Script Manager → RecoverGoFunctionsAndTypes.py**

### Performance Tips
- **Iterative analysis**: Re-analysis gets 64% speedup after first run
- **Same session**: Moduledata cache persists across analyses
- **Cache stats**: Check console for cache hit rate metrics

## Documentation

### Performance & Architecture
- [v2.2.0 Release Notes](V2.2.0_RELEASE_NOTES.md) - Performance benchmarks and caching details
- [Phase 4 Track 4 Completion](PHASE4_TRACK4_COMPLETION.md) - Technical implementation guide

### Security & Deployment
- [Security Exception Handling](SECURITY_EXCEPTION_HANDLING.md)
- [Exception API](ghidra_scripts/ghidrago/exceptions.py)
- [Deployment Guide](deploy-production.sh)

## Version History

- **v2.2.0** (Oct 4, 2025) - Performance caching (64% faster re-analysis) 🚀
- **v2.1.0** (Oct 4, 2025) - Auto-analyzer + Help system
- **v2.0.0** (Oct 4, 2025) - Type extraction + Security hardening
- **v1.0.0** (Oct 2, 2025) - Function recovery MVP

## Contributing

Report issues and performance results at:
https://github.com/eatenbywo1ves/studious-chainsaw/issues

## License

Developed by Catalytic Computing for defensive security operations.
