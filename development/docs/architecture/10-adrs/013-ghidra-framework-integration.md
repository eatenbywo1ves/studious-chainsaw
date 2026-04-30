# ADR-013: Ghidra Framework Integration

**Status**: Accepted | **Date**: 2024-10-14 | **Deciders**: RE Team, Architecture

## Decision
Integrate **NSA Ghidra 11.x** as the core reverse engineering framework via GhidraGo toolkit.

## Rationale
- Open source (Apache 2.0) - no licensing costs at scale
- Extensible Java/Python API for automation
- Supports 30+ processor architectures
- Active community and government backing
- Headless mode for server-side analysis

## Architecture
```
┌─────────────────────────────────────────────────┐
│                  GhidraGo v2.2.0                │
├─────────────────────────────────────────────────┤
│  REST API  │  Type Cache  │  Analysis Pipeline  │
├─────────────────────────────────────────────────┤
│              Ghidra Headless Analyzer           │
├─────────────────────────────────────────────────┤
│    Decompiler    │    Disassembler    │  SLEIGH │
└─────────────────────────────────────────────────┘
```

## Key Extensions
| Extension | Purpose |
|-----------|---------|
| Type Caching | Persist decompiled types across sessions |
| Batch Analysis | Parallel binary processing |
| REST Bridge | HTTP API for Ghidra operations |
| Script Runner | Automated Ghidra Python scripts |

## Performance
- Analysis throughput: 50+ binaries/hour (headless)
- Type cache hit rate: 85%+ on repeated analysis
- Memory footprint: 4-8GB per analysis instance

## Alternatives Rejected
- **IDA Pro**: $1,500+ per seat, proprietary
- **Binary Ninja**: Less mature scripting API
- **Radare2**: Steeper learning curve, less GUI

---
**Last Updated**: 2024-10-15
