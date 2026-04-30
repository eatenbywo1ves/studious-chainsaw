# GhidraGo Toolkit Container

**C4 Model Level 2: Container Detail**

## Overview

GhidraGo is the reverse engineering toolkit providing binary analysis capabilities built on the NSA's Ghidra framework. It includes custom extensions, Golang binary analysis, and automated analysis pipelines.

---

## Container Specifications

| Attribute | Value |
|-----------|-------|
| **Name** | GhidraGo Toolkit |
| **Technology** | Java 17+, Python 3.11+ (Ghidrathon), Go 1.16+ |
| **Base** | Ghidra 11.4.2 |
| **Deployment** | Standalone / Headless |
| **Image** | `catalytic/ghidrago:latest` |

---

## Components

### 1. GhidraGo Core (v2.2.0)
Golang binary analyzer with intelligent type caching.

**Features**:
- Go binary detection and parsing
- Runtime type reconstruction
- Symbol recovery
- Cross-reference analysis

### 2. Ghidra Extensions

| Extension | Purpose | Language |
|-----------|---------|----------|
| **GhidraCtrlP** | Quick navigation (Ctrl+P fuzzy finder) | Java |
| **GhidraLookup** | API/function lookup | Java |
| **GhidrAssist** | AI-assisted analysis | Java/Python |
| **Ghidrathon** | Python 3 scripting support | Java/Python |
| **GhidraGraph** | Enhanced graph visualization | Java |
| **GolangLoader** | Go binary loader | Java |

### 3. Analysis Scripts

```
scripts/
├── arm_rop_finder.py      # ARM ROP gadget finder
├── mips_rop_finder.py     # MIPS ROP gadget finder
├── malware_analysis.py    # Malware pattern detection
├── string_decoder.py      # Encoded string decryption
├── function_classifier.py # ML-based function classification
└── batch_analyzer.py      # Batch processing wrapper
```

---

## Responsibilities

1. **Binary Analysis**
   - Disassembly and decompilation
   - Control flow graph generation
   - Data flow analysis
   - Cross-reference mapping

2. **Golang-Specific Analysis**
   - Go runtime detection
   - Interface type recovery
   - Goroutine identification
   - Channel communication tracing

3. **Automation**
   - Headless analysis mode
   - Batch processing pipelines
   - API for integration with other services
   - Scheduled analysis jobs

4. **Extensibility**
   - Custom loader development
   - Script API (Python via Ghidrathon)
   - Java extension API
   - Plugin marketplace integration

---

## Deployment Modes

### 1. Interactive Mode (Analyst Workstation)
```bash
# Launch Ghidra with extensions
./ghidraRun --project-dir /projects --script-dir /scripts

# Features:
# - Full GUI
# - Real-time analysis
# - Interactive scripting
# - Debugger integration
```

### 2. Headless Mode (Automation)
```bash
# Headless analysis
./analyzeHeadless /projects MyProject \
  -import /samples/binary.exe \
  -postScript batch_analyzer.py \
  -scriptPath /scripts \
  -deleteProject

# Features:
# - No GUI required
# - CI/CD integration
# - Batch processing
# - API-driven
```

### 3. Container Mode (Service)
```yaml
# Docker deployment for headless analysis service
ghidrago:
  image: catalytic/ghidrago:latest
  volumes:
    - ./samples:/samples:ro
    - ./output:/output
    - ./scripts:/scripts:ro
  command: >
    analyzeHeadless /projects AutoProject
    -import /samples
    -postScript batch_analyzer.py
    -recursive
```

---

## Architecture

### Type Caching System

GhidraGo implements intelligent type caching for Go binaries:

```
┌─────────────────────────────────────────┐
│           Binary Analysis               │
├─────────────────────────────────────────┤
│                                         │
│  ┌──────────┐     ┌──────────────────┐  │
│  │  Parser  │────▶│  Type Extractor  │  │
│  └──────────┘     └────────┬─────────┘  │
│                            │            │
│                   ┌────────▼─────────┐  │
│                   │    Type Cache    │  │
│                   │  (LRU, 10K types)│  │
│                   └────────┬─────────┘  │
│                            │            │
│  ┌──────────┐     ┌────────▼─────────┐  │
│  │ Annotator│◀────│  Type Resolver   │  │
│  └──────────┘     └──────────────────┘  │
│                                         │
└─────────────────────────────────────────┘
```

### Analysis Pipeline

```
Input Binary
     │
     ▼
┌─────────────┐
│   Loader    │ ← GolangLoader for .go binaries
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Disassembly │ ← Ghidra's Sleigh processor
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Analysis   │ ← Control flow, data flow, xrefs
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Decompiler  │ ← Ghidra decompiler
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Scripts   │ ← Custom post-processing
└──────┬──────┘
       │
       ▼
   Output (JSON, XML, reports)
```

---

## Configuration

### Ghidra Configuration

```properties
# ghidra.properties
ghidra.user.dir=/home/ghidra/.ghidra
ghidra.cachedfilesystem.dir=/tmp/ghidra_cache
ghidra.max.heap.size=8G

# Extension paths
ghidra.extension.path=/extensions/GhidraGo
ghidra.extension.path=/extensions/Ghidrathon
```

### Script Configuration

```python
# scripts/config.py
ANALYSIS_CONFIG = {
    'timeout_seconds': 600,         # 10 min per binary
    'max_function_count': 100000,   # Skip huge binaries
    'enable_decompiler': True,
    'enable_xrefs': True,
    'output_format': 'json',        # json, xml, sarif
    'cache_results': True,
}
```

### Docker Configuration

```dockerfile
FROM eclipse-temurin:17-jre

# Install Ghidra
ENV GHIDRA_VERSION=11.4.2
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC.zip \
    && unzip ghidra_${GHIDRA_VERSION}_PUBLIC.zip \
    && rm ghidra_${GHIDRA_VERSION}_PUBLIC.zip

# Install Python (for Ghidrathon)
RUN apt-get update && apt-get install -y python3 python3-pip

# Install extensions
COPY extensions/ /extensions/

# Set up scripts
COPY scripts/ /scripts/

WORKDIR /ghidra
ENTRYPOINT ["./support/analyzeHeadless"]
```

---

## Supported Architectures

| Architecture | Status | Notes |
|--------------|--------|-------|
| x86 | ✅ Full | Primary target |
| x86_64 | ✅ Full | Primary target |
| ARM | ✅ Full | v7, v8, Thumb |
| ARM64 | ✅ Full | AArch64 |
| MIPS | ✅ Full | 32/64-bit |
| PowerPC | ✅ Full | 32/64-bit |
| RISC-V | ✅ Partial | rv32/rv64 |
| SPARC | ✅ Full | v9 |

---

## Performance

### Analysis Benchmarks

| Binary Size | Analysis Time | Memory |
|-------------|---------------|--------|
| 1 MB | 15 seconds | 2 GB |
| 10 MB | 2 minutes | 4 GB |
| 100 MB | 15 minutes | 8 GB |
| 1 GB | 2 hours | 32 GB |

### Type Cache Performance

| Metric | Value |
|--------|-------|
| Cache Hit Rate | 85%+ |
| Avg Lookup Time | 0.5ms |
| Max Cached Types | 10,000 |
| Memory Overhead | 50 MB |

---

## Integration Points

### API Integration

```python
# REST API for headless analysis
import requests

response = requests.post('http://ghidrago:8082/analyze', json={
    'binary_url': 'https://storage.example.com/sample.exe',
    'scripts': ['malware_analysis.py'],
    'output_format': 'json'
})

result = response.json()
# {
#   'status': 'completed',
#   'functions': 1234,
#   'strings': 567,
#   'imports': 89,
#   'report_url': 'https://storage.example.com/reports/abc123.json'
# }
```

### Catalytic Engine Integration

```python
# Submit binary for combined analysis
from catalytic import CatalyticClient

client = CatalyticClient()

# Binary analysis + lattice-based pattern matching
result = client.analyze_binary(
    binary_path='/samples/malware.exe',
    use_gpu=True,  # GPU-accelerated pattern matching
    patterns=['ransomware', 'c2_beaconing', 'persistence']
)
```

---

## Security Considerations

### Sandboxing
- Binaries analyzed in isolated containers
- No network access during analysis (optional)
- Read-only binary input
- Limited filesystem access

### Malware Handling
```yaml
# Docker security for malware analysis
ghidrago:
  security_opt:
    - no-new-privileges:true
  read_only: true
  tmpfs:
    - /tmp:size=1G
  networks:
    - isolated  # No external network
  cap_drop:
    - ALL
```

### Output Sanitization
- All output validated before storage
- No executable content in reports
- PII/secrets detection and redaction

---

## Related Documentation

- [Container Overview](container-overview.md)
- [GhidraGo Design](../ghidrago-design.md)
- [Ghidra Integration ADR](../10-adrs/013-ghidra-framework-integration.md)
- [Security Architecture](../05-cross-cutting-concerns/security-architecture.md)

---

**Last Updated**: November 2025
