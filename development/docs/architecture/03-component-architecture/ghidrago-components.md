# GhidraGo Toolkit - Component Architecture

## Overview
GhidraGo v2.2.0 wraps NSA Ghidra with REST APIs, type caching, and batch processing capabilities for automated binary analysis.

## Component Layers

### 1. REST API Layer

#### Analysis Controller
**Path**: `/api/v1/analysis`
```
POST /submit         - Submit binary for analysis
GET  /{job_id}       - Analysis status
GET  /{job_id}/result - Analysis results
POST /batch          - Submit multiple binaries
DELETE /{job_id}     - Cancel analysis
```

#### Script Controller
**Path**: `/api/v1/scripts`
```
GET  /               - List available scripts
POST /execute        - Run script on binary
POST /custom         - Execute custom Ghidra script
GET  /templates      - Script templates
```

#### Type Controller
**Path**: `/api/v1/types`
```
GET  /cache          - List cached types
GET  /cache/{hash}   - Get cached type by hash
POST /cache          - Store type
DELETE /cache/{hash} - Invalidate cached type
GET  /stats          - Cache statistics
```

### 2. Analysis Core

#### Headless Analyzer
**Responsibilities**:
- Non-GUI Ghidra analysis
- Architecture detection
- Full auto-analysis pipeline

**Analysis Pipeline**:
```
Binary → Import → Auto-Analysis → Decompilation → Export
         │            │                │            │
         ▼            ▼                ▼            ▼
   Format Detection  Disassembly   C Pseudocode  JSON/XML
                     Function ID
                     Data Type
                     References
```

**Key Methods**:
```java
public class HeadlessAnalyzer {
    public AnalysisResult analyze(byte[] binary, AnalysisOptions options);
    public void setProcessor(String processorName);
    public void enableAnalyzer(String analyzerName, boolean enable);
    public List<Function> getFunctions();
    public List<DataType> getDataTypes();
}
```

#### Decompiler
**Outputs**:
- C pseudocode per function
- Variable names and types
- Control flow structure
- Inlined comments

**Configuration**:
```java
DecompileOptions options = new DecompileOptions();
options.setMaxPayloadMBytes(64);
options.setMaxInstructions(100000);
options.setTimeout(120);  // seconds
```

#### Disassembler
**Outputs**:
- Assembly instructions
- Cross-references
- Symbol table
- String references

**Supported Formats**:
- PE (Windows executables)
- ELF (Linux/Unix)
- Mach-O (macOS/iOS)
- Raw binary (with manual base address)

### 3. Extension Components

#### Type Cache
**Purpose**: Persist decompiled types across analysis sessions for faster repeated analysis.

**Cache Structure**:
```
{
  "type_hash": "sha256(type_definition)",
  "type_name": "struct MyStruct",
  "type_category": "/project/headers",
  "definition": "...",
  "source_binary": "binary_sha256",
  "created_at": "2024-10-15T10:30:00Z",
  "hit_count": 42
}
```

**Key Methods**:
```java
public class TypeCache {
    public Optional<DataType> get(String typeHash);
    public void put(DataType type, String sourceHash);
    public void invalidate(String typeHash);
    public CacheStats getStats();
    public void prune(int maxAgeDays);
}
```

**Cache Strategy**:
- LRU eviction when cache exceeds 10,000 types
- Background persistence to disk every 5 minutes
- Cross-binary type matching by structural hash

#### Script Engine
**Supported Languages**:
- Ghidra Python (Jython 2.7)
- Java

**Script Categories**:
| Category | Purpose | Example |
|----------|---------|---------|
| Analysis | Enhanced analysis | Find crypto constants |
| Export | Data extraction | Dump strings |
| Patch | Binary modification | NOP instruction |
| Search | Pattern matching | Find vulnerabilities |

**Execution Environment**:
```java
public class ScriptEngine {
    public ScriptResult execute(String scriptPath, Program program);
    public ScriptResult executeInline(String scriptCode, Program program);
    public void setTimeout(int seconds);
    public void setScriptVariables(Map<String, Object> vars);
}
```

#### Batch Processor
**Purpose**: Parallel analysis of multiple binaries.

**Configuration**:
```yaml
batch:
  max_parallel_jobs: 4
  memory_per_job: 4GB
  timeout_per_binary: 600  # seconds
  retry_on_failure: true
  max_retries: 2
```

**Key Methods**:
```java
public class BatchProcessor {
    public BatchJob submit(List<byte[]> binaries, AnalysisOptions options);
    public BatchStatus getStatus(String batchId);
    public List<AnalysisResult> getResults(String batchId);
    public void cancel(String batchId);
}
```

### 4. Architecture Support

#### SLEIGH Processor
**Purpose**: Define processor instruction semantics.

**Supported Architectures** (30+):
- x86/x64 (Intel, AMD)
- ARM/ARM64 (including Thumb)
- MIPS (32/64)
- PowerPC
- RISC-V
- 6502, Z80, 68000 (retro)
- Many more...

#### P-Code Analyzer
**Purpose**: Intermediate representation for cross-architecture analysis.

**P-Code Operations**:
```
COPY, LOAD, STORE           - Data movement
INT_ADD, INT_SUB, INT_MULT  - Arithmetic
INT_AND, INT_OR, INT_XOR    - Bitwise
BRANCH, CBRANCH, CALL       - Control flow
RETURN                      - Function return
```

### 5. Output Components

#### Result Exporter
**Export Formats**:
| Format | Use Case | Size |
|--------|----------|------|
| JSON | API responses | Compact |
| XML | Ghidra-compatible | Verbose |
| FlatBuffer | Binary efficiency | Minimal |
| HTML | Human-readable | Report |

**Export Options**:
```java
ExportOptions options = new ExportOptions();
options.setIncludeFunctions(true);
options.setIncludeDataTypes(true);
options.setIncludeStrings(true);
options.setIncludeXrefs(true);
options.setDecompileAll(false);  // On-demand only
```

#### Project Manager
**Responsibilities**:
- Ghidra project file management
- Shared project support
- Version control integration

## Data Flow

```
                 ┌─────────────────┐
                 │  Binary Input   │
                 └────────┬────────┘
                          │
                 ┌────────▼────────┐
                 │ Format Detection│
                 └────────┬────────┘
                          │
                 ┌────────▼────────┐
                 │ SLEIGH Processor│ ◄── Architecture
                 └────────┬────────┘     Definition
                          │
         ┌────────────────┼────────────────┐
         │                │                │
    ┌────▼────┐    ┌──────▼──────┐   ┌────▼────┐
    │Disassem │    │ Auto-Analyze│   │  Import │
    └────┬────┘    └──────┬──────┘   └────┬────┘
         │                │                │
         └────────────────┼────────────────┘
                          │
                 ┌────────▼────────┐
                 │   Decompiler    │◄───┐
                 └────────┬────────┘    │
                          │             │
                 ┌────────▼────────┐    │
                 │   Type Cache    │────┘
                 └────────┬────────┘
                          │
                 ┌────────▼────────┐
                 │ Result Exporter │
                 └─────────────────┘
```

## Performance Metrics

| Metric | Value |
|--------|-------|
| Analysis throughput | 50+ binaries/hour |
| Type cache hit rate | 85% |
| Average decompile time | 2-5 seconds/function |
| Memory per instance | 4-8 GB |
| Batch parallelism | 4 concurrent jobs |

## Security Considerations

| Risk | Mitigation |
|------|------------|
| Malicious binary execution | Analysis in isolated container |
| Resource exhaustion | Per-job memory/time limits |
| Type cache poisoning | Hash verification |
| Script injection | Sandboxed execution environment |

---
**Last Updated**: 2024-10-15
