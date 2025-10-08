# GhidraGo - Golang Binary Analyzer Plugin
## Technical Specification v1.0

**Author**: Catalytic Computing / Claude Code AI
**Date**: January 10, 2025
**Target Ghidra Version**: 11.4.2+
**Estimated Implementation Time**: 2-3 days

---

## Executive Summary

GhidraGo is a comprehensive Ghidra plugin for analyzing Go (Golang) binaries, addressing the unique challenges of reverse engineering statically-linked, stripped Go executables. Based on extensive research of existing tools (gotools, GolangAnalyzerExtension, golang-ghidra) and CUJO AI's definitive technical analysis, this plugin provides automated symbol recovery, type extraction, and function signature reconstruction.

---

## Problem Statement

### Why Go Binaries Are Hard to Reverse Engineer

1. **Statically Linked**: All runtime and standard library code embedded (10-20 MB binaries)
2. **Stripped by Default**: Release builds remove debugging symbols
3. **Custom Calling Convention**: Not C calling convention, confuses decompilers
4. **Unique String Structure**: `{pointer, length}` tuple instead of null-terminated
5. **Obfuscated Function Names**: Mangled package paths (`main_main_func1`)
6. **Runtime Complexity**: Goroutines, channels, GC structures
7. **Version Fragmentation**: Go 1.5-1.23 have incompatible runtime structures

### Go Malware Trend

- **Ransomware**: WastedLocker, Babuk, REvil variants
- **Botnets**: Mirai variants, XMRIG miners
- **APT Tools**: APT41, Lazarus Group use Go
- **Growing 300%**: Go malware samples increased 3x in 2023-2024

---

## Research Findings

### Existing Solutions Analysis

| Plugin | Version Support | Features | Limitations |
|--------|----------------|----------|-------------|
| **gotools** (felberj) | Limited | Function names, args/returns | Linux x86_64 only, early stage |
| **GolangAnalyzerExtension** | Go 1.6-1.23 | Comprehensive analysis | Complex, heavy |
| **golang-ghidra** (cyberkaida) | Unknown | Function identification | Unknown scope |

### Key Technical References

1. **CUJO AI Blog Series** (2023) - Most comprehensive:
   - Part 1: Function name recovery, string extraction
   - Part 2: Type extraction, PE files, version handling

2. **Google Cloud Blog** (2022) - Moduledata internals:
   - GoReSym tool architecture
   - Version compatibility approaches

3. **Go Runtime Source** - Ground truth:
   - `runtime/symtab.go` - pclntab structure
   - `runtime/type.go` - type system
   - `runtime/runtime2.go` - moduledata definition

---

## Core Go Binary Structures

### 1. **PCLNTAB** (Program Counter Line Table)

**Purpose**: Maps virtual addresses to function names and source locations

**Location**:
- ELF/Mach-O: `.gopclntab` section
- PE: Must search via symbol table or magic bytes

**Structure** (varies by Go version):

```go
// Go 1.2
type pcHeader struct {
    magic uint32  // 0xfffffffb
    pad1  uint8
    pad2  uint8
    minLC uint8
    ptrsize uint8
}

// Go 1.16+
type pcHeader struct {
    magic      uint32  // 0xfffffff0 or 0xfffffff1
    pad1       uint8
    pad2       uint8
    minLC      uint8
    ptrsize    uint8
    nfunc      int     // Number of functions
    nfiles     uint    // Number of file names
    funcnameOffset uintptr
    cuOffset   uintptr
    filetabOffset uintptr
    pctabOffset uintptr
    pclnOffset uintptr
}
```

**Magic Numbers by Version**:
- Go 1.2-1.15: `0xfffffffb` or `0xfffffffa`
- Go 1.16-1.17: `0xfffffff0`
- Go 1.18+: `0xfffffff1`

### 2. **MODULEDATA**

**Purpose**: Runtime metadata table containing pclntab pointer, typelinks, and module info

**Location**:
- ELF: `.noptrdata` section
- PE: `.text` or `.data` section (search for pclntab pointer)

**Key Fields**:
```go
type moduledata struct {
    pclntab    []byte    // Pointer to pclntab
    ftab       []functab // Function table
    filetab    []uint32  // File name table
    findfunctab uintptr   // Find function table
    minpc      uintptr    // Minimum PC value
    maxpc      uintptr    // Maximum PC value
    text       uintptr    // .text section start
    etext      uintptr    // .text section end
    noptrdata  uintptr    // .noptrdata start
    enoptrdata uintptr    // .noptrdata end
    data       uintptr    // .data start
    edata      uintptr    // .data end
    bss        uintptr    // .bss start
    ebss       uintptr    // .bss end
    noptrbss   uintptr    // .noptrbss start
    enoptrbss  uintptr    // .noptrbss end
    types      uintptr    // Type information start
    etypes     uintptr    // Type information end
    typelinks  []int32    // Offsets to type descriptors
    // ... more fields (version-specific)
}
```

**Detection Method**:
1. Find pclntab via magic number
2. Linear scan for structure containing pclntab address
3. Verify moduledata fields (minpc < maxpc, text < etext, etc.)
4. Alternative: Disassemble `runtime.moduledataverify1`

### 3. **TYPELINKS** (Type Information Array)

**Purpose**: Array of offsets to type descriptors for reflection and GC

**Structure**:
```go
// Array of int32 offsets from types section base
typelinks []int32
```

**Type Descriptor** (rtype):
```go
type _type struct {
    size       uintptr
    ptrdata    uintptr
    hash       uint32
    tflag      tflag
    align      uint8
    fieldAlign uint8
    kind       uint8
    equal      func(unsafe.Pointer, unsafe.Pointer) bool
    gcdata     *byte
    str        nameOff  // Offset to name
    ptrToThis  typeOff  // Offset to *T type
}
```

**Type Kinds**:
```go
const (
    kindBool = 1
    kindInt = 2
    kindInt8 = 3
    kindInt16 = 4
    kindInt32 = 5
    kindInt64 = 6
    kindUint = 7
    kindUint8 = 8
    kindUint16 = 9
    kindUint32 = 10
    kindUint64 = 11
    kindUintptr = 12
    kindFloat32 = 13
    kindFloat64 = 14
    kindComplex64 = 15
    kindComplex128 = 16
    kindArray = 17
    kindChan = 18
    kindFunc = 19
    kindInterface = 20
    kindMap = 21
    kindPtr = 22
    kindSlice = 23
    kindString = 24
    kindStruct = 25
    kindUnsafePointer = 26
)
```

### 4. **GO STRINGS**

**Structure** (not null-terminated):
```go
type stringStruct struct {
    str unsafe.Pointer  // Pointer to data
    len int             // Length in bytes
}
```

**Static Strings**: Stored in `.rodata` with pointer/length pairs
**Dynamic Strings**: Created via runtime calls with specific instruction patterns

---

## GhidraGo Architecture

### Plugin Structure

```
GhidraGo/
├── build.gradle
├── extension.properties
├── Module.manifest
├── README.md
├── src/main/
│   ├── java/ghidrago/
│   │   ├── GhidraGoPlugin.java           # Main plugin entry
│   │   ├── GhidraGoProvider.java         # UI provider
│   │   ├── analyzers/
│   │   │   ├── GoRuntimeAnalyzer.java    # Auto-analyzer
│   │   │   └── GoFunctionAnalyzer.java   # Function analyzer
│   │   ├── parsers/
│   │   │   ├── PclntabParser.java        # Parse pclntab
│   │   │   ├── ModuledataParser.java     # Parse moduledata
│   │   │   ├── TypelinksParser.java      # Parse typelinks
│   │   │   └── StringParser.java         # Parse Go strings
│   │   ├── models/
│   │   │   ├── GoFunction.java           # Function model
│   │   │   ├── GoType.java               # Type model
│   │   │   └── GoString.java             # String model
│   │   ├── services/
│   │   │   ├── SymbolRecoveryService.java  # Symbol recovery
│   │   │   ├── TypeExtractionService.java  # Type extraction
│   │   │   └── SignatureService.java       # Function signatures
│   │   ├── utils/
│   │   │   ├── GoVersionDetector.java    # Detect Go version
│   │   │   ├── BinarySearchUtils.java    # Binary search helpers
│   │   │   └── StructureValidator.java   # Validate structures
│   │   └── ui/
│   │       └── GoAnalysisPanel.java      # Analysis results panel
│   └── help/help/
│       ├── TOC_Source.xml
│       └── topics/ghidrago/
│           └── help.html
├── ghidra_scripts/
│   ├── RecoverGoFunctions.py             # Script for function recovery
│   ├── ExtractGoTypes.py                 # Script for type extraction
│   └── FindGoStrings.py                  # Script for string extraction
└── data/
    └── go_stdlib_signatures.json         # Known stdlib function signatures
```

---

## Feature Implementation Plan

### Phase 1: Core Infrastructure (Day 1)

#### 1.1 Go Version Detection
**Priority**: CRITICAL
**Complexity**: Low

**Implementation**:
```java
public class GoVersionDetector {
    public enum GoVersion {
        GO_1_2,  GO_1_16, GO_1_18, GO_1_20, GO_1_23, UNKNOWN
    }

    public GoVersion detectVersion(Program program) {
        // 1. Check buildinfo section (Go 1.18+)
        // 2. Check pclntab magic number
        // 3. Check moduledata structure layout
        // 4. Heuristic analysis of runtime functions
    }
}
```

**Success Criteria**:
- Correctly identify Go versions 1.2, 1.16, 1.18, 1.20+
- Fallback to heuristic detection for unknown versions

#### 1.2 PCLNTAB Parser
**Priority**: CRITICAL
**Complexity**: Medium

**Implementation**:
```java
public class PclntabParser {
    private static final int MAGIC_12 = 0xfffffffb;
    private static final int MAGIC_116 = 0xfffffff0;
    private static final int MAGIC_118 = 0xfffffff1;

    public PclntabStructure parse(Program program, GoVersion version) {
        // 1. Locate pclntab via section name or magic scan
        // 2. Parse header based on version
        // 3. Extract function table (ftab)
        // 4. Build funcname → address mapping
    }

    private Address findPclntab(Program program) {
        // ELF: Look for .gopclntab section
        // PE: Search for magic bytes in .rdata or .text
    }
}
```

**Success Criteria**:
- Locate pclntab in ELF and PE binaries
- Parse function names for all Go versions
- Handle stripped and non-stripped binaries

#### 1.3 Moduledata Parser
**Priority**: CRITICAL
**Complexity**: High

**Implementation**:
```java
public class ModuledataParser {
    public ModuledataStructure parse(Program program,
                                      Address pclntabAddr,
                                      GoVersion version) {
        // 1. Scan for pclntab pointer reference
        // 2. Validate candidate moduledata structures
        // 3. Extract typelinks array
        // 4. Parse section boundaries (text, data, bss)
    }

    private boolean validateModuledata(Program program,
                                        Address candidate,
                                        Address pclntabAddr) {
        // Verify:
        // - First pointer == pclntab address
        // - minpc < maxpc
        // - text < etext
        // - Reasonable section sizes
    }
}
```

**Success Criteria**:
- Locate moduledata in ELF and PE files
- Extract typelinks array successfully
- Handle version-specific structure layouts

---

### Phase 2: Symbol Recovery (Day 1-2)

#### 2.1 Function Name Recovery
**Priority**: HIGH
**Complexity**: Medium

**Implementation**:
```java
public class SymbolRecoveryService {
    public void recoverFunctionNames(Program program,
                                      PclntabStructure pclntab) {
        FunctionManager funcMgr = program.getFunctionManager();

        for (FunctionEntry entry : pclntab.getFunctionTable()) {
            Address addr = entry.getAddress();
            String name = entry.getName();

            // Create or rename function
            Function func = funcMgr.getFunctionAt(addr);
            if (func == null) {
                func = funcMgr.createFunction(name, addr,
                    new AddressSet(addr), SourceType.ANALYSIS);
            } else {
                func.setName(name, SourceType.ANALYSIS);
            }

            // Add namespace (package)
            String packageName = extractPackage(name);
            if (packageName != null) {
                Namespace ns = createNamespace(program, packageName);
                func.setParentNamespace(ns);
            }
        }
    }
}
```

**Success Criteria**:
- Recover 90%+ of function names
- Correctly parse package namespaces
- Handle mangled names (main_main_func1)

#### 2.2 Function Signature Reconstruction
**Priority**: HIGH
**Complexity**: High

**Implementation**:
```java
public class SignatureService {
    public void reconstructSignatures(Program program,
                                       TypelinksParser typeParser) {
        FunctionManager funcMgr = program.getFunctionManager();

        for (Function func : funcMgr.getFunctions(true)) {
            // 1. Find function type in typelinks
            GoType funcType = typeParser.findFunctionType(func.getName());
            if (funcType == null) continue;

            // 2. Extract parameter types
            List<DataType> params = funcType.getParameterTypes();

            // 3. Extract return types (Go supports multiple returns)
            List<DataType> returns = funcType.getReturnTypes();

            // 4. Create FunctionSignature
            FunctionSignature sig = createSignature(func, params, returns);
            func.setSignature(sig, SourceType.ANALYSIS);
        }
    }
}
```

**Success Criteria**:
- Reconstruct signatures for 70%+ of functions
- Handle multi-return values
- Support interface and struct types

---

### Phase 3: Type Extraction (Day 2)

#### 3.1 Typelinks Parser
**Priority**: MEDIUM
**Complexity**: High

**Implementation**:
```java
public class TypelinksParser {
    public Map<String, GoType> parseTypes(Program program,
                                          ModuledataStructure moduledata) {
        Map<String, GoType> types = new HashMap<>();

        Address typesBase = moduledata.getTypesStart();
        int[] typelinks = moduledata.getTypelinks();

        for (int offset : typelinks) {
            Address typeAddr = typesBase.add(offset);
            GoType type = parseType(program, typeAddr);
            types.put(type.getName(), type);
        }

        return types;
    }

    private GoType parseType(Program program, Address typeAddr) {
        // 1. Read _type structure
        // 2. Extract kind, name, size
        // 3. Recursively parse nested types
        // 4. Handle struct fields, interface methods, etc.
    }
}
```

**Success Criteria**:
- Extract all defined types from typelinks
- Parse struct field information
- Handle interface type definitions

#### 3.2 Type Application
**Priority**: MEDIUM
**Complexity**: Medium

**Implementation**:
```java
public class TypeExtractionService {
    public void applyTypes(Program program,
                          Map<String, GoType> types) {
        DataTypeManager dtm = program.getDataTypeManager();

        for (GoType goType : types.values()) {
            // Convert GoType to Ghidra DataType
            DataType ghidraType = convertToGhidraType(goType, dtm);

            // Add to data type manager
            dtm.addDataType(ghidraType, DataTypeConflictHandler.DEFAULT_HANDLER);

            // Apply to variables if possible
            applyTypeToVariables(program, goType, ghidraType);
        }
    }
}
```

**Success Criteria**:
- Create Ghidra data types for Go types
- Apply types to global variables
- Support custom struct definitions

---

### Phase 4: String Recovery (Day 2-3)

#### 4.1 Static String Extraction
**Priority**: HIGH
**Complexity**: Low

**Implementation**:
```java
public class StringParser {
    public List<GoString> findStaticStrings(Program program) {
        List<GoString> strings = new ArrayList<>();

        // Search .rodata section for string structures
        MemoryBlock rodata = findRODataSection(program);
        if (rodata == null) return strings;

        Address addr = rodata.getStart();
        Address end = rodata.getEnd();

        while (addr.compareTo(end) < 0) {
            // Look for string structure pattern:
            // [8-byte pointer][8-byte length]
            long ptrValue = readPointer(program, addr);
            long lenValue = readPointer(program, addr.add(8));

            if (isValidStringPointer(program, ptrValue, lenValue)) {
                GoString str = extractString(program, ptrValue, lenValue);
                strings.add(str);

                // Create data and label
                createStringData(program, addr, str);
            }

            addr = addr.add(1); // Move forward for next search
        }

        return strings;
    }
}
```

**Success Criteria**:
- Find 80%+ of static strings
- Minimize false positives
- Create proper string data types

#### 4.2 Dynamic String Detection
**Priority**: MEDIUM
**Complexity**: Medium

**Implementation**:
```java
public class DynamicStringDetector {
    // Architecture-specific instruction patterns
    private static final byte[] X86_64_PATTERN = {
        // mov rax, [string_ptr]
        // mov rbx, [string_len]
    };

    public List<GoString> findDynamicStrings(Program program) {
        // 1. Search for runtime.concatstrings calls
        // 2. Identify string allocation patterns
        // 3. Trace back to source data
        // 4. Create references
    }
}
```

**Success Criteria**:
- Detect common dynamic string patterns
- Support x86_64, ARM64
- Reduce false positive rate

---

### Phase 5: UI & Integration (Day 3)

#### 5.1 Analysis Panel
**Priority**: MEDIUM
**Complexity**: Low

**Implementation**:
```java
public class GoAnalysisPanel extends JPanel {
    private JTextArea resultsArea;
    private JButton analyzeButton;
    private JButton exportButton;

    public void displayResults(AnalysisResults results) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Go Binary Analysis Results ===\n\n");
        sb.append("Go Version: ").append(results.getGoVersion()).append("\n");
        sb.append("Functions Recovered: ").append(results.getFunctionCount()).append("\n");
        sb.append("Types Extracted: ").append(results.getTypeCount()).append("\n");
        sb.append("Strings Found: ").append(results.getStringCount()).append("\n");

        resultsArea.setText(sb.toString());
    }
}
```

#### 5.2 Auto-Analyzer Integration
**Priority**: HIGH
**Complexity**: Low

**Implementation**:
```java
@AutoAnalyzer
public class GoRuntimeAnalyzer extends AbstractAnalyzer {
    @Override
    public boolean canAnalyze(Program program) {
        // Detect if binary is Go
        return detectGoBinary(program);
    }

    @Override
    public boolean analyze(Program program,
                          AddressSetView set,
                          TaskMonitor monitor) {
        // 1. Detect Go version
        // 2. Parse pclntab
        // 3. Parse moduledata
        // 4. Recover symbols
        // 5. Extract types
        // 6. Find strings

        return true;
    }
}
```

**Success Criteria**:
- Auto-detect Go binaries
- Run automatically on import
- Provide progress feedback

---

## Implementation Timeline

### Day 1: Core Infrastructure (8 hours)
- ✅ Project setup (build.gradle, extension.properties)
- ✅ Go version detection
- ✅ PCLNTAB parser (basic version)
- ✅ Moduledata parser (ELF only)
- ✅ Basic function name recovery

### Day 2: Symbol & Type Recovery (8 hours)
- ✅ Complete moduledata parser (PE support)
- ✅ Function signature reconstruction
- ✅ Typelinks parser
- ✅ Type extraction service
- ✅ Static string recovery

### Day 3: Polish & Integration (6-8 hours)
- ✅ Dynamic string detection
- ✅ UI panel
- ✅ Auto-analyzer integration
- ✅ Documentation (README, help.html)
- ✅ Testing with sample binaries
- ✅ Known stdlib signature database

**Total**: 22-24 hours (~3 days)

---

## Testing Strategy

### Test Binaries

1. **Simple Hello World** (Go 1.20)
   - Stripped and non-stripped
   - Linux ELF, Windows PE

2. **Complex Application** (Go 1.23)
   - Multiple packages
   - Interfaces and structs
   - Concurrent goroutines

3. **Real Malware Sample**
   - Mirai variant (Go-based botnet)
   - Stripped binary
   - Obfuscated strings

### Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Function Recovery Rate | 90%+ | Functions with correct names / total functions |
| Type Extraction Rate | 70%+ | Types extracted / total types in typelinks |
| String Recovery Rate | 80%+ | Strings found / strings in binary |
| False Positive Rate | <5% | Invalid strings marked / total strings marked |
| Version Detection Accuracy | 95%+ | Correct version detected / test binaries |

---

## Technology Stack

- **Language**: Java 17+
- **Framework**: Ghidra Plugin API
- **Build**: Gradle 7.x
- **Dependencies**: None (uses Ghidra core APIs)
- **Testing**: Manual testing with sample binaries

---

## Key Differentiators from Existing Plugins

### vs. gotools (felberj):
- ✅ **Cross-platform**: Support Linux (ELF), Windows (PE), macOS (Mach-O)
- ✅ **Version support**: Go 1.2 through 1.23
- ✅ **Type extraction**: Full type information, not just names
- ✅ **UI integration**: Visual results panel

### vs. GolangAnalyzerExtension:
- ✅ **Simpler codebase**: Focused feature set, easier to maintain
- ✅ **Better documentation**: Comprehensive help system
- ✅ **Integration**: Works with GhidraGraph for call graph visualization

### vs. golang-ghidra:
- ✅ **Signature reconstruction**: Multi-return type support
- ✅ **String recovery**: Both static and dynamic strings
- ✅ **Stdlib database**: Known function signatures

---

## Future Enhancements (v1.1+)

1. **Interface Analysis**
   - Identify interface implementations
   - Visualize interface relationships

2. **Goroutine Detection**
   - Locate goroutine creation
   - Map goroutine call chains

3. **Channel Analysis**
   - Identify channel operations
   - Track data flow through channels

4. **Standard Library Matching**
   - FLIRT-style signature matching
   - Auto-label stdlib functions

5. **Decompiler Enhancement**
   - Custom calling convention
   - String literal fixes
   - Stack frame analysis

6. **Export Functionality**
   - Export recovered symbols to JSON
   - Import into other tools (IDA, Binary Ninja)

---

## References

1. CUJO AI Blog Series (2023):
   - https://cujo.com/blog/reverse-engineering-go-binaries-with-ghidra/
   - https://cujo.com/blog/reverse-engineering-go-binaries-with-ghidra-part-2-type-extraction-windows-pe-files-and-golang-versions/

2. Google Cloud Blog (2022):
   - https://cloud.google.com/blog/topics/threat-intelligence/golang-internals-symbol-recovery/

3. Go Runtime Source:
   - https://github.com/golang/go/blob/master/src/runtime/symtab.go
   - https://github.com/golang/go/blob/master/src/runtime/type.go

4. Existing Plugins:
   - https://github.com/felberj/gotools
   - https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension
   - https://github.com/cyberkaida/golang-ghidra

---

**Specification Status**: ✅ COMPLETE
**Ready for Implementation**: YES
**Next Step**: Begin Day 1 implementation (project setup + core parsers)
