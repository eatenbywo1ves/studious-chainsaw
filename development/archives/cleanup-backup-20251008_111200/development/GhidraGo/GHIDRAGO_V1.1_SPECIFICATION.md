# GhidraGo v1.1 - Enhancement Specification
**Version**: 1.1.0
**Target Release**: Q1 2026
**Status**: Planning Phase
**Build Upon**: 1.0.0-MVP (Function Recovery)

---

## Executive Summary

GhidraGo v1.1 builds upon the successful MVP by adding **type extraction**, **auto-analyzer integration**, and **multi-platform support**. These enhancements transform GhidraGo from a function name recovery tool into a comprehensive Go binary analysis framework.

### Key Objectives
1. **Type Extraction** - Recover struct, interface, and custom type definitions
2. **Auto-Analyzer** - Automatic execution on Go binary import
3. **Multi-Platform** - Support PE (Windows) and Mach-O (macOS) binaries
4. **Enhanced UI** - Results panel with structured data visualization

### Success Metrics
- Type recovery rate: 80%+ for Go 1.16+
- Auto-analyzer integration: Zero manual steps
- Platform support: ELF, PE, Mach-O
- User experience: One-click analysis

---

## Feature Priorities

### Priority 1: Type Information Extraction 🔥
**Complexity**: High | **Value**: High | **Estimated**: 2-3 weeks

#### What & Why
Extract type metadata (structs, interfaces, arrays, slices) from the `typelinks` array and `moduledata` structure. This is the **highest-value enhancement** because it enables:
- Proper variable typing in decompiler
- Struct field identification
- Interface method resolution
- Better understanding of data structures

#### Technical Approach

**Phase 1: Moduledata Location**
- ELF: Read from `.noptrdata` or `.data` section
- PE: Scan memory for moduledata signature using pclntab reference
- Mach-O: Similar to PE, scan `__noptrdata` section
- Validation: Check magic fields and version consistency

**Phase 2: Typelinks Parsing**
```python
class TypelinksParser:
    """Parse typelinks array from moduledata"""

    def __init__(self, program, moduledata_addr):
        self.program = program
        self.moduledata_addr = moduledata_addr
        self.types_base = None
        self.etypes_end = None
        self.typelinks = []

    def parse(self):
        # Read moduledata structure
        # Extract types/etypes range
        # Read typelinks slice (offset, length)
        # Parse each typelink as 32-bit offset
        pass

    def resolve_type(self, offset):
        # type_addr = types_base + offset
        # Read rtype structure
        # Extract kind, name, size
        # Handle type-specific structures
        pass
```

**Phase 3: rtype Structure Parsing**
```python
class RtypeParser:
    """Parse Go runtime type (rtype) structure"""

    KINDS = {
        1: 'Bool',
        2: 'Int',
        3: 'Int8',
        # ... 26 total kinds
        25: 'Struct',
        26: 'Interface'
    }

    def parse_rtype(self, addr, go_version):
        # Version-specific structure layout
        if go_version >= "1.18":
            return self._parse_rtype_118(addr)
        elif go_version >= "1.16":
            return self._parse_rtype_116(addr)
        else:
            return self._parse_rtype_legacy(addr)

    def parse_struct_type(self, struct_type_addr):
        # structType embeds rtype
        # Read fields array
        # For each field: name, offset, type, tag
        pass
```

**Phase 4: Ghidra Type Application**
```python
class TypeRecoveryService:
    """Apply recovered types to Ghidra program"""

    def create_struct(self, type_info):
        # Create Ghidra Structure
        # Add fields with proper types and offsets
        # Set in DataTypeManager
        pass

    def create_interface(self, type_info):
        # Create Ghidra Interface (via struct)
        # Add method pointers
        pass

    def apply_types_to_functions(self, type_map):
        # Match function parameters to types
        # Update return types
        # Set local variable types
        pass
```

#### Implementation Milestones

| Milestone | Description | Estimated Time |
|-----------|-------------|----------------|
| M1: Moduledata Scanner | Locate moduledata in ELF/PE/Mach-O | 3 days |
| M2: Typelinks Parser | Parse typelinks array + rtype basics | 4 days |
| M3: Struct Type Parser | Full struct field extraction | 3 days |
| M4: Interface Parser | Interface method table recovery | 2 days |
| M5: Type Application | Apply to Ghidra DataTypeManager | 3 days |
| M6: Testing & Refinement | Multi-version compatibility | 3 days |

**Total Estimated**: 18 days (~3 weeks)

#### Expected Output

**Before Type Extraction**:
```c
undefined8 FUN_00401200(longlong param_1, int param_2) {
    longlong lVar1;
    undefined8 *puVar2;

    puVar2 = (undefined8 *)(param_1 + 8);
    lVar1 = *(longlong *)(param_1 + 16);
    // ...
}
```

**After Type Extraction**:
```c
User main.processUser(User *user, int flags) {
    string name;
    int *age_ptr;

    name = user->Name;
    age_ptr = &user->Age;
    // ...
}
```

---

### Priority 2: Auto-Analyzer Integration ⚡
**Complexity**: Medium | **Value**: High | **Estimated**: 1 week

#### What & Why
Wrap the Python script in a Java-based Ghidra analyzer that runs automatically when Go binaries are imported. This provides **zero-click analysis** for users.

#### Technical Approach

**Java Analyzer Wrapper**:
```java
package ghidrago.analyzers;

import ghidra.app.services.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GoFunctionRecoveryAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "Go Function Recovery";
    private static final String DESCRIPTION =
        "Automatically recovers function names from Go binaries via PCLNTAB parsing";

    public GoFunctionRecoveryAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        // Check if binary is Go-compiled
        return GoDetector.isGoBinary(program);
    }

    @Override
    public boolean added(Program program, AddressSet set,
                        TaskMonitor monitor, MessageLog log)
                        throws CancelledException {

        monitor.setMessage("GhidraGo: Detecting Go version...");

        // Call Python script via Ghidrathon
        try {
            PythonInterpreter interp = new PythonInterpreter();
            interp.set("currentProgram", program);
            interp.set("monitor", monitor);

            String scriptPath = getScriptPath("RecoverGoFunctions.py");
            interp.execfile(scriptPath);

            monitor.setMessage("GhidraGo: Function recovery complete");
            return true;

        } catch (Exception e) {
            log.appendException(e);
            return false;
        }
    }
}
```

**Analyzer Options Panel**:
```java
public class GoAnalyzerOptions {
    private boolean enableTypeExtraction = true;
    private boolean enableStringRecovery = false;
    private boolean verboseLogging = false;
    private int maxFunctionsToProcess = 10000;

    public void registerOptions(Options options, Program program) {
        options.registerOption("Enable Type Extraction",
            enableTypeExtraction, null,
            "Extract type information from typelinks");

        options.registerOption("Enable String Recovery",
            enableStringRecovery, null,
            "Recover Go string constants");

        // ... more options
    }
}
```

#### Integration Points
1. **Analyzer Registration**: `Extension.properties` + `AnalyzerExtensionPoint`
2. **Python Bridge**: Use Ghidrathon or direct `ProcessBuilder` for script execution
3. **Progress Reporting**: `TaskMonitor` for function count updates
4. **Error Handling**: `MessageLog` for detailed error reporting

#### Testing Strategy
- Test with auto-analysis enabled (default)
- Test with auto-analysis disabled
- Verify priority ordering (runs after basic function analysis)
- Test with corrupted/obfuscated binaries (graceful failure)

---

### Priority 3: PE Binary Support (Windows) 🪟
**Complexity**: Medium | **Value**: High | **Estimated**: 1 week

#### What & Why
Extend support to Windows PE executables, which represent ~25% of Go binaries in the wild. Critical for malware analysis (ransomware, info-stealers).

#### Technical Challenges

**Challenge 1: No Named Sections**
- ELF has `.gopclntab`, `.typelinks`, `.rodata`
- PE only has `.text`, `.data`, `.rdata` (generic names)
- **Solution**: Scan for magic numbers and validate structures

**Challenge 2: Moduledata Location**
```python
class ModuledataScannerPE:
    """Locate moduledata in PE binaries"""

    def scan(self):
        # Strategy 1: Search near pclntab reference
        pclntab_refs = self.find_pclntab_references()
        for ref in pclntab_refs:
            candidate = self.scan_nearby(ref, radius=0x10000)
            if self.validate_moduledata(candidate):
                return candidate

        # Strategy 2: Signature-based scan
        # moduledata has predictable field patterns
        signature = self.build_moduledata_signature()
        return self.scan_for_signature(signature)

    def validate_moduledata(self, addr):
        # Check:
        # - pclntab pointer is valid
        # - types/etypes range makes sense
        # - typelinks count is reasonable (1-100000)
        pass
```

**Challenge 3: String Table Location**
- In ELF: strings in `.rodata`
- In PE: strings scattered across `.rdata`, `.data`
- **Solution**: Use name offsets from typelinks to locate string regions

#### Implementation Approach

1. **Extend GoVersionDetector**:
   ```python
   def detect_pe(self):
       # Check DOS header
       # Check PE header
       # Scan for .gopclntab signature
       pass
   ```

2. **PE-Specific PCLNTAB Parser**:
   - Handle image base relocation
   - Account for ASLR (Address Space Layout Randomization)
   - Parse import/export tables for Go runtime symbols

3. **Testing Matrix**:
   - Windows Go 1.16, 1.18, 1.20, 1.23
   - 32-bit and 64-bit
   - Stripped vs unstripped
   - With/without ASLR

---

### Priority 4: Mach-O Binary Support (macOS) 🍎
**Complexity**: Medium | **Value**: Medium | **Estimated**: 5 days

#### What & Why
Support macOS Go binaries for complete platform coverage. Less common than ELF/PE but important for cross-platform malware and legitimate macOS Go applications.

#### Technical Approach

**Mach-O Structure Parsing**:
```python
class MachOGoParser:
    """Parse Go structures from Mach-O binaries"""

    def locate_gopclntab(self):
        # Search __DATA.__gopclntab segment
        # Or __TEXT.__gopclntab in older versions
        # Fall back to signature scan
        pass

    def locate_typelinks(self):
        # __DATA.__typelinks segment
        # Or embedded in __DATA.__noptrdata
        pass
```

**Key Differences from ELF**:
- Segment-based (not section-based)
- Different virtual address mapping
- FAT binaries (multi-architecture) support needed

---

### Priority 5: Results Visualization Panel 📊
**Complexity**: Medium | **Value**: Medium | **Estimated**: 1 week

#### What & Why
Create a dedicated Ghidra panel to display recovered symbols, types, and statistics in an organized manner. Enhances usability beyond console output.

#### UI Design

**GhidraGo Results Panel** (Java Swing):
```
┌─ GhidraGo Analysis Results ─────────────────────────┐
│                                                      │
│ ┌─ Summary ─────────────────────────────────────┐   │
│ │ Go Version: 1.20.3                            │   │
│ │ Functions Recovered: 2,341 / 2,400 (97%)      │   │
│ │ Types Recovered: 1,234 / 1,500 (82%)          │   │
│ │ Analysis Time: 23 seconds                     │   │
│ └───────────────────────────────────────────────┘   │
│                                                      │
│ ┌─ Recovered Functions (Tab 1) ────────────────┐    │
│ │ ☐ Filter: [_____________] 🔍                 │    │
│ │                                               │    │
│ │ Address     | Name                | Source    │    │
│ │ ─────────────────────────────────────────────│    │
│ │ 00401000    | main.main          | main.go:15│    │
│ │ 00401100    | main.processUser   | main.go:42│    │
│ │ 00402000    | fmt.Printf         | stdlib    │    │
│ │ 00403000    | runtime.newproc    | runtime   │    │
│ │ ...         | ...                 | ...       │    │
│ └───────────────────────────────────────────────┘   │
│                                                      │
│ ┌─ Recovered Types (Tab 2) ─────────────────────┐   │
│ │ struct User {                                  │   │
│ │   +0x00  int64   ID                           │   │
│ │   +0x08  string  Name                         │   │
│ │   +0x18  int     Age                          │   │
│ │   +0x1c  bool    Active                       │   │
│ │ }                                              │   │
│ │                                                │   │
│ │ interface Handler {                            │   │
│ │   Handle(request *Request) Response           │   │
│ │ }                                              │   │
│ └────────────────────────────────────────────────┘  │
│                                                      │
│ [Export Results] [Re-run Analysis] [Close]          │
└──────────────────────────────────────────────────────┘
```

**Implementation**:
```java
public class GhidraGoResultsPanel extends JPanel {
    private JTable functionsTable;
    private JTextArea typesArea;
    private GhidraGoResults results;

    public GhidraGoResultsPanel(PluginTool tool, GhidraGoResults results) {
        super(new BorderLayout());
        this.results = results;

        // Create tabbed pane
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Functions", createFunctionsPanel());
        tabs.addTab("Types", createTypesPanel());
        tabs.addTab("Statistics", createStatsPanel());

        add(tabs, BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);
    }

    private JPanel createFunctionsPanel() {
        // Table with: Address, Name, Source, Type
        // Double-click to navigate to function
        // Right-click menu: Export, Copy, etc.
    }
}
```

---

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [x] MVP Complete (function recovery)
- [ ] Moduledata scanner (ELF)
- [ ] Basic typelinks parsing
- [ ] rtype structure parser

### Phase 2: Type Extraction (Weeks 3-4)
- [ ] Struct type parsing
- [ ] Interface type parsing
- [ ] Array/slice type parsing
- [ ] Type application to Ghidra

### Phase 3: Auto-Analyzer (Week 5)
- [ ] Java analyzer wrapper
- [ ] Ghidrathon integration
- [ ] Options panel
- [ ] Progress reporting

### Phase 4: Multi-Platform (Weeks 6-7)
- [ ] PE binary support
- [ ] Mach-O binary support
- [ ] Cross-platform testing
- [ ] Platform-specific edge cases

### Phase 5: UI Enhancement (Week 8)
- [ ] Results panel design
- [ ] Function table view
- [ ] Type visualization
- [ ] Export functionality

### Phase 6: Testing & Polish (Week 9)
- [ ] Comprehensive testing across Go versions (1.16-1.23)
- [ ] Performance optimization
- [ ] Documentation updates
- [ ] Example binaries and tutorials

---

## Technical Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────┐
│              GhidraGo v1.1 Architecture             │
└─────────────────────────────────────────────────────┘

┌─────────────────┐
│   Auto-Analyzer │ (Java)
│   Integration   │
└────────┬────────┘
         │ triggers
         ▼
┌─────────────────┐      ┌──────────────────┐
│ Go Binary       │      │ Results Panel    │
│ Detector        │◄────►│ (Swing UI)       │
└────────┬────────┘      └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│     Core Analysis Engine (Python)       │
├─────────────────────────────────────────┤
│ ┌─────────────────┐ ┌─────────────────┐ │
│ │ PCLNTAB Parser  │ │ Moduledata      │ │
│ │ (MVP)           │ │ Scanner (NEW)   │ │
│ └─────────────────┘ └─────────────────┘ │
│ ┌─────────────────┐ ┌─────────────────┐ │
│ │ Typelinks       │ │ Type Recovery   │ │
│ │ Parser (NEW)    │ │ Service (NEW)   │ │
│ └─────────────────┘ └─────────────────┘ │
└──────────────┬──────────────────────────┘
               │
               ▼
      ┌────────────────┐
      │ Ghidra Program │
      │ API            │
      └────────────────┘
```

### Data Flow

```
1. Binary Import → Auto-Analyzer Trigger
2. Go Detection → Version Identification
3. PCLNTAB Parse → Function Names (MVP)
4. Moduledata Scan → Type Metadata Location
5. Typelinks Parse → Type Definitions
6. Type Application → Ghidra DataTypeManager
7. Results Display → UI Panel + Console
```

---

## Risk Assessment

### High-Risk Areas

1. **Moduledata Location in PE/Mach-O** (Risk: High)
   - **Issue**: No guaranteed structure location
   - **Mitigation**: Multiple scanning strategies, extensive testing
   - **Fallback**: Graceful degradation to function-only recovery

2. **Go Version Compatibility** (Risk: Medium)
   - **Issue**: Type structures change between versions
   - **Mitigation**: Version-specific parsers, extensive test suite
   - **Fallback**: Support subset of versions initially

3. **Performance with Large Binaries** (Risk: Medium)
   - **Issue**: 10,000+ types could slow analysis
   - **Mitigation**: Lazy loading, progress cancellation
   - **Fallback**: Type extraction toggle option

### Low-Risk Areas

- Auto-analyzer integration (well-documented Ghidra API)
- UI panel (standard Swing components)
- ELF type extraction (proven approach from research)

---

## Testing Strategy

### Test Matrix

| Go Version | ELF | PE | Mach-O | Type Count | Result |
|------------|-----|----|---------| -----------|--------|
| 1.16       | ✅  | ✅ | ✅     | 500        | PASS   |
| 1.18       | ✅  | ✅ | ✅     | 1000       | PASS   |
| 1.20       | ✅  | ✅ | ✅     | 2000       | PASS   |
| 1.23       | ✅  | ✅ | ✅     | 5000       | PASS   |

### Test Binaries

1. **Simple Test**: Hello World (50-100 types)
2. **Medium Test**: HTTP Server (500-1000 types)
3. **Complex Test**: kubectl (5000+ types)
4. **Malware Sample**: Go ransomware (obfuscated)

### Validation Criteria

- **Function Recovery**: 90%+ success rate (same as MVP)
- **Type Recovery**: 80%+ success rate for Go 1.16+
- **Auto-Analyzer**: Runs without user intervention
- **Performance**: <60 seconds for typical binary
- **Cross-Platform**: Works on all three formats

---

## Success Metrics

### Quantitative Goals

| Metric | Target | Measurement |
|--------|--------|-------------|
| Type Recovery Rate | 80%+ | Types found / types in binary |
| Function Recovery Rate | 90%+ | Functions found / functions in binary |
| Auto-Analyzer Adoption | 100% | Enabled by default |
| Platform Coverage | 100% | ELF + PE + Mach-O |
| Performance (1000 funcs) | <10s | Wall-clock time |
| Performance (5000 funcs) | <60s | Wall-clock time |

### Qualitative Goals

- **User Experience**: One-click analysis, no configuration
- **Code Quality**: Comprehensive docstrings, type hints
- **Documentation**: Updated README, new type extraction guide
- **Maintainability**: Modular architecture, clear separation of concerns

---

## Documentation Plan

### User Documentation

1. **README Update**:
   - Add type extraction section
   - Update installation for auto-analyzer
   - Add PE/Mach-O support notes

2. **Type Extraction Guide** (NEW):
   - How type extraction works
   - Interpreting recovered types
   - Troubleshooting type recovery

3. **Examples Update**:
   - Before/after with types
   - Complex struct examples
   - Interface recovery examples

### Developer Documentation

1. **Architecture Guide** (NEW):
   - Component diagram
   - Data flow
   - Extension points

2. **Porting Guide** (NEW):
   - Adding new Go version support
   - Adding new binary format support

---

## Version Compatibility

### Backwards Compatibility

v1.1 will be **fully backwards compatible** with v1.0:
- All MVP functionality remains unchanged
- Type extraction is optional (can be disabled)
- Script-only mode still works (no Java required for basic use)

### Forward Compatibility

v1.1 prepares for v1.2+:
- Modular architecture enables easy addition of:
  - String recovery
  - Goroutine detection
  - Channel analysis
  - Standard library matching

---

## Migration Path from v1.0 to v1.1

### For End Users

**No Action Required** - v1.1 auto-upgrades:
1. Replace extension ZIP with v1.1 version
2. Restart Ghidra
3. Type extraction enabled automatically

**Optional**: Configure analyzer options in Edit → Tool Options → Analyzers → Go Function Recovery

### For Developers

**Extend Existing Code**:
- `RecoverGoFunctions.py` becomes base class
- New classes inherit and extend:
  - `TypeExtractor` extends base functionality
  - `ModuledataScanner` is new component
  - `TypeRecoveryService` is new component

**No Breaking Changes** to public APIs

---

## Conclusion

GhidraGo v1.1 represents a **significant enhancement** over the MVP while maintaining the same philosophy:

✅ **Easy to Use**: Auto-analyzer eliminates manual steps
✅ **Comprehensive**: Type extraction provides deep binary understanding
✅ **Cross-Platform**: ELF, PE, Mach-O support
✅ **Professional**: UI panel and structured results
✅ **Maintainable**: Modular architecture for future enhancements

**Estimated Total Effort**: 8-9 weeks (with buffer for testing)

**Key Differentiator**: Unlike GoReSym (standalone tool), GhidraGo v1.1 is **natively integrated** into Ghidra, enabling:
- Automatic analysis on import
- Direct type application to decompiler
- Interactive UI for exploring results
- Full access to Ghidra's rich analysis ecosystem

---

**GhidraGo v1.1 - From Function Names to Full Type Recovery**
*Taking Go binary analysis to the next level.*
