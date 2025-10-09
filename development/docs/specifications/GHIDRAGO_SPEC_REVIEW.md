# GhidraGo Specification - Review & Discussion Points
**Review Date**: January 10, 2025
**Specification**: GHIDRAGO_SPECIFICATION.md (793 lines)

---

## Overview Statistics

- **Total Lines**: 793 (comprehensive documentation)
- **Code Examples**: 15+ Java snippets
- **Data Structures**: 7 Go runtime structures documented
- **Implementation Phases**: 5 phases over 3 days
- **References**: 8+ technical sources

---

## Specification Strengths ✅

### 1. **Comprehensive Research Foundation**
- Analyzed 3 existing plugins (gotools, GolangAnalyzerExtension, golang-ghidra)
- Reviewed 5+ technical blog posts (CUJO AI, Google Cloud, etc.)
- Cross-referenced Go runtime source code
- Industry trend analysis (300% malware growth)

### 2. **Clear Problem Definition**
- 7 specific challenges identified
- Real-world use cases (ransomware, botnets, APT tools)
- Quantified market need

### 3. **Detailed Technical Specifications**
- Complete Go runtime structure documentation:
  - PCLNTAB (Program Counter Line Table)
  - MODULEDATA (Runtime metadata)
  - TYPELINKS (Type information array)
  - GO STRINGS (String structure)
- Version-specific handling (Go 1.2, 1.16, 1.18, 1.20, 1.23)
- Magic number references for all versions

### 4. **Phased Implementation Plan**
- Day 1: Core infrastructure (8 hours)
- Day 2: Symbol & type recovery (8 hours)
- Day 3: Polish & integration (6-8 hours)
- Clear success criteria for each phase

### 5. **Success Metrics Defined**
- Function recovery: 90%+
- Type extraction: 70%+
- String recovery: 80%+
- False positives: <5%
- Version detection: 95%+

---

## Areas for Discussion 🤔

### Priority 1: **Scope Considerations**

#### Question 1: Feature Prioritization
**Current Plan**: Implement all 5 phases in 3 days

**Options to Consider**:

**A. Full Implementation (as specified)**
- ✅ Complete feature set
- ✅ Maximum value delivery
- ⚠️ Ambitious timeline (22-24 hours)
- ⚠️ Higher complexity risk

**B. Phased Release Approach**
- **v0.1 (Day 1-2)**: Core + Symbol Recovery only
  - Go version detection
  - PCLNTAB parsing
  - Function name recovery
  - Basic moduledata parsing
- **v0.2 (Day 3)**: Add Type Extraction
  - Typelinks parsing
  - Type application
- **v0.3 (Day 4)**: Add String Recovery + UI
  - Static/dynamic strings
  - Analysis panel

**Recommendation**: Consider option B if we want to validate core functionality early.

---

#### Question 2: Platform Support
**Current Plan**: ELF, PE, and Mach-O support

**Considerations**:
- **ELF (Linux)**: Most common, easiest to implement
- **PE (Windows)**: More complex (moduledata harder to find)
- **Mach-O (macOS)**: Less common in malware

**Options**:
1. **Full support**: All three formats (as specified)
2. **ELF first**: Ship with Linux support, add PE/Mach-O later
3. **ELF + PE**: Focus on most common platforms

**Question**: Is Mach-O support critical for v1.0, or can it be deferred?

---

#### Question 3: Go Version Range
**Current Plan**: Support Go 1.2 through 1.23

**Considerations**:
- Go 1.2-1.15: Older format (magic `0xfffffffb`)
- Go 1.16-1.17: Intermediate format (magic `0xfffffff0`)
- Go 1.18+: Current format (magic `0xfffffff1`)

**Options**:
1. **Full range**: 1.2-1.23 (as specified)
2. **Modern focus**: 1.16+ only (90% of current malware)
3. **Latest only**: 1.18+ (simplest implementation)

**Question**: How important is legacy Go version support vs. implementation simplicity?

---

### Priority 2: **Implementation Approach**

#### Question 4: Language Choice
**Current Plan**: Pure Java implementation

**Alternatives**:
1. **Pure Java** (as specified)
   - ✅ Deep Ghidra integration
   - ✅ Performance
   - ⚠️ More verbose code
   - ⚠️ Longer development time

2. **Python + Java Hybrid**
   - ✅ Faster development (Python for parsers)
   - ✅ Easier prototyping
   - ⚠️ Less performant for large binaries
   - ✅ Can leverage existing Python scripts (CUJO AI examples)

3. **Python Scripts Only** (no plugin)
   - ✅ Very fast development (1-2 days)
   - ✅ Easy to modify
   - ⚠️ No auto-analyzer integration
   - ⚠️ No UI panel

**Recommendation**:
- Start with Python scripts for rapid prototyping
- Wrap in Java plugin for polish and auto-analyzer integration
- This could reduce Day 1-2 from 16 hours to 10-12 hours

---

#### Question 5: Moduledata Detection Strategy
**Current Plan**: Linear byte scan for pclntab pointer

**Alternatives**:
1. **Linear Scan** (as specified)
   - ✅ Works for all cases
   - ⚠️ Slow for large binaries
   - ⚠️ May have false positives

2. **Section-based Search**
   - ✅ Faster (search only .noptrdata/.data sections)
   - ✅ Fewer false positives
   - ⚠️ May miss obfuscated binaries

3. **Hybrid Approach**
   - Try section-based first
   - Fall back to linear scan if not found
   - Best of both worlds

**Recommendation**: Use hybrid approach for better performance.

---

### Priority 3: **Technical Challenges**

#### Challenge 1: Version Detection Reliability
**Specified Approach**:
1. Check buildinfo section (Go 1.18+)
2. Check pclntab magic number
3. Check moduledata structure layout
4. Heuristic analysis of runtime functions

**Potential Issues**:
- Obfuscated binaries may modify magic numbers
- Packed binaries may hide pclntab
- Custom Go builds may have modified structures

**Question**: How should we handle edge cases where version detection fails?

**Options**:
1. Fail gracefully with user warning
2. Attempt analysis with "best guess" version
3. Allow manual version override in UI

---

#### Challenge 2: Type Extraction Complexity
**Specified Approach**: Recursive parsing of typelinks array

**Complexity Factors**:
- 26 different type kinds to handle
- Recursive type references (struct containing struct)
- Interface method tables
- Function signature multi-return types

**Question**: Should we implement full type extraction in v1.0, or start with basic types (primitives, structs) and add complex types (interfaces, functions) later?

**Recommendation**:
- **v1.0**: Primitives + Structs (covers 70% of cases)
- **v1.1**: Add Interfaces + Function types

---

#### Challenge 3: String Recovery Accuracy
**Specified Targets**:
- Static strings: 80%+
- Dynamic strings: Unknown (architecture-dependent)

**Concerns**:
- False positives from random data matching string pattern
- Architecture-specific instruction patterns may miss cases
- Dynamic strings harder to verify

**Question**: What's acceptable false positive rate for strings?

**Options**:
1. **Conservative** (as specified): <5% false positives, may miss some strings
2. **Aggressive**: Higher coverage, accept 10-15% false positives
3. **Manual verification**: Flag uncertain strings for user review

---

### Priority 4: **Dependency & Integration**

#### Question 6: Standard Library Signature Database
**Mentioned**: "data/go_stdlib_signatures.json - Known stdlib function signatures"

**Considerations**:
- Need to generate this database from Go source
- Different signatures for different Go versions
- Size could be 1000+ functions

**Options**:
1. **Pre-generate**: Create comprehensive database before release
   - ✅ Complete coverage
   - ⚠️ Large file size
   - ⚠️ Maintenance burden

2. **Minimal set**: Only most common 100-200 functions
   - ✅ Smaller, easier to maintain
   - ✅ Covers 90% of cases
   - ⚠️ Incomplete

3. **Optional add-on**: Ship plugin without DB, provide separately
   - ✅ Smaller plugin
   - ✅ Users can update independently
   - ⚠️ Extra installation step

**Recommendation**: Option 2 (minimal set) for v1.0, expand later.

---

#### Question 7: GhidraGraph Integration
**Mentioned**: "Works with GhidraGraph for call graph visualization"

**Integration Points**:
1. Share recovered function names with GhidraGraph
2. Export Go-specific call graphs
3. Visualize goroutine relationships

**Question**: Should this integration be part of v1.0, or added in v1.1?

**Recommendation**:
- v1.0: Basic function naming (works automatically with GhidraGraph)
- v1.1: Advanced integration (Go-specific visualizations)

---

## Specification Gaps 🔍

### Gap 1: Error Handling Strategy
**Missing**: Detailed error handling for malformed binaries

**Should Define**:
- What happens if pclntab magic number not found?
- How to handle corrupted moduledata structures?
- User feedback for failed analysis

**Recommendation**: Add error handling section with:
- Graceful degradation (partial analysis)
- Clear error messages
- Logging strategy

---

### Gap 2: Performance Considerations
**Partially Addressed**: Mentions large binary size (10-20 MB)

**Should Define**:
- Expected analysis time for typical binary
- Memory usage estimates
- Progress feedback mechanism
- Cancellation support

**Recommendation**: Add performance section with:
- Benchmarks for different binary sizes
- TaskMonitor integration for progress
- Configurable timeout limits

---

### Gap 3: Testing Strategy Detail
**Mentioned**: Test with Hello World, Complex App, Malware Sample

**Should Define**:
- Where to obtain test binaries?
- How to validate results?
- Automated test suite?
- Regression testing approach?

**Recommendation**: Add testing section with:
- Test binary repository references
- Validation scripts
- Expected output for known binaries

---

### Gap 4: User Documentation
**Mentioned**: help.html and README.md

**Should Define**:
- User workflow documentation
- Troubleshooting guide
- Example use cases with screenshots
- FAQ section

**Recommendation**: Plan documentation alongside development, not after.

---

## Alternative Approaches to Consider 💡

### Alternative 1: **Script-First Development**
Instead of plugin-first, develop Python scripts first:

**Phase 1 (1 day)**: Python scripts
- `RecoverGoFunctions.py`
- `ExtractGoTypes.py`
- `FindGoStrings.py`

**Phase 2 (1-2 days)**: Wrap in Java plugin
- Auto-analyzer integration
- UI panel
- Help system

**Advantages**:
- Faster initial development
- Easier debugging
- Can leverage CUJO AI's existing scripts
- Users can run scripts independently

**Disadvantages**:
- Less polished initially
- No auto-analyzer in phase 1
- Two-phase delivery

---

### Alternative 2: **Minimal Viable Plugin (MVP)**
Focus on core value proposition only:

**MVP Features**:
- ✅ Go version detection
- ✅ Function name recovery (pclntab parsing)
- ✅ Auto-analyzer integration
- ✅ Basic documentation

**Defer to v1.1**:
- Type extraction
- String recovery
- UI panel
- Signature database

**Timeline**: 1-2 days instead of 3

**Advantages**:
- Faster time to value
- Lower risk
- Early user feedback
- Iterative improvement

---

### Alternative 3: **Leverage Existing Tools**
Instead of reimplementing everything, integrate existing tools:

**Option**: Create Ghidra plugin that wraps GoReSym
- GoReSym (https://github.com/mandiant/GoReSym) is mature Go symbol recovery tool
- Written in Go, outputs JSON
- Already handles version compatibility

**Implementation**:
1. Call GoReSym as external process
2. Parse JSON output
3. Apply to Ghidra program
4. Add UI for result visualization

**Timeline**: 1 day

**Advantages**:
- ✅ Leverage battle-tested code
- ✅ Automatic version updates
- ✅ Faster development

**Disadvantages**:
- ⚠️ External dependency (requires Go installed)
- ⚠️ Less integration
- ⚠️ No type extraction (GoReSym doesn't do this)

---

## Recommendations Summary 🎯

### Immediate Questions to Resolve:

1. **Scope**: Full implementation vs. MVP vs. phased release?
2. **Platform**: ELF only vs. ELF+PE vs. all three?
3. **Versions**: Go 1.2-1.23 vs. 1.16+ vs. 1.18+ only?
4. **Language**: Pure Java vs. Python+Java hybrid vs. Python scripts?
5. **Timeline**: 3 days as specified vs. adjusted based on scope?

---

### Recommended Approach (Balanced):

**Phase 1 - MVP (Day 1-2)**:
- Python scripts for core functionality
  - Go version detection
  - PCLNTAB parsing
  - Function name recovery
- Basic Java plugin wrapper
- ELF support only
- Go 1.16+ support

**Phase 2 - Enhancement (Day 3)**:
- Add PE support
- Add basic type extraction (primitives + structs)
- Add UI panel
- Complete documentation

**Phase 3 - Polish (Day 4, optional)**:
- Add string recovery
- Add signature database
- Add Mach-O support
- Add legacy Go version support (1.2-1.15)

**Total**: 2-4 days depending on desired completeness

---

### Alternative Recommendation (Fast Track):

**Use GoReSym Integration Approach**:
- Day 1: Wrapper plugin + JSON parser
- Day 2: UI panel + documentation
- Total: 2 days, production-ready

**Then add unique features in v1.1**:
- Type extraction (GoReSym doesn't do this)
- String recovery
- GhidraGraph integration

---

## Questions for You 💬

Before proceeding with implementation, please advise on:

### Critical Decisions:
1. **Scope preference**: Full specification vs. MVP vs. phased?
2. **Timeline flexibility**: Must be 3 days, or can adjust?
3. **Platform priority**: All platforms critical, or ELF sufficient initially?
4. **Quality vs. speed**: Prefer complete/polished vs. fast/iterative?

### Feature Priorities:
5. **Type extraction**: Must-have for v1.0 or can defer?
6. **String recovery**: Critical or nice-to-have?
7. **UI panel**: Required or can use console output initially?
8. **Legacy Go versions**: Important or focus on modern (1.16+)?

### Technical Approach:
9. **Pure Java vs. hybrid**: Preference for implementation language?
10. **External tools**: Open to GoReSym integration or prefer pure implementation?

---

## Conclusion

The specification is **thorough and well-researched**, providing an excellent foundation. The questions above are about **optimization and risk management**, not specification flaws.

**Two paths forward**:

**Path A - Full Specification** (3 days, ambitious):
- Implement as specified
- High value, higher risk
- All features in v1.0

**Path B - Pragmatic MVP** (2 days, safer):
- Core features first (function recovery)
- Iterative enhancement
- Lower risk, faster delivery

**My recommendation**: Path B (MVP) with full specification as roadmap for v1.1-1.3.

**What would you like to proceed with?**
