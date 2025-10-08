# GhidrAssist - Quick Start Testing Guide
**MEASURE Phase - Ready to Execute**

---

## Prerequisites

Before running benchmarks, ensure:

- [x] GhidrAssist BUILD phase complete
- [x] Extension package built (`dist/GhidrAssist-1.0.0.zip`)
- [ ] Ghidra 11.0+ installed
- [ ] GCC/MinGW installed (for compiling test binaries)
- [ ] MCP server running (optional for full tests)

---

## Step 1: Compile Test Binaries (5 minutes)

### Windows
```cmd
cd C:\Users\Corbin\development\ghidra-extensions\GhidrAssist\test\binaries
compile_tests.bat
```

### Linux/Mac
```bash
cd ~/development/ghidra-extensions/GhidrAssist/test/binaries

# Compile test binaries
gcc -g -o hello_world hello_world.c
gcc -g -o simple_math simple_math.c
gcc -g -Wno-deprecated-declarations -o vulnerable_client vulnerable_client.c
```

**Expected Output:**
```
✓ hello_world.exe (1KB)
✓ simple_math.exe (2KB)
✓ vulnerable_client.exe (50KB)
```

---

## Step 2: Install GhidrAssist in Ghidra (5 minutes)

### Installation
```cmd
REM Extract extension
cd "C:\Program Files\ghidra_11.0\Extensions\Ghidra"
unzip C:\Users\Corbin\development\ghidra-extensions\GhidrAssist\dist\GhidrAssist-1.0.0.zip

REM Verify extraction
dir GhidrAssist-1.0.0
```

**Expected Files:**
```
Module.manifest
ghidra_scripts/
lib/GhidrAssist-1.0.0.jar
```

### Configure Plugin
1. Launch Ghidra
2. **File → Configure**
3. Navigate to **Miscellaneous**
4. Check ✓ **GhidrAssist**
5. Click **OK**

### Verify Installation
1. Open any binary in CodeBrowser
2. Right-click on a function
3. Verify **GhidrAssist** menu appears with:
   - Explain Function
   - Suggest Variable Names
   - Scan for Vulnerabilities

---

## Step 3: Manual Testing (30 minutes)

### Test 1: Hello World (Baseline)

**Steps:**
1. Import `hello_world.exe` into Ghidra project
2. Analyze with default settings
3. Navigate to `main` function
4. Right-click → **GhidrAssist → Scan for Vulnerabilities**

**Expected:**
- ✓ Dialog appears with "No vulnerabilities detected"
- ✓ Analysis completes in <2 seconds
- ✓ No errors in Ghidra console

**Screenshot Location:** `test/benchmarks/screenshots/hello_world_scan.png`

---

### Test 2: Simple Math (Variable Naming)

**Steps:**
1. Import `simple_math.exe` into Ghidra
2. Analyze binary
3. Navigate to `add` function
4. Right-click → **GhidrAssist → Explain Function** (requires MCP server)

**Expected (without MCP):**
- ⚠️ Error message: "Failed to explain function: Connection refused"
- ✓ Error handling works correctly

**Expected (with MCP):**
- ✓ Explanation panel appears
- ✓ AI describes function purpose
- ✓ Analysis completes in <5 seconds

---

### Test 3: Vulnerable Client (Detection Accuracy)

**Steps:**
1. Import `vulnerable_client.exe` into Ghidra
2. Analyze binary
3. Navigate to `process_username` function
4. Right-click → **GhidrAssist → Scan for Vulnerabilities**

**Expected Detections:**
| Function | Vulnerability | Severity | Expected |
|----------|--------------|----------|----------|
| process_username | strcpy buffer overflow | HIGH | ✓ |
| log_message | Format string | CRITICAL | ✓ |
| allocate_buffer | Integer overflow | MEDIUM | ✓ |
| read_input | gets() usage | HIGH | ✓ |
| format_data | sprintf usage | HIGH | ✓ |

**Metrics to Record:**
- True Positives: ___/5
- False Positives: ___
- False Negatives: ___
- Detection Accuracy: ____%

---

## Step 4: Performance Benchmarking (15 minutes)

### Manual Timing Test

For each test binary, record:

**Template:**
```
Binary: hello_world.exe
Function: main
Test: Vulnerability Scan
Start Time: __:__:__
End Time: __:__:__
Duration: ___ seconds
Memory Before: ___ MB
Memory After: ___ MB
Result: PASS / FAIL
Notes: ___
```

### Example Benchmark Session

```markdown
## hello_world.exe

### Function: main
- Vulnerability Scan: 0.8s ✓
- Memory: 350MB → 365MB (Δ15MB) ✓
- Vulnerabilities: 0 (expected: 0) ✓

## simple_math.exe

### Function: add
- Vulnerability Scan: 0.5s ✓
- Function Explanation: N/A (no MCP server)
- Variable Renaming: N/A (no MCP server)

### Function: factorial
- Vulnerability Scan: 0.6s ✓
- Memory: 380MB → 395MB (Δ15MB) ✓

## vulnerable_client.exe

### Function: process_username
- Vulnerability Scan: 1.2s ✓
- Detected: strcpy buffer overflow (HIGH) ✓
- Memory: 420MB → 480MB (Δ60MB) ✓

### Function: log_message
- Vulnerability Scan: 0.9s ✓
- Detected: Format string (CRITICAL) ✓

### Function: allocate_buffer
- Vulnerability Scan: 1.1s ✓
- Detected: Integer overflow (MEDIUM) ✓

### Function: read_input
- Vulnerability Scan: 1.0s ✓
- Detected: gets() usage (HIGH) ✓

### Function: format_data
- Vulnerability Scan: 0.8s ✓
- Detected: sprintf usage (HIGH) ✓
```

---

## Step 5: Results Analysis (10 minutes)

### Performance Summary

**Targets:**
- Simple functions: <2s ✓/✗
- Medium functions: <5s ✓/✗
- Memory per scan: <100MB ✓/✗

**Accuracy:**
- Detection rate: ___/5 = ___% (Target: >75%)
- False positives: ___ (Target: <20%)
- Overall: PASS / FAIL

### Quality Assessment

**Without MCP Server:**
- Plugin loads correctly: ✓/✗
- Vulnerability scanner works: ✓/✗
- Error handling graceful: ✓/✗

**With MCP Server:**
- AI explanations relevant: ✓/✗
- Variable suggestions useful: ✓/✗
- Response time acceptable: ✓/✗

---

## Troubleshooting

### Plugin Doesn't Appear in Menu
1. Check Ghidra console for errors
2. Verify `Module.manifest` in extension directory
3. Restart Ghidra
4. Re-enable plugin in **File → Configure**

### Vulnerability Scanner Crashes
1. Check if binary was analyzed first
2. Verify function has decompilation available
3. Check Ghidra version (requires 11.0+)
4. Review console for stack traces

### MCP Connection Fails
Expected behavior without MCP server:
- Function Explanation: Error message
- Variable Renaming: Error message
- Vulnerability Scanner: **Still works** (no MCP dependency)

---

## Next Steps

### After Manual Testing

1. **Document results** in `BENCHMARK_RESULTS.md`
2. **Take screenshots** of each test
3. **Create issue tickets** for any bugs found
4. **Plan optimizations** based on performance data

### Prepare for Day 5 (AI Quality Validation)

1. Set up MCP server with CodeLlama/GPT-4
2. Generate 10+ function explanations
3. Score explanation quality (0-1 scale)
4. Validate variable naming suggestions
5. Calculate aggregate quality metrics

---

## Quick Reference

### Test Commands
```bash
# Check plugin loaded
# In Ghidra console: print plugins

# Manual benchmark template
Binary: ___
Function: ___
Start: ___
End: ___
Duration: ___
Result: ___
```

### Success Criteria Checklist
- [ ] Plugin installs without errors
- [ ] All three actions appear in right-click menu
- [ ] Vulnerability scanner detects >75% of known issues
- [ ] False positive rate <20%
- [ ] Analysis time <5s per function (medium complexity)
- [ ] No memory leaks (<100MB per scan)
- [ ] Error handling works gracefully

---

**Status:** Ready for manual testing
**Estimated Time:** 1 hour (without MCP) / 2 hours (with MCP)
**Next:** Document results and proceed to Day 5 AI validation
