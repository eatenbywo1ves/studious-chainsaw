# GhidraGo Phase 2 - Quick Start Testing Guide

**Goal**: Validate GhidraGo Phase 2 in under 30 minutes using a pre-built Go binary

---

## Prerequisites

✅ **Required**:
- Ghidra installed and functional
- Web browser (for downloading test binary)
- ~50MB free disk space

❌ **Not Required**:
- Go compiler (we'll use pre-built binaries)
- Custom test programs

---

## Step-by-Step Guide (30 Minutes)

### Step 1: Download Test Binary (5 minutes)

**Recommended: Hugo Static Site Generator**

**Option A - Automated** (recommended):
```batch
cd C:\Users\Corbin\development\GhidraGo\test_binaries
download_prebuilt_go_binary.bat
```
This will open your browser to Hugo releases. Download `hugo_extended_*_windows-amd64.zip`.

**Option B - Manual**:
1. Visit: https://github.com/gohugoio/hugo/releases/latest
2. Download: `hugo_extended_X.X.X_windows-amd64.zip` (look for Extended version)
3. Extract `hugo.exe` from the zip file
4. Place in: `C:\Users\Corbin\development\GhidraGo\test_binaries\prebuilt_binaries\`

**Alternative Binaries** (if Hugo unavailable):
- Docker CLI: https://download.docker.com/win/static/stable/x86_64/
- Kubectl: https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/

---

### Step 2: Set Up Ghidra Project (5 minutes)

1. **Launch Ghidra**
   - Open Ghidra application

2. **Create New Project**
   - File → New Project
   - Choose "Non-Shared Project"
   - Name: `GhidraGo_Phase2_Testing`
   - Location: `C:\Users\Corbin\development\GhidraGo\ghidra_projects\`

3. **Import Binary**
   - File → Import File
   - Navigate to: `C:\Users\Corbin\development\GhidraGo\test_binaries\prebuilt_binaries\`
   - Select: `hugo.exe` (or your downloaded binary)
   - Click OK (accept default format: Portable Executable)

4. **Analyze Binary**
   - Double-click `hugo.exe` in project window
   - Click "Yes" when prompted to analyze
   - Wait for auto-analysis to complete (~3-5 minutes)
   - Check progress in bottom-right corner

---

### Step 3: Run GhidraGo Phase 2 (2 minutes)

1. **Open Script Manager**
   - Window → Script Manager (or press `Shift+F11`)

2. **Navigate to Script**
   - In filter box, type: `RecoverGo`
   - Or navigate to: `ghidra_scripts` folder
   - Find: `RecoverGoFunctionsAndTypes.py`

3. **Run Script**
   - Double-click the script (or select and click green "Run" button)
   - Watch console output (Window → Console if not visible)

4. **Monitor Progress**
   - You'll see 6 phases execute:
     ```
     Phase 1: Go Detection and PCLNTAB Location
     Phase 2: Function Name Recovery
     Phase 3: Moduledata Structure Location
     Phase 4: Typelinks Array Parsing
     Phase 5: Type Information Extraction
     Phase 5.5: Initialize Phase 2 Parsers and Resolver
     Phase 6: Type Application to Ghidra
     ```
   - Expected duration: 15-60 seconds depending on binary size

---

### Step 4: Verify Results (10 minutes)

#### 4.1 Check Console Output

**Look for success indicators**:
```
[+] Detected Go version: 1.XX
[+] PCLNTAB located at: 0x...
[+] Successfully parsed XXX functions
[+] Moduledata found at: 0x...
[+] Successfully extracted XXX types
[+] Type resolution complete!
    Types created in Ghidra: XXX
```

**Red flags** (if you see these, something went wrong):
```
[!] Failed to detect Go binary
[!] No types extracted
[!] Error: ...
```

#### 4.2 Open Data Type Manager

1. **Open Data Type Manager**
   - Window → Data Type Manager

2. **Expand Type Tree**
   - Look for Go types in the tree
   - Expand categories like `main`, `net`, `http`, etc.

3. **Inspect a Struct Type**
   - Find a struct type (e.g., `main.Config`, `http.Request`)
   - Double-click to view structure
   - **Check for**:
     - ✅ Field names (should be descriptive, not `field_0`, `field_1`)
     - ✅ Field types (should be resolved, not all `undefined`)
     - ✅ Field offsets (should show hex offsets like `+0x00`, `+0x08`)

#### 4.3 Check Interface Types

1. Find an interface type (e.g., `io.Reader`, `http.ResponseWriter`)
2. Double-click to view
3. **Look for**:
   - Structure representation (tab pointer + data pointer)
   - Method list in description/comment section

---

### Step 5: Take Screenshots (5 minutes)

**Create screenshots directory**:
```batch
mkdir C:\Users\Corbin\development\GhidraGo\test_results\hugo_test\screenshots
```

**Capture these screenshots** (using Snipping Tool or Print Screen):

1. **Console Output** - Show all 6 phases complete
2. **Data Type Manager** - Show expanded type tree with Go types
3. **Struct Example** - Show a struct with visible fields
4. **Interface Example** - Show an interface type

**Save to**: `C:\Users\Corbin\development\GhidraGo\test_results\hugo_test\screenshots\`

---

### Step 6: Document Results (3 minutes)

**Quick validation**:
- [ ] Script completed without errors
- [ ] Types were extracted (count > 0)
- [ ] At least one struct has visible field names
- [ ] Console shows success messages

**If all checkboxes are ✅**: Phase 2 is working! 🎉

**If any are ❌**: Document the issue and refer to troubleshooting section

---

## Quick Validation Checklist

Copy this to your test notes:

```
=== GhidraGo Phase 2 Quick Validation ===
Date: ___________
Binary: hugo.exe / docker.exe / kubectl.exe / other: _______

Results:
[ ] Binary imported to Ghidra successfully
[ ] Auto-analysis completed
[ ] GhidraGo script executed without errors
[ ] All 6 phases completed
[ ] Types extracted (count: _____)
[ ] Struct fields have descriptive names
[ ] Field types are resolved (not undefined)
[ ] Screenshots captured

Status: ✅ SUCCESS / ⚠️ PARTIAL / ❌ FAILED

Notes:
_________________________________________________
_________________________________________________
```

---

## Troubleshooting

### Issue: "Failed to detect Go binary"
**Solution**: Binary may not be a Go program, or unsupported Go version
- Verify binary is actually Go: Look for `.gopclntab` section in Ghidra
- Try a different binary (Hugo, Docker, Kubectl)

### Issue: "No types extracted"
**Solution**: Moduledata structure not found
- Check Phase 3 output
- Try updating script to latest version
- Report issue with binary details

### Issue: "Script hangs or infinite loop"
**Solution**: Possible circular reference issue
- Wait 2-3 minutes to see if it completes
- If still hung, stop script (Script Manager → Stop)
- Report issue with binary name

### Issue: "All fields show as undefined"
**Solution**: Type resolution may not be working
- Check Phase 5.5 and 6 output for errors
- Verify TypeResolver initialized
- Try simpler binary first

---

## Expected Results (Hugo Binary)

**Typical output for Hugo**:
- Functions recovered: 5,000-10,000
- Types extracted: 100-300
- Types created: 100-300
- Analysis time: 15-60 seconds

**Types you should see**:
- `main.Config`
- `main.Command`
- Various Hugo-specific types
- Standard library types (`http.Request`, `context.Context`, etc.)

---

## Next Steps After Successful Validation

1. **Fill out complete validation template**:
   - Use: `TEST_VALIDATION_TEMPLATE.md`
   - Document detailed findings

2. **Test additional binaries** (optional):
   - Docker CLI for complex interfaces
   - Kubectl for cloud-native patterns

3. **Create validation report**:
   - Summarize all test results
   - Include screenshots
   - Note any issues or limitations

4. **Mark Phase 2 as validated** ✅

---

## Time Breakdown

- Download binary: 5 min
- Ghidra setup: 5 min
- Script execution: 2 min
- Result verification: 10 min
- Screenshots: 5 min
- Documentation: 3 min

**Total**: ~30 minutes

---

## Success Criteria

**Minimum Success** (validates Phase 2 is functional):
- ✅ Script completes all 6 phases
- ✅ At least 10 types extracted
- ✅ At least one struct with field names visible

**Full Success** (validates Phase 2 is production-ready):
- ✅ 100+ types extracted
- ✅ Struct fields have descriptive names and resolved types
- ✅ Tags visible (if present in binary)
- ✅ Interface methods extracted
- ✅ No errors or warnings in console

---

## Questions or Issues?

Document in: `test_results/hugo_test/ISSUES.txt`

Include:
- Binary name and version
- Ghidra version
- Console output (copy/paste)
- Screenshots of problem areas

---

**Quick Start Guide v1.0**
**Last Updated**: October 2, 2025
**Status**: Ready for use
