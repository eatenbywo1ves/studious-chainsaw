# GhidraGo Phase 2 - Automated Testing Implementation Plan

**Date**: October 2, 2025
**Purpose**: Design automated/semi-automated implementation of next testing steps
**Status**: Implementation Plan

---

## Overview

This document outlines how to implement the 3 testing steps with maximum automation using available tools, agents, and servers.

---

## Step 1: Download Hugo Binary - AUTOMATED ✅

### Implementation Strategy

**Approach**: Use PowerShell/curl to download Hugo binary directly

### Automated Script (Enhanced)

**File**: `download_hugo_auto.bat`

```batch
@echo off
REM Automated Hugo Download for GhidraGo Testing
echo ========================================
echo GhidraGo Phase 2 - Automated Hugo Download
echo ========================================
echo.

REM Create directory
if not exist "prebuilt_binaries" mkdir prebuilt_binaries
cd prebuilt_binaries

REM Set Hugo version (latest as of Oct 2, 2025)
set HUGO_VERSION=0.151.0
set HUGO_URL=https://github.com/gohugoio/hugo/releases/download/v%HUGO_VERSION%/hugo_extended_%HUGO_VERSION%_windows-amd64.zip
set HUGO_ZIP=hugo_extended_%HUGO_VERSION%_windows-amd64.zip

echo [*] Downloading Hugo v%HUGO_VERSION% Extended (Windows AMD64)
echo [*] URL: %HUGO_URL%
echo.

REM Download using PowerShell (built-in on Windows 10/11)
echo [*] Starting download...
powershell -Command "& {$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%HUGO_URL%' -OutFile '%HUGO_ZIP%'}"

if %ERRORLEVEL% EQU 0 (
    echo [+] Download successful!
    echo.

    REM Extract using PowerShell
    echo [*] Extracting hugo.exe...
    powershell -Command "& {Expand-Archive -Path '%HUGO_ZIP%' -DestinationPath '.' -Force}"

    if exist "hugo.exe" (
        echo [+] Extraction successful!
        echo [+] Hugo binary location: %CD%\hugo.exe
        echo.

        REM Verify binary
        hugo.exe version
        echo.

        REM Get binary size
        for %%I in (hugo.exe) do echo [*] Binary size: %%~zI bytes (%%~zI / 1024 / 1024 MB)
        echo.

        echo [+] Hugo ready for testing!
        echo.
        echo ========================================
        echo Next Steps:
        echo ========================================
        echo 1. Open Ghidra
        echo 2. Import: %CD%\hugo.exe
        echo 3. Run RecoverGoFunctionsAndTypes.py
        echo 4. Follow QUICK_START_TESTING.md
        echo.

        REM Clean up zip
        del "%HUGO_ZIP%"

    ) else (
        echo [!] Extraction failed - hugo.exe not found
        exit /b 1
    )

) else (
    echo [!] Download failed
    echo [!] Please check internet connection and try again
    echo [!] Or download manually from: %HUGO_URL%
    exit /b 1
)

pause
```

**Implementation**:
- ✅ **Fully Automated**: No user interaction required
- ✅ **Direct Download**: PowerShell Invoke-WebRequest
- ✅ **Auto-Extract**: PowerShell Expand-Archive
- ✅ **Verification**: Run hugo.exe version
- ✅ **Cleanup**: Remove zip after extraction

**Time**: 2-5 minutes (depending on internet speed)

---

## Step 2: Ghidra Testing - SEMI-AUTOMATED ⚙️

### Challenge: Ghidra is GUI-Based

**Limitation**: Ghidra requires GUI interaction for:
- Project creation
- Binary import
- Script execution (from Script Manager)
- Result verification (Data Type Manager)

**Available Automation**:
- ✅ Ghidra Headless Analyzer (command-line)
- ✅ Python scripting within Ghidra
- ❌ No full GUI automation without additional tools

### Implementation Option A: Headless Ghidra (FULLY AUTOMATED)

**Ghidra Headless Analyzer** can run scripts without GUI:

```batch
@echo off
REM Automated Ghidra Testing using Headless Analyzer

set GHIDRA_DIR=C:\ghidra_11.2_PUBLIC
set PROJECT_DIR=%CD%\ghidra_test_project
set BINARY=%CD%\prebuilt_binaries\hugo.exe
set SCRIPT_DIR=C:\Users\Corbin\development\GhidraGo\ghidra_scripts

echo [*] Running GhidraGo Phase 2 in Headless Mode...

%GHIDRA_DIR%\support\analyzeHeadless ^
    %PROJECT_DIR% GhidraGoTest ^
    -import %BINARY% ^
    -scriptPath %SCRIPT_DIR% ^
    -postScript RecoverGoFunctionsAndTypes.py ^
    -deleteProject ^
    > ghidra_headless_output.txt 2>&1

echo [+] Analysis complete! Check ghidra_headless_output.txt
type ghidra_headless_output.txt
```

**Advantages**:
- ✅ Fully automated
- ✅ No GUI required
- ✅ Console output captured
- ✅ Scriptable and repeatable

**Disadvantages**:
- ⚠️ Cannot verify Data Type Manager visually
- ⚠️ Cannot take screenshots
- ⚠️ Requires Ghidra installation path
- ⚠️ Output harder to interpret than GUI

### Implementation Option B: GUI with Scripted Guidance (SEMI-AUTOMATED)

**Enhanced Guide Script** with automated setup:

```batch
@echo off
REM Semi-Automated Ghidra Testing Guide

echo ========================================
echo GhidraGo Phase 2 - Testing Guide
echo ========================================
echo.

echo [*] Preparing test environment...

REM Check Hugo binary
if not exist "prebuilt_binaries\hugo.exe" (
    echo [!] Hugo binary not found!
    echo [*] Running automated download...
    call download_hugo_auto.bat
)

echo.
echo [+] Hugo binary ready: %CD%\prebuilt_binaries\hugo.exe
echo.

echo ========================================
echo Manual Steps Required:
echo ========================================
echo.
echo STEP 1: Open Ghidra
echo    - Launch Ghidra application
echo.
echo STEP 2: Create/Open Project
echo    - File → New Project (Non-Shared)
echo    - Name: GhidraGo_Phase2_Testing
echo    - Location: %CD%\ghidra_test_project
echo.
echo STEP 3: Import Hugo Binary
echo    - File → Import File
echo    - Select: %CD%\prebuilt_binaries\hugo.exe
echo    - Format: Portable Executable (PE)
echo    - Click OK, then Analyze
echo    - Wait for analysis to complete (~3-5 minutes)
echo.
echo STEP 4: Run GhidraGo Script
echo    - Window → Script Manager
echo    - Filter: "RecoverGo"
echo    - Double-click: RecoverGoFunctionsAndTypes.py
echo    - Watch Console for 6 phases
echo.
echo STEP 5: Verify Results
echo    - Window → Data Type Manager
echo    - Look for Go types (main.*, http.*, etc.)
echo    - Expand a struct to see fields
echo.
echo ========================================
echo Press any key when ready to take screenshots...
pause >nul

echo.
echo [*] Opening screenshot directory...
if not exist "screenshots" mkdir screenshots
start screenshots

echo.
echo [*] Take these 5 screenshots:
echo    1. Console output (all 6 phases)
echo    2. Data Type Manager (type tree)
echo    3. Struct example (expanded fields)
echo    4. Interface example
echo    5. Decompiler view
echo.
echo Save to: %CD%\screenshots\
echo.

pause
```

**Advantages**:
- ✅ Guides user step-by-step
- ✅ Automated pre-checks (Hugo download)
- ✅ Automated directory creation
- ✅ Visual verification possible
- ✅ Screenshots can be taken

**Disadvantages**:
- ⚠️ Requires manual GUI interaction
- ⚠️ User must follow instructions

---

## Step 3: Document Results - SEMI-AUTOMATED 📝

### Implementation Strategy

**Approach**: Pre-fill template with automated data, user fills specifics

### Automated Documentation Generator

```batch
@echo off
REM Generate pre-filled validation report

set REPORT_FILE=test_results\hugo_test\VALIDATION_REPORT.md

REM Create directory
mkdir test_results\hugo_test\screenshots 2>nul

echo [*] Generating validation report...

REM Get system info
for /f "tokens=*" %%i in ('powershell -Command "Get-ComputerInfo | Select-Object -ExpandProperty OsName"') do set OS_NAME=%%i
for /f "tokens=*" %%i in ('powershell -Command "Get-ComputerInfo | Select-Object -ExpandProperty OsVersion"') do set OS_VER=%%i

REM Get Hugo info
if exist "prebuilt_binaries\hugo.exe" (
    for %%I in (prebuilt_binaries\hugo.exe) do set HUGO_SIZE=%%~zI
    for /f "tokens=*" %%i in ('prebuilt_binaries\hugo.exe version ^| findstr "hugo"') do set HUGO_VER=%%i
)

REM Generate report from template
(
echo # GhidraGo Phase 2 - Test Validation Report
echo.
echo **Binary Name**: Hugo Extended
echo **Binary Size**: %HUGO_SIZE% bytes
echo **Date Tested**: %DATE% %TIME%
echo **Tester**: Automated Pre-fill + Manual Completion
echo.
echo ---
echo.
echo ## Test Environment
echo.
echo **System Information**:
echo - OS: %OS_NAME%
echo - OS Version: %OS_VER%
echo - Ghidra Version: _____ ^(FILL IN^)
echo - GhidraGo Version: v1.1 Phase 2
echo - Binary Architecture: x64
echo.
echo **Binary Information**:
echo - Source: Hugo Static Site Generator
echo - Version: %HUGO_VER%
echo - Download URL: https://github.com/gohugoio/hugo/releases
echo - Binary Location: %CD%\prebuilt_binaries\hugo.exe
echo.
echo ---
echo.
echo ## Phase 1: Import and Analysis
echo.
echo ### 1.1 Ghidra Import
echo - ^[ ^] Binary imported successfully
echo - ^[ ^] Format detected: PE
echo - ^[ ^] Auto-analysis completed without errors
echo - ^[ ^] Analysis duration: _____ minutes ^(FILL IN^)
echo.
echo **Issues encountered**:
echo ```
echo ^(FILL IN - None or describe issues^)
echo ```
echo.
echo ---
echo.
echo ## Phase 2: Script Execution
echo.
echo ### 2.1 RecoverGoFunctionsAndTypes.py Execution
echo - ^[ ^] Script located in Script Manager
echo - ^[ ^] Script executed without errors
echo - ^[ ^] All 6 phases completed
echo.
echo **Console Output Summary**:
echo ```
echo Phase 1 ^(Go Detection^): PASS / FAIL ^(FILL IN^)
echo Phase 2 ^(Function Recovery^): PASS / FAIL - _____ functions ^(FILL IN^)
echo Phase 3 ^(Moduledata Location^): PASS / FAIL ^(FILL IN^)
echo Phase 4 ^(Typelinks Parsing^): PASS / FAIL - _____ type offsets ^(FILL IN^)
echo Phase 5 ^(Type Extraction^): PASS / FAIL - _____ types extracted ^(FILL IN^)
echo Phase 5.5 ^(Parser Init^): PASS / FAIL ^(FILL IN^)
echo Phase 6 ^(Type Application^): PASS / FAIL - _____ types created ^(FILL IN^)
echo ```
echo.
echo **Script execution duration**: _____ seconds ^(FILL IN^)
echo.
echo **Errors/Warnings**:
echo ```
echo ^(FILL IN - Copy from console^)
echo ```
echo.
echo ---
echo.
echo ## Phase 3: Type Extraction Validation
echo.
echo ### 3.1 Data Type Manager Check
echo - ^[ ^] Data Type Manager opened successfully
echo - ^[ ^] Go types visible in type tree
echo - ^[ ^] Types organized in namespaces
echo.
echo **Types Found**:
echo - Total struct types: _____ ^(FILL IN^)
echo - Total interface types: _____ ^(FILL IN^)
echo - Total other types: _____ ^(FILL IN^)
echo - **Grand Total**: _____ ^(FILL IN^)
echo.
echo **Sample Types** ^(FILL IN - list 5-10^):
echo 1. _____
echo 2. _____
echo 3. _____
echo 4. _____
echo 5. _____
echo.
echo ---
echo.
echo ^(Continue with rest of template...^)
echo.
echo **Report auto-generated**: %DATE% %TIME%
echo **Template location**: %CD%\TEST_VALIDATION_TEMPLATE.md
echo **Screenshots directory**: %CD%\screenshots\
) > "%REPORT_FILE%"

echo [+] Validation report generated: %REPORT_FILE%
echo [*] Please open and fill in remaining sections
echo.

start notepad "%REPORT_FILE%"
```

**Advantages**:
- ✅ Auto-fills system info
- ✅ Auto-fills binary details
- ✅ Creates directory structure
- ✅ Opens report in editor
- ✅ Saves time on boilerplate

**Disadvantages**:
- ⚠️ User must fill test results
- ⚠️ User must capture screenshots

---

## Complete Automated Workflow

### Master Script: `run_complete_test.bat`

```batch
@echo off
echo ========================================
echo GhidraGo Phase 2 - Complete Automated Testing
echo ========================================
echo.

echo [1/5] Downloading Hugo Binary...
call download_hugo_auto.bat
if %ERRORLEVEL% NEQ 0 (
    echo [!] Download failed
    pause
    exit /b 1
)
echo.

echo [2/5] Preparing Test Environment...
mkdir ghidra_test_project 2>nul
mkdir test_results\hugo_test\screenshots 2>nul
echo [+] Directories created
echo.

echo [3/5] Generating Pre-filled Validation Report...
call generate_validation_report.bat
echo [+] Report ready
echo.

echo [4/5] Opening Quick Start Guide...
start QUICK_START_TESTING.md
echo [+] Guide opened
echo.

echo [5/5] Ready for Ghidra Testing!
echo.
echo ========================================
echo Manual Steps (Follow Quick Start Guide):
echo ========================================
echo 1. Open Ghidra
echo 2. Import: %CD%\prebuilt_binaries\hugo.exe
echo 3. Run RecoverGoFunctionsAndTypes.py
echo 4. Verify in Data Type Manager
echo 5. Take 5 screenshots
echo 6. Fill remaining sections in validation report
echo.
echo ========================================
echo Automation Complete!
echo ========================================
echo.
echo Time saved: ~10-15 minutes
echo Manual time remaining: ~30-40 minutes
echo.

pause
```

---

## Agent-Based Implementation (ADVANCED)

### Using Task Agent for Coordination

**Pseudo-code for agent orchestration**:

```python
# Task: Complete GhidraGo Phase 2 Testing
agent = general_purpose_agent

# Step 1: Download Hugo (AUTOMATED)
agent.execute_task("""
Download Hugo v0.151.0 Extended Windows AMD64 binary:
1. Use PowerShell Invoke-WebRequest
2. URL: https://github.com/gohugoio/hugo/releases/download/v0.151.0/hugo_extended_0.151.0_windows-amd64.zip
3. Extract to: prebuilt_binaries/
4. Verify: run hugo.exe version
5. Report size and version
""")

# Step 2: Prepare Environment (AUTOMATED)
agent.execute_task("""
Prepare testing environment:
1. Create directories: ghidra_test_project, test_results/hugo_test/screenshots
2. Generate pre-filled validation report
3. Open Quick Start Guide
4. Report readiness
""")

# Step 3: Guide User (SEMI-AUTOMATED)
agent.provide_guidance("""
User must complete these manual steps:
1. Open Ghidra
2. Import hugo.exe (location: {path})
3. Run RecoverGoFunctionsAndTypes.py
4. Verify types in Data Type Manager
5. Capture 5 screenshots
6. Fill validation report

Monitor user progress and provide assistance when asked.
""")

# Step 4: Post-Processing (AUTOMATED)
agent.execute_task("""
After user completes testing:
1. Verify screenshots exist (5 files)
2. Check validation report is filled
3. Generate summary statistics
4. Create final test report
5. Archive results
""")
```

---

## Implementation Decision Matrix

| Step | Automation Level | Implementation | Time Saved | User Effort |
|------|------------------|----------------|------------|-------------|
| **Download Hugo** | ✅ Full | PowerShell script | 5-8 min | 0 min |
| **Setup Directories** | ✅ Full | Batch script | 2 min | 0 min |
| **Generate Report** | ⚙️ Semi | Pre-fill template | 10 min | 5 min |
| **Import to Ghidra** | ❌ Manual | User GUI action | 0 min | 5 min |
| **Run Script** | ❌ Manual | User GUI action | 0 min | 2 min |
| **Verify Results** | ❌ Manual | User GUI action | 0 min | 10 min |
| **Screenshots** | ❌ Manual | User captures | 0 min | 5 min |
| **Fill Report** | ⚙️ Semi | User fills blanks | 5 min | 10 min |

**Total Time Saved**: ~22-25 minutes
**Remaining User Time**: ~37 minutes
**Overall**: ~60 minutes → ~37 minutes (38% reduction)

---

## Recommended Implementation

### Phase 1: Immediate Implementation (Today)

1. **Create** `download_hugo_auto.bat` (fully automated download)
2. **Create** `generate_validation_report.bat` (pre-fill template)
3. **Create** `run_complete_test.bat` (master orchestrator)
4. **Test** automated scripts on current system

### Phase 2: Enhanced Implementation (Future)

1. **Implement** Ghidra Headless mode for full automation
2. **Create** PowerShell screenshot automation
3. **Build** result parser to auto-fill validation data
4. **Develop** agent-based orchestration

---

## Implementation Files to Create

1. **download_hugo_auto.bat** - Automated Hugo download ✅
2. **generate_validation_report.bat** - Pre-fill report ✅
3. **run_complete_test.bat** - Master script ✅
4. **test_ghidra_headless.bat** - Headless Ghidra option (advanced)
5. **capture_results.ps1** - Result extraction (advanced)

---

## Conclusion

**Current Best Approach**: Hybrid automation
- ✅ Automate Steps 1 & 3 (download, documentation)
- ⚙️ Semi-automate Step 2 (guided Ghidra testing)
- ⏱️ Time savings: ~40% (25 minutes saved)
- 🎯 User focus: Testing and verification (core value)

**Implementation Priority**:
1. **High**: download_hugo_auto.bat
2. **High**: run_complete_test.bat
3. **Medium**: generate_validation_report.bat
4. **Low**: Headless Ghidra (for future CI/CD)

Let's implement these scripts now!
