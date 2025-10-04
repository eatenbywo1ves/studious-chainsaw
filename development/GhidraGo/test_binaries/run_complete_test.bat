@echo off
REM GhidraGo Phase 2 - Complete Testing Workflow
REM Automates Steps 1 & 3, guides Step 2

echo.
echo  ========================================================================
echo    GhidraGo Phase 2 - Automated Testing Workflow
echo  ========================================================================
echo.
echo  This script will:
echo    [1] Download Hugo binary automatically
echo    [2] Prepare test environment
echo    [3] Generate pre-filled validation report
echo    [4] Guide you through Ghidra testing
echo.
echo  Estimated time: 40-50 minutes (vs 60+ minutes manual)
echo.
echo  ========================================================================
pause

REM =============================================================================
REM STEP 1: Download Hugo Binary (FULLY AUTOMATED)
REM =============================================================================

echo.
echo  ========================================================================
echo    STEP 1/5: Downloading Hugo Binary
echo  ========================================================================
echo.

call download_hugo_auto.bat

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] STEP 1 FAILED - Hugo download unsuccessful
    echo [!] Cannot proceed without test binary
    echo.
    echo [*] Options:
    echo     1. Check internet connection and retry
    echo     2. Download manually: https://github.com/gohugoio/hugo/releases
    echo     3. Use alternative binary (Docker, Kubectl)
    echo.
    pause
    exit /b 1
)

echo.
echo [+] STEP 1 COMPLETE - Hugo binary ready
echo.
pause

REM =============================================================================
REM STEP 2: Prepare Test Environment (FULLY AUTOMATED)
REM =============================================================================

echo.
echo  ========================================================================
echo    STEP 2/5: Preparing Test Environment
echo  ========================================================================
echo.

echo [*] Creating directory structure...

REM Create Ghidra project directory
if not exist "ghidra_test_project" (
    mkdir ghidra_test_project
    echo [+] Created: ghidra_test_project\
) else (
    echo [*] Exists: ghidra_test_project\
)

REM Create test results directory
if not exist "..\test_results\hugo_test" (
    mkdir ..\test_results\hugo_test
    echo [+] Created: test_results\hugo_test\
) else (
    echo [*] Exists: test_results\hugo_test\
)

REM Create screenshots directory
if not exist "..\test_results\hugo_test\screenshots" (
    mkdir ..\test_results\hugo_test\screenshots
    echo [+] Created: test_results\hugo_test\screenshots\
) else (
    echo [*] Exists: test_results\hugo_test\screenshots\
)

echo.
echo [+] STEP 2 COMPLETE - Environment ready
echo.
pause

REM =============================================================================
REM STEP 3: Generate Pre-filled Validation Report (SEMI-AUTOMATED)
REM =============================================================================

echo.
echo  ========================================================================
echo    STEP 3/5: Generating Validation Report
echo  ========================================================================
echo.

echo [*] Collecting system information...

REM Get Hugo info
if exist "prebuilt_binaries\hugo.exe" (
    for %%I in (prebuilt_binaries\hugo.exe) do set HUGO_SIZE=%%~zI
    for /f "tokens=*" %%i in ('prebuilt_binaries\hugo.exe version 2^>nul ^| findstr /C:"hugo"') do set HUGO_VER=%%i
)

REM Set report location
set REPORT_FILE=..\test_results\hugo_test\VALIDATION_REPORT.md
set HUGO_PATH=%CD%\prebuilt_binaries\hugo.exe

echo [*] Generating report from template...

(
echo # GhidraGo Phase 2 - Hugo Test Validation Report
echo.
echo **Binary Name**: Hugo Extended
echo **Binary Size**: %HUGO_SIZE% bytes ^(~%HUGO_SIZE:~0,-6% MB^)
echo **Date Tested**: %DATE%
echo **Tester**: %USERNAME%
echo.
echo ---
echo.
echo ## Test Environment
echo.
echo **System Information**:
echo - OS: Windows
echo - Ghidra Version: _____ ^(FILL IN AFTER OPENING GHIDRA^)
echo - GhidraGo Version: v1.1 Phase 2
echo - Binary Architecture: x64 ^(AMD64^)
echo.
echo **Binary Information**:
echo - Source: Hugo Static Site Generator
echo - Version: %HUGO_VER%
echo - Download URL: https://github.com/gohugoio/hugo/releases/tag/v0.151.0
echo - Binary Location: %HUGO_PATH%
echo.
echo ---
echo.
echo ## Phase 1: Import and Analysis
echo.
echo ### 1.1 Ghidra Import
echo - ^[ ^] Binary imported successfully
echo - ^[ ^] Format detected: PE ^(Portable Executable^)
echo - ^[ ^] Auto-analysis completed without errors
echo - ^[ ^] Analysis duration: _____ minutes
echo.
echo **Issues encountered**:
echo ```
echo ^(None / describe any issues^)
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
echo Phase 1 ^(Go Detection^): PASS / FAIL ^(circle one^)
echo Phase 2 ^(Function Recovery^): PASS / FAIL - _____ functions recovered
echo Phase 3 ^(Moduledata Location^): PASS / FAIL
echo Phase 4 ^(Typelinks Parsing^): PASS / FAIL - _____ type offsets
echo Phase 5 ^(Type Extraction^): PASS / FAIL - _____ types extracted
echo Phase 6 ^(Type Application^): PASS / FAIL - _____ types created
echo ```
echo.
echo **Script execution duration**: _____ seconds
echo.
echo **Errors/Warnings**: ^(Copy from console if any^)
echo ```
echo.
echo ```
echo.
echo ---
echo.
echo ## Phase 3: Type Extraction Validation
echo.
echo ### 3.1 Data Type Manager Check
echo - ^[ ^] Data Type Manager opened
echo - ^[ ^] Go types visible
echo - ^[ ^] Types organized by namespace
echo.
echo **Types Found**:
echo - Total types: _____ ^(FILL IN^)
echo - Sample types ^(list 5-10^):
echo   1. _____
echo   2. _____
echo   3. _____
echo   4. _____
echo   5. _____
echo.
echo ---
echo.
echo ## Screenshots
echo.
echo Save to: %CD%\..\test_results\hugo_test\screenshots\
echo.
echo Required screenshots:
echo 1. ^[ ^] console_output.png - All 6 phases complete
echo 2. ^[ ^] data_type_manager.png - Type tree with Go types
echo 3. ^[ ^] struct_example.png - Struct with visible fields
echo 4. ^[ ^] interface_example.png - Interface type
echo 5. ^[ ^] decompiler_view.png - Function with improved types
echo.
echo ---
echo.
echo ## Overall Assessment
echo.
echo **Success Rating**: ⭐⭐⭐⭐⭐ ^(circle 1-5 stars^)
echo.
echo **Status**:
echo - ^[ ^] ✅ Production Ready
echo - ^[ ^] ⚠️  Minor Issues
echo - ^[ ^] ❌ Needs Work
echo.
echo **Comments**:
echo ```
echo ^(Your overall impression, issues found, suggestions^)
echo.
echo.
echo ```
echo.
echo ---
echo.
echo **Report generated**: %DATE% %TIME%
echo **Next**: Fill in blanks above after testing
) > "%REPORT_FILE%"

echo [+] Report generated: %REPORT_FILE%
echo.
echo [+] STEP 3 COMPLETE - Report ready for your input
echo.
pause

REM =============================================================================
REM STEP 4: Open Documentation (AUTOMATED)
REM =============================================================================

echo.
echo  ========================================================================
echo    STEP 4/5: Opening Test Documentation
echo  ========================================================================
echo.

echo [*] Opening Quick Start Guide...
start QUICK_START_TESTING.md

timeout /t 2 /nobreak >nul

echo [*] Opening validation report...
start notepad "%REPORT_FILE%"

timeout /t 2 /nobreak >nul

echo [*] Opening screenshots directory...
start ..\test_results\hugo_test\screenshots

echo.
echo [+] STEP 4 COMPLETE - Documentation open
echo.
pause

REM =============================================================================
REM STEP 5: Display Testing Instructions (GUIDANCE)
REM =============================================================================

echo.
echo  ========================================================================
echo    STEP 5/5: Manual Testing Instructions
echo  ========================================================================
echo.
echo  AUTOMATION COMPLETE!
echo  Time saved so far: ~15 minutes
echo.
echo  ------------------------------------------------------------------------
echo  Now YOU must complete these steps in Ghidra:
echo  ------------------------------------------------------------------------
echo.
echo  1. OPEN GHIDRA
echo     - Launch Ghidra application
echo.
echo  2. CREATE/OPEN PROJECT
echo     - File -^> New Project
echo     - Type: Non-Shared Project
echo     - Name: GhidraGo_Phase2_Testing
echo     - Location: %CD%\ghidra_test_project
echo.
echo  3. IMPORT HUGO BINARY
echo     - File -^> Import File
echo     - Select: %CD%\prebuilt_binaries\hugo.exe
echo     - Format: Portable Executable ^(PE^)
echo     - Click OK, then YES to analyze
echo     - Wait ~3-5 minutes for analysis
echo.
echo  4. RUN GHIDRAGO SCRIPT
echo     - Window -^> Script Manager
echo     - Filter: RecoverGo
echo     - Double-click: RecoverGoFunctionsAndTypes.py
echo     - Watch console for 6 phases ^(~30 seconds^)
echo.
echo  5. VERIFY RESULTS
echo     - Window -^> Data Type Manager
echo     - Expand type tree
echo     - Find struct ^(e.g., main.Config, http.Request^)
echo     - Double-click to see fields
echo     - Check: Field names visible ^(not field_0, field_1^)
echo.
echo  6. CAPTURE SCREENSHOTS ^(5 total^)
echo     - Console output ^(all 6 phases^)
echo     - Data Type Manager ^(type tree^)
echo     - Struct with fields
echo     - Interface type
echo     - Decompiler view
echo     - Save to: %CD%\..\test_results\hugo_test\screenshots\
echo.
echo  7. FILL VALIDATION REPORT
echo     - Report already open in Notepad
echo     - Fill in: phase results, type counts, observations
echo     - Check all checkboxes
echo     - Add comments
echo.
echo  ------------------------------------------------------------------------
echo  Expected Results:
echo  ------------------------------------------------------------------------
echo    - Functions recovered: 5,000-10,000
echo    - Types extracted: 100-300
echo    - Script duration: 15-60 seconds
echo    - All 6 phases: PASS
echo.
echo  ------------------------------------------------------------------------
echo  Troubleshooting:
echo  ------------------------------------------------------------------------
echo    - "No types extracted" -^> Check Phase 3 ^(moduledata location^)
echo    - "Script hangs" -^> Wait 2-3 min, may be processing large binary
echo    - "Fields undefined" -^> Check Phase 6 output for errors
echo.
echo  ------------------------------------------------------------------------
echo  Files Ready for You:
echo  ------------------------------------------------------------------------
echo    Hugo binary: %CD%\prebuilt_binaries\hugo.exe
echo    Quick Start Guide: QUICK_START_TESTING.md ^(OPEN^)
echo    Validation Report: %REPORT_FILE% ^(OPEN^)
echo    Screenshots folder: ..\test_results\hugo_test\screenshots\ ^(OPEN^)
echo.
echo  ========================================================================
echo    GOOD LUCK! Phase 2 validation begins now!
echo  ========================================================================
echo.
echo  Estimated time remaining: 30-40 minutes
echo.

pause
