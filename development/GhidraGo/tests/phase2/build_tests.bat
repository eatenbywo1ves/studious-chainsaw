@echo off
REM Build script for Phase 2 test binaries
REM Requires: Go 1.16+ installed

echo ======================================================================
echo GhidraGo Phase 2 Test Binary Builder
echo ======================================================================

REM Check if Go is installed
where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Go compiler not found. Please install Go from https://go.dev/dl/
    echo [!] Add Go to PATH and run this script again.
    pause
    exit /b 1
)

echo [*] Go compiler found
go version

REM Create output directory
if not exist "binaries" mkdir binaries

echo.
echo ======================================================================
echo Building Test Binaries
echo ======================================================================

REM Test 1: Basic Struct
echo [*] Building test_basic_struct.exe...
go build -o binaries\test_basic_struct.exe test_basic_struct.go
if %ERRORLEVEL% EQU 0 (
    echo [+] test_basic_struct.exe created
) else (
    echo [!] Failed to build test_basic_struct.exe
)

REM Test 2: Interface
echo [*] Building test_interface.exe...
go build -o binaries\test_interface.exe test_interface.go
if %ERRORLEVEL% EQU 0 (
    echo [+] test_interface.exe created
) else (
    echo [!] Failed to build test_interface.exe
)

REM Test 3: Nested Types
echo [*] Building test_nested_types.exe...
go build -o binaries\test_nested_types.exe test_nested_types.go
if %ERRORLEVEL% EQU 0 (
    echo [+] test_nested_types.exe created
) else (
    echo [!] Failed to build test_nested_types.exe
)

REM Test 4: Embedded Fields
echo [*] Building test_embedded_fields.exe...
go build -o binaries\test_embedded_fields.exe test_embedded_fields.go
if %ERRORLEVEL% EQU 0 (
    echo [+] test_embedded_fields.exe created
) else (
    echo [!] Failed to build test_embedded_fields.exe
)

echo.
echo ======================================================================
echo Build Summary
echo ======================================================================
echo Test binaries created in: binaries\
dir /B binaries\*.exe 2>nul
echo.
echo To test Phase 2 enhancements:
echo 1. Open Ghidra
echo 2. Import a test binary (e.g., binaries\test_basic_struct.exe)
echo 3. Analyze with default analyzers
echo 4. Run Script Manager ^> RecoverGoFunctionsAndTypes.py
echo 5. Check Data Type Manager for recovered structs with fields
echo.
pause
