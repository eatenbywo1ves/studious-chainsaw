@echo off
REM Build script for GhidraGo Phase 2 test binaries
REM Compiles test programs for Windows and Linux (amd64)

echo ========================================
echo GhidraGo Phase 2 Test Binary Builder
echo ========================================
echo.

REM Check if Go is installed
where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Go compiler not found!
    echo Please install Go from https://golang.org/dl/
    exit /b 1
)

echo [*] Go compiler found:
go version
echo.

REM Create output directories
if not exist "windows_amd64" mkdir windows_amd64
if not exist "linux_amd64" mkdir linux_amd64

echo ========================================
echo Building Test Binaries
echo ========================================
echo.

REM Test 1: Simple structs
echo [*] Building test_structs_simple...
set GOOS=windows
set GOARCH=amd64
go build -o windows_amd64\test_structs_simple.exe test_structs_simple.go
set GOOS=linux
set GOARCH=amd64
go build -o linux_amd64\test_structs_simple test_structs_simple.go
echo [+] test_structs_simple complete

REM Test 2: Struct tags
echo [*] Building test_structs_tags...
set GOOS=windows
set GOARCH=amd64
go build -o windows_amd64\test_structs_tags.exe test_structs_tags.go
set GOOS=linux
set GOARCH=amd64
go build -o linux_amd64\test_structs_tags test_structs_tags.go
echo [+] test_structs_tags complete

REM Test 3: Embedded fields
echo [*] Building test_embedded_fields...
set GOOS=windows
set GOARCH=amd64
go build -o windows_amd64\test_embedded_fields.exe test_embedded_fields.go
set GOOS=linux
set GOARCH=amd64
go build -o linux_amd64\test_embedded_fields test_embedded_fields.go
echo [+] test_embedded_fields complete

REM Test 4: Interfaces
echo [*] Building test_interfaces...
set GOOS=windows
set GOARCH=amd64
go build -o windows_amd64\test_interfaces.exe test_interfaces.go
set GOOS=linux
set GOARCH=amd64
go build -o linux_amd64\test_interfaces test_interfaces.go
echo [+] test_interfaces complete

REM Test 5: Circular references
echo [*] Building test_circular_refs...
set GOOS=windows
set GOARCH=amd64
go build -o windows_amd64\test_circular_refs.exe test_circular_refs.go
set GOOS=linux
set GOARCH=amd64
go build -o linux_amd64\test_circular_refs test_circular_refs.go
echo [+] test_circular_refs complete

REM Test 6: Comprehensive test
echo [*] Building test_comprehensive...
set GOOS=windows
set GOARCH=amd64
go build -o windows_amd64\test_comprehensive.exe test_comprehensive.go
set GOOS=linux
set GOARCH=amd64
go build -o linux_amd64\test_comprehensive test_comprehensive.go
echo [+] test_comprehensive complete

echo.
echo ========================================
echo Build Summary
echo ========================================
echo.

REM Count files
set /a win_count=0
set /a linux_count=0

for %%f in (windows_amd64\*) do set /a win_count+=1
for %%f in (linux_amd64\*) do set /a linux_count+=1

echo [+] Windows binaries: %win_count%
echo [+] Linux binaries: %linux_count%
echo.

echo [*] Windows binaries (amd64):
dir /b windows_amd64
echo.

echo [*] Linux binaries (amd64):
dir /b linux_amd64
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Test these binaries with GhidraGo Phase 2:
echo   1. Load binary into Ghidra
echo   2. Run RecoverGoFunctionsAndTypes.py
echo   3. Check Data Type Manager for recovered types
echo   4. Verify struct fields, tags, and interface methods
echo.
echo Test binaries created:
echo   - test_structs_simple: Basic primitives, strings, pointers, slices, arrays
echo   - test_structs_tags: JSON tags, validation tags, multiple tag types
echo   - test_embedded_fields: Embedded fields, nested embedding, pointer embedding
echo   - test_interfaces: Simple/complex interfaces, embedded interfaces
echo   - test_circular_refs: Linked lists, trees, mutual references, graphs
echo   - test_comprehensive: All features combined in complex structures
echo.

pause
