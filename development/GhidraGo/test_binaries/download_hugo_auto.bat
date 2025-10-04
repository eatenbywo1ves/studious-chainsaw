@echo off
REM Automated Hugo Download for GhidraGo Testing
REM Fully automated - no user interaction required

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
echo [*] Target: %CD%\%HUGO_ZIP%
echo.

REM Check if already downloaded
if exist "hugo.exe" (
    echo [!] Hugo already exists!
    echo [*] Current version:
    hugo.exe version
    echo.
    choice /C YN /M "Re-download anyway"
    if errorlevel 2 (
        echo [*] Using existing hugo.exe
        cd ..
        exit /b 0
    )
    echo [*] Removing old version...
    del hugo.exe
)

REM Download using PowerShell (built-in on Windows 10/11)
echo [*] Starting download (this may take 1-2 minutes)...
powershell -Command "& {$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%HUGO_URL%' -OutFile '%HUGO_ZIP%' -ErrorAction Stop}" 2>download_error.txt

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Download failed!
    echo [!] Error details:
    type download_error.txt
    echo.
    echo [!] Possible solutions:
    echo     1. Check internet connection
    echo     2. Manual download: %HUGO_URL%
    echo     3. Try alternative binary (Docker, Kubectl)
    echo.
    cd ..
    exit /b 1
)

echo [+] Download successful! (%HUGO_ZIP%)
echo.

REM Extract using PowerShell
echo [*] Extracting hugo.exe...
powershell -Command "& {Expand-Archive -Path '%HUGO_ZIP%' -DestinationPath '.' -Force -ErrorAction Stop}" 2>extract_error.txt

if %ERRORLEVEL% NEQ 0 (
    echo [!] Extraction failed!
    type extract_error.txt
    cd ..
    exit /b 1
)

if not exist "hugo.exe" (
    echo [!] Extraction succeeded but hugo.exe not found!
    echo [!] Zip contents:
    powershell -Command "& {Get-ChildItem}"
    cd ..
    exit /b 1
)

echo [+] Extraction successful!
echo.

REM Verify binary
echo [*] Verifying Hugo installation...
hugo.exe version
echo.

REM Get binary size
for %%I in (hugo.exe) do (
    set /a SIZE_MB=%%~zI / 1024 / 1024
    echo [*] Binary size: %%~zI bytes (~!SIZE_MB! MB)
)
echo [*] Binary location: %CD%\hugo.exe
echo.

REM Clean up zip
echo [*] Cleaning up...
del "%HUGO_ZIP%" 2>nul
del download_error.txt 2>nul
del extract_error.txt 2>nul

echo [+] Hugo ready for testing!
echo.
echo ========================================
echo Next Steps:
echo ========================================
echo 1. Open Ghidra
echo 2. Import: %CD%\hugo.exe
echo 3. Run: RecoverGoFunctionsAndTypes.py
echo 4. Follow: QUICK_START_TESTING.md
echo.
echo Or run: run_complete_test.bat for guided testing
echo.

cd ..
pause
