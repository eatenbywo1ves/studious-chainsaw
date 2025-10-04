@echo off
REM Download pre-built Go binary for GhidraGo Phase 2 testing
REM Since Go compiler is not installed, we'll use an existing Go binary
REM Hugo is a good choice: ~20MB, actively maintained, rich type information

echo ========================================
echo GhidraGo Phase 2 - Download Test Binary
echo ========================================
echo.

echo [*] This script will download Hugo (Go static site generator)
echo [*] Hugo is written in Go and contains rich type information
echo [*] Perfect for testing GhidraGo Phase 2 type extraction
echo.

REM Create download directory
if not exist "prebuit_binaries" mkdir prebuilt_binaries
cd prebuilt_binaries

echo [*] Hugo Download Options:
echo.
echo 1. Manual Download (Recommended)
echo    - Visit: https://github.com/gohugoio/hugo/releases
echo    - Download: hugo_extended_X.X.X_windows-amd64.zip
echo    - Extract hugo.exe to: C:\Users\Corbin\development\GhidraGo\test_binaries\prebuilt_binaries\
echo.
echo 2. Alternative: Docker CLI
echo    - Visit: https://download.docker.com/win/static/stable/x86_64/
echo    - Download: docker-XX.XX.X.zip
echo    - Extract docker.exe
echo.
echo 3. Alternative: Kubectl
echo    - Visit: https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/
echo    - Download kubectl.exe directly
echo.

echo ========================================
echo Next Steps After Download:
echo ========================================
echo.
echo 1. Place downloaded .exe in: prebuilt_binaries\
echo 2. Verify binary: hugo.exe version (or docker.exe --version)
echo 3. Import to Ghidra for testing
echo 4. Run RecoverGoFunctionsAndTypes.py
echo.

echo [*] Would you like to open the Hugo releases page in your browser?
echo Press any key to open browser, or Ctrl+C to cancel...
pause >nul

start https://github.com/gohugoio/hugo/releases/latest

echo.
echo [+] Browser opened to Hugo releases page
echo [*] Download hugo_extended_*_windows-amd64.zip
echo [*] Extract hugo.exe to this directory
echo.

pause
