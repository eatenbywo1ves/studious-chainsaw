@echo off
REM Ghidra Launch Helper - Most Reliable Method
REM This script opens the Ghidra directory in Windows Explorer for manual launch

echo ================================================
echo           GHIDRA LAUNCH HELPER
echo ================================================
echo.
echo Due to console redirection issues, the most reliable
echo way to launch Ghidra is through Windows Explorer.
echo.
echo This will open the Ghidra directory where you can
echo double-click on ghidraRun.bat to start Ghidra.
echo.

set GHIDRA_DIR=C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC

if not exist "%GHIDRA_DIR%" (
    echo ERROR: Ghidra directory not found at:
    echo %GHIDRA_DIR%
    pause
    exit /b 1
)

echo Opening Ghidra directory in Windows Explorer...
echo Directory: %GHIDRA_DIR%
echo.
echo INSTRUCTIONS:
echo 1. Windows Explorer will open showing the Ghidra directory
echo 2. Double-click on "ghidraRun.bat" to launch Ghidra
echo 3. Wait for Ghidra to fully load (may take 30-60 seconds)
echo 4. Go to File ^> Configure ^> Extensions to enable:
echo    - CryptoDetect extension
echo    - RetSync extension
echo 5. Restart Ghidra to activate the extensions
echo.

pause

REM Open Windows Explorer at the Ghidra directory
explorer "%GHIDRA_DIR%"

echo.
echo Windows Explorer opened. Please double-click ghidraRun.bat
echo.
pause