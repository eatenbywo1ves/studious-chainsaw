@echo off
echo ====================================
echo     Starting Ghidra from Source
echo ====================================
echo.

:: Set the Ghidra directory
set GHIDRA_DIR=C:\Users\Corbin\development\ghidra

:: Check if Java is available
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Java is not installed or not in PATH
    echo Please install Java JDK 21 or higher
    echo.
    echo Install with: winget install Microsoft.OpenJDK.21
    pause
    exit /b 1
)

echo Launching Ghidra...
echo.

:: Change to Ghidra runtime scripts directory
cd /d "%GHIDRA_DIR%\Ghidra\RuntimeScripts\Windows"

:: Run Ghidra
call ghidraRun.bat %*

:: Keep window open if there was an error
if %errorlevel% neq 0 (
    echo.
    echo Ghidra exited with an error.
    pause
)