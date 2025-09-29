@echo off
REM Ghidra Robust Launcher - Handles console redirection issues
REM This wrapper script ensures Ghidra launches properly

setlocal EnableDelayedExpansion

REM Set the Ghidra directory
set "GHIDRA_DIR=C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC"

REM Check if Ghidra directory exists
if not exist "%GHIDRA_DIR%" (
    echo ERROR: Ghidra not found at %GHIDRA_DIR%
    pause
    exit /b 1
)

REM Check if ghidraRun.bat exists
if not exist "%GHIDRA_DIR%\ghidraRun.bat" (
    echo ERROR: ghidraRun.bat not found
    pause
    exit /b 1
)

echo Starting Ghidra...
echo Directory: %GHIDRA_DIR%
echo.

REM Change to Ghidra directory
cd /d "%GHIDRA_DIR%"

REM Launch Ghidra with proper console handling
REM Use 'start' command to launch in separate process
start "Ghidra" /D "%GHIDRA_DIR%" "%GHIDRA_DIR%\ghidraRun.bat"

REM Check if the process started
timeout /t 2 /nobreak >nul
echo Ghidra launch initiated...

REM Exit this launcher
exit /b 0