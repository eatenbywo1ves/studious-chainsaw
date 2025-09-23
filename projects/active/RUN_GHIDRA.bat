@echo off
title Ghidra Launcher
color 0A

echo ============================================
echo           GHIDRA LAUNCHER
echo ============================================
echo.

:: Try to run from source first
if exist "C:\Users\Corbin\development\ghidra\Ghidra\RuntimeScripts\Windows\ghidraRun.bat" (
    echo Found Ghidra source installation
    echo Launching from: C:\Users\Corbin\development\ghidra
    echo.
    cd /d "C:\Users\Corbin\development\ghidra\Ghidra\RuntimeScripts\Windows"
    start "" ghidraRun.bat
    echo.
    echo Ghidra is starting in a new window...
    timeout /t 3
    exit
)

:: Try pre-built version if exists
if exist "C:\Users\Corbin\development\ghidra_11.2_PUBLIC\ghidraRun.bat" (
    echo Found pre-built Ghidra installation
    echo Launching from: C:\Users\Corbin\development\ghidra_11.2_PUBLIC
    echo.
    cd /d "C:\Users\Corbin\development\ghidra_11.2_PUBLIC"
    start "" ghidraRun.bat
    echo.
    echo Ghidra is starting in a new window...
    timeout /t 3
    exit
)

echo ============================================
echo         GHIDRA NOT FOUND
echo ============================================
echo.
echo Please install Ghidra first:
echo.
echo Option 1: Run the Python script
echo   python C:\Users\Corbin\development\download_ghidra_direct.py
echo.
echo Option 2: Download manually
echo   https://github.com/NationalSecurityAgency/ghidra/releases
echo   Extract to: C:\Users\Corbin\development\
echo.
echo Option 3: Build from source
echo   cd C:\Users\Corbin\development\ghidra
echo   gradlew.bat buildGhidra
echo.
pause