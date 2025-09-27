@echo off
REM Test script to verify installation logic without actually installing

setlocal EnableDelayedExpansion

echo Testing Installation Logic...
echo =============================

REM Step 1: Check Ghidra installation
if "%GHIDRA_INSTALL_DIR%"=="" (
    echo GHIDRA_INSTALL_DIR environment variable not set
    echo.
    echo Searching for Ghidra installation...

    REM Search common locations - user directories first, then system directories
    echo Searching in user directories...

    REM Check user development directory
    for /d %%d in ("%USERPROFILE%\development\ghidra_*") do (
        echo Checking: %%d
        if exist "%%d\ghidraRun.bat" (
            set GHIDRA_INSTALL_DIR=%%d
            echo Found Ghidra at: %%d
            goto :found_ghidra
        )
    )

    echo Searching in system directories...
    REM Check system directories
    for /d %%d in ("C:\ghidra_*") do (
        echo Checking: %%d
        if exist "%%d\ghidraRun.bat" (
            set GHIDRA_INSTALL_DIR=%%d
            echo Found Ghidra at: %%d
            goto :found_ghidra
        )
    )

    echo.
    echo Could not find Ghidra installation automatically.
    goto :end
)

:found_ghidra
echo Using Ghidra installation: !GHIDRA_INSTALL_DIR!
echo.

REM Step 2: Detect Ghidra version
if exist "!GHIDRA_INSTALL_DIR!\Ghidra\application.properties" (
    for /f "tokens=2 delims==" %%v in ('findstr "application.version" "!GHIDRA_INSTALL_DIR!\Ghidra\application.properties"') do (
        set GHIDRA_VERSION=%%v
    )
) else (
    echo Warning: Could not detect Ghidra version
    set GHIDRA_VERSION=unknown
)

echo Detected Ghidra version: !GHIDRA_VERSION!
echo.

REM Step 3: Detect version suffix and create Extensions directory
echo Detecting Ghidra user directory...
set VERSION_SUFFIX=
set GHIDRA_BASE_DIR=%USERPROFILE%\.ghidra

REM Try different version suffixes in order of preference
for %%s in (_DEV _PUBLIC _build "") do (
    set "TEST_DIR=!GHIDRA_BASE_DIR!\.ghidra_!GHIDRA_VERSION!%%s"
    if exist "!TEST_DIR!" (
        set "VERSION_SUFFIX=%%s"
        echo Found existing directory: !TEST_DIR!
        goto :suffix_found
    )
)

:suffix_found
if "!VERSION_SUFFIX!"=="" (
    echo Using default _DEV suffix
    set VERSION_SUFFIX=_DEV
)

set "EXTENSIONS_DIR=!GHIDRA_BASE_DIR!\.ghidra_!GHIDRA_VERSION!!VERSION_SUFFIX!\Extensions"
echo Using extensions directory: !EXTENSIONS_DIR!

if exist "!EXTENSIONS_DIR!" (
    echo Extensions directory exists
) else (
    echo Extensions directory would be created
)

echo.
echo Test completed successfully!

:end
pause