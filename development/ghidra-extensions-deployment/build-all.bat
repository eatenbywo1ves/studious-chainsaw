@echo off
REM Catalytic Computing - Ghidra Extensions Build Script (Windows)

echo Catalytic Computing - Ghidra Extensions Build System
echo =====================================================

set BUILD_VERSION=1.0.0
set GHIDRA_VERSION=11.4.2

if "%GHIDRA_INSTALL_DIR%"=="" (
    echo ERROR: GHIDRA_INSTALL_DIR environment variable not set!
    echo Please set it to your Ghidra installation directory.
    echo Example: set GHIDRA_INSTALL_DIR=C:\ghidra_11.4.2_PUBLIC
    pause
    exit /b 1
)

echo Using Ghidra installation: %GHIDRA_INSTALL_DIR%
echo Build Version: %BUILD_VERSION%
echo Target Ghidra Version: %GHIDRA_VERSION%
echo.

REM Create output directories
set OUTPUT_DIR=build\catalytic-ghidra-extensions
set DIST_DIR=%OUTPUT_DIR%\dist
set DOCS_DIR=%OUTPUT_DIR%\docs

if exist build rmdir /s /q build
mkdir "%OUTPUT_DIR%" 2>nul
mkdir "%DIST_DIR%" 2>nul
mkdir "%DOCS_DIR%" 2>nul

echo Building all Ghidra extensions...
echo.

REM Build GhidraCtrlP
echo [1/4] Building GhidraCtrlP...
cd ..\GhidraCtrlP
if exist gradlew.bat (
    call gradlew.bat clean build
) else (
    echo Using manual packaging for GhidraCtrlP...
    mkdir "..\ghidra-extensions-deployment\%DIST_DIR%\GhidraCtrlP" 2>nul
    
    REM Create extension package manually since it's script-based
    set CTRL_TEMP=..\ghidra-extensions-deployment\build\temp\GhidraCtrlP
    mkdir "%CTRL_TEMP%" 2>nul
    
    xcopy /y /s ghidra_scripts "%CTRL_TEMP%\ghidra_scripts\"
    xcopy /y /s docs "%CTRL_TEMP%\docs\" 2>nul
    xcopy /y /s data "%CTRL_TEMP%\data\" 2>nul
    copy /y README.md "%CTRL_TEMP%\"
    copy /y extension.properties "%CTRL_TEMP%\"
    copy /y Module.manifest "%CTRL_TEMP%\"
    
    REM Create ZIP package
    powershell -Command "Compress-Archive -Path '%CTRL_TEMP%\*' -DestinationPath '..\ghidra-extensions-deployment\%DIST_DIR%\GhidraCtrlP\ghidra_%GHIDRA_VERSION%_PUBLIC_%date:~10,4%%date:~4,2%%date:~7,2%_GhidraCtrlP.zip' -Force"
)

REM Build GhidraLookup
echo [2/4] Building GhidraLookup...
cd ..\GhidraLookup
if exist dist (
    mkdir "..\ghidra-extensions-deployment\%DIST_DIR%\GhidraLookup" 2>nul
    copy /y dist\*.zip "..\ghidra-extensions-deployment\%DIST_DIR%\GhidraLookup\"
    copy /y README.md "..\ghidra-extensions-deployment\%DOCS_DIR%\GhidraLookup-README.md"
    echo GhidraLookup: Using existing build
) else (
    echo GhidraLookup: No distribution found - skipping
)

REM Build GhidrAssist  
echo [3/4] Building GhidrAssist...
cd ..\GhidrAssist
if exist dist (
    mkdir "..\ghidra-extensions-deployment\%DIST_DIR%\GhidrAssist" 2>nul
    copy /y dist\*.zip "..\ghidra-extensions-deployment\%DIST_DIR%\GhidrAssist\"
    copy /y README.md "..\ghidra-extensions-deployment\%DOCS_DIR%\GhidrAssist-README.md"
    echo GhidrAssist: Using existing build
) else (
    echo GhidrAssist: No distribution found - skipping
)

REM Build Ghidrathon
echo [4/4] Building Ghidrathon...
cd ..\Ghidrathon
if exist dist (
    mkdir "..\ghidra-extensions-deployment\%DIST_DIR%\Ghidrathon" 2>nul
    copy /y dist\*.zip "..\ghidra-extensions-deployment\%DIST_DIR%\Ghidrathon\"
    copy /y README.md "..\ghidra-extensions-deployment\%DOCS_DIR%\Ghidrathon-README.md"
    echo Ghidrathon: Using existing build
) else (
    echo Ghidrathon: No distribution found - skipping
)

cd ..\ghidra-extensions-deployment

echo.
echo Generating documentation...
call :GenerateMasterDoc > "%DOCS_DIR%\README.md"
call :GenerateInstallGuide > "%DOCS_DIR%\INSTALLATION_GUIDE.md"

echo.
echo Creating master distribution package...
set MASTER_ZIP=build\CatalyticComputing-GhidraExtensions-%BUILD_VERSION%.zip
powershell -Command "Compress-Archive -Path '%OUTPUT_DIR%\*' -DestinationPath '%MASTER_ZIP%' -Force"

echo.
echo =====================================================
echo BUILD COMPLETED SUCCESSFULLY!
echo =====================================================
echo Output directory: %OUTPUT_DIR%
echo Master package: %MASTER_ZIP%

for /f %%A in ('dir /b "%DIST_DIR%" 2^>nul ^| find /c /v ""') do set EXTENSION_COUNT=%%A
echo Extensions packaged: %EXTENSION_COUNT%

echo.
echo To install extensions:
echo 1. Set GHIDRA_INSTALL_DIR environment variable
echo 2. Run: build-all.bat install
echo 3. Or manually copy ZIP files to Ghidra/Extensions/Ghidra/
echo.

if "%1"=="install" goto :InstallExtensions
goto :EOF

:InstallExtensions
echo Installing extensions to Ghidra...
set GHIDRA_EXT_DIR=%GHIDRA_INSTALL_DIR%\Extensions\Ghidra

if not exist "%GHIDRA_EXT_DIR%" (
    echo ERROR: Ghidra extensions directory not found: %GHIDRA_EXT_DIR%
    echo Please verify GHIDRA_INSTALL_DIR is correct.
    pause
    exit /b 1
)

echo Copying extensions to: %GHIDRA_EXT_DIR%
for /r "%DIST_DIR%" %%f in (*.zip) do (
    copy /y "%%f" "%GHIDRA_EXT_DIR%\"
    echo Installed: %%~nxf
)

echo.
echo Extensions installed successfully!
echo Please restart Ghidra and use File ^> Install Extensions to enable them.
goto :EOF

:GenerateMasterDoc
echo # Catalytic Computing - Ghidra Extensions Suite
echo.
echo A comprehensive collection of professional Ghidra extensions designed to enhance reverse engineering workflows.
echo.
echo ## Version Information
echo - **Suite Version**: %BUILD_VERSION%
echo - **Target Ghidra Version**: %GHIDRA_VERSION% 
echo - **Build Date**: %DATE% %TIME%
echo.
echo ## Extensions Overview
echo.
echo ### GhidraCtrlP
echo Fast navigation and command palette for Ghidra - VS Code style Ctrl+P functionality
echo.
echo ### GhidraLookup  
echo Win32 API documentation lookup functionality with automatic constant analysis
echo.
echo ### GhidrAssist
echo AI-assisted reverse engineering with LLM integration and automation features
echo.
echo ### Ghidrathon
echo Python 3 integration for Ghidra scripting with modern library support
echo.
echo ## Installation
echo.
echo See INSTALLATION_GUIDE.md for detailed setup instructions.
echo.
echo ## Support
echo.
echo For issues and support, refer to individual extension documentation.
goto :EOF

:GenerateInstallGuide
echo # Installation Guide - Catalytic Computing Ghidra Extensions
echo.
echo ## Prerequisites
echo - Ghidra %GHIDRA_VERSION% or later
echo - Java 17 or later
echo - Python 3.8+ ^(for Ghidrathon^)
echo.
echo ## Quick Install
echo.
echo 1. Set GHIDRA_INSTALL_DIR environment variable:
echo    ```
echo    set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
echo    ```
echo.
echo 2. Run the installer:
echo    ```
echo    build-all.bat install
echo    ```
echo.
echo 3. Start Ghidra and enable extensions via File ^> Install Extensions
echo.
echo ## Manual Installation
echo.
echo 1. Copy ZIP files from dist\ directory to:
echo    GHIDRA_INSTALL_DIR\Extensions\Ghidra\
echo.
echo 2. Restart Ghidra
echo.
echo 3. Go to File ^> Install Extensions and select the ZIP files
echo.
echo ## Extension Configuration
echo.
echo - **GhidraCtrlP**: Add keyboard shortcut ^(Ctrl+P recommended^)
echo - **GhidraLookup**: Enable in File ^> Configure ^> Miscellaneous
echo - **GhidrAssist**: Configure API keys in Tools ^> GhidrAssist Settings
echo - **Ghidrathon**: Run python ghidrathon_configure.py after installation
goto :EOF