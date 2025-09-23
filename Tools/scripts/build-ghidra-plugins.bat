@echo off
REM Automated Ghidra Plugin Build Script
REM This script builds all Ghidra plugins using their gradle wrappers

echo ========================================
echo Ghidra Plugin Automated Build System
echo ========================================
echo.

REM Set Ghidra installation directory
set GHIDRA_INSTALL_DIR=C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV
echo Ghidra Directory: %GHIDRA_INSTALL_DIR%
echo.

REM Create extensions directory
set EXTENSIONS_DIR=%USERPROFILE%\.ghidra\.ghidra_12.0_DEV\Extensions
if not exist "%EXTENSIONS_DIR%" (
    echo Creating Extensions directory...
    mkdir "%EXTENSIONS_DIR%"
)

REM Plugin directories
set PLUGIN_BASE=%USERPROFILE%\ghidra-plugins
cd /d %PLUGIN_BASE%

echo ========================================
echo Building Ghidrathon (Python 3 Support)
echo ========================================
if exist "%PLUGIN_BASE%\Ghidrathon" (
    cd /d "%PLUGIN_BASE%\Ghidrathon"
    if exist "gradlew.bat" (
        echo Building Ghidrathon...
        call gradlew.bat -PGHIDRA_INSTALL_DIR="%GHIDRA_INSTALL_DIR%" buildExtension
        if exist "dist\*.zip" (
            echo Copying Ghidrathon to Extensions...
            copy /Y dist\*.zip "%EXTENSIONS_DIR%\"
            echo SUCCESS: Ghidrathon built
        ) else (
            echo WARNING: Ghidrathon build may have failed
        )
    ) else (
        echo ERROR: gradlew.bat not found for Ghidrathon
    )
) else (
    echo SKIP: Ghidrathon not found
)
echo.

echo ========================================
echo Building Kaiju (Binary Analysis)
echo ========================================
if exist "%PLUGIN_BASE%\kaiju" (
    cd /d "%PLUGIN_BASE%\kaiju"
    if exist "gradlew.bat" (
        echo Building Kaiju...
        call gradlew.bat -PGHIDRA_INSTALL_DIR="%GHIDRA_INSTALL_DIR%" buildExtension
        if exist "dist\*.zip" (
            echo Copying Kaiju to Extensions...
            copy /Y dist\*.zip "%EXTENSIONS_DIR%\"
            echo SUCCESS: Kaiju built
        ) else (
            echo WARNING: Kaiju build may have failed
        )
    ) else (
        echo ERROR: gradlew.bat not found for Kaiju
    )
) else (
    echo SKIP: Kaiju not found
)
echo.

echo ========================================
echo Building C++ Class Analyzer
echo ========================================
if exist "%PLUGIN_BASE%\Ghidra-Cpp-Class-Analyzer" (
    cd /d "%PLUGIN_BASE%\Ghidra-Cpp-Class-Analyzer"
    if exist "gradlew.bat" (
        echo Building C++ Class Analyzer...
        call gradlew.bat -PGHIDRA_INSTALL_DIR="%GHIDRA_INSTALL_DIR%" buildExtension
        if exist "dist\*.zip" (
            echo Copying C++ Class Analyzer to Extensions...
            copy /Y dist\*.zip "%EXTENSIONS_DIR%\"
            echo SUCCESS: C++ Class Analyzer built
        ) else (
            echo WARNING: C++ Class Analyzer build may have failed
        )
    ) else (
        echo ERROR: gradlew.bat not found for C++ Class Analyzer
    )
) else (
    echo SKIP: C++ Class Analyzer not found
)
echo.

echo ========================================
echo Building ret-sync (Debugger Sync)
echo ========================================
if exist "%PLUGIN_BASE%\ret-sync\ext_ghidra" (
    cd /d "%PLUGIN_BASE%\ret-sync\ext_ghidra"
    if exist "gradlew.bat" (
        echo Building ret-sync...
        call gradlew.bat -PGHIDRA_INSTALL_DIR="%GHIDRA_INSTALL_DIR%" buildExtension
        if exist "dist\*.zip" (
            echo Copying ret-sync to Extensions...
            copy /Y dist\*.zip "%EXTENSIONS_DIR%\"
            echo SUCCESS: ret-sync built
        ) else (
            echo WARNING: ret-sync build may have failed
        )
    ) else (
        echo ERROR: gradlew.bat not found for ret-sync
    )
) else (
    echo SKIP: ret-sync not found
)
echo.

echo ========================================
echo Installing Script-Based Plugins
echo ========================================

REM GhidraEmu - Python scripts
if exist "%PLUGIN_BASE%\GhidraEmu" (
    echo Installing GhidraEmu scripts...
    if exist "%PLUGIN_BASE%\GhidraEmu\*.py" (
        copy /Y "%PLUGIN_BASE%\GhidraEmu\*.py" "%GHIDRA_INSTALL_DIR%\Ghidra\Features\Base\ghidra_scripts\"
        echo SUCCESS: GhidraEmu scripts installed
    )
) else (
    echo SKIP: GhidraEmu not found
)

REM LazyGhidra - Utility scripts
if exist "%PLUGIN_BASE%\LazyGhidra" (
    echo Installing LazyGhidra scripts...
    if exist "%PLUGIN_BASE%\LazyGhidra\ghidra_scripts" (
        xcopy /Y /E "%PLUGIN_BASE%\LazyGhidra\ghidra_scripts\*" "%GHIDRA_INSTALL_DIR%\Ghidra\Features\Base\ghidra_scripts\"
        echo SUCCESS: LazyGhidra scripts installed
    )
) else (
    echo SKIP: LazyGhidra not found
)
echo.

echo ========================================
echo Build Summary
echo ========================================
echo Extensions installed to: %EXTENSIONS_DIR%
echo Scripts installed to: %GHIDRA_INSTALL_DIR%\Ghidra\Features\Base\ghidra_scripts\
echo.
echo Next steps:
echo 1. Launch Ghidra
echo 2. Go to File - Install Extensions
echo 3. Select the plugins you want to enable
echo 4. Restart Ghidra
echo 5. For scripts: Window - Script Manager - Refresh
echo.
echo Build process complete!
pause