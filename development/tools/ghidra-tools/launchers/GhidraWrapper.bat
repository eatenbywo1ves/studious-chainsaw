@echo off
REM Ultimate Ghidra Wrapper - Handles all edge cases

echo ================================================
echo              GHIDRA LAUNCHER
echo ================================================
echo.

set "GHIDRA_DIR=C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC"

REM Check if Ghidra exists
if not exist "%GHIDRA_DIR%" (
    echo ERROR: Ghidra not found at:
    echo %GHIDRA_DIR%
    echo.
    echo Please check the installation path.
    pause
    exit /b 1
)

if not exist "%GHIDRA_DIR%\ghidraRun.bat" (
    echo ERROR: ghidraRun.bat not found in:
    echo %GHIDRA_DIR%
    pause
    exit /b 1
)

echo Ghidra Directory: %GHIDRA_DIR%
echo.

REM Method 1: Try direct execution with proper environment
echo Attempting to launch Ghidra...
cd /d "%GHIDRA_DIR%"

REM Set JAVA_HOME if needed
if "%JAVA_HOME%"=="" (
    for /f "tokens=*" %%i in ('where java 2^>nul') do (
        set "JAVA_PATH=%%i"
        goto :found_java
    )
    echo WARNING: Java not found in PATH
    goto :try_anyway
)

:found_java
echo Using Java at: %JAVA_PATH%

:try_anyway
echo.
echo Starting Ghidra (this may take 30-60 seconds)...
echo Please wait for the GUI to appear...
echo.

REM Launch with start command to detach from this console
start "Ghidra" /D "%GHIDRA_DIR%" "%GHIDRA_DIR%\ghidraRun.bat"

REM Give it a moment to start
timeout /t 3 /nobreak >nul

echo.
echo Ghidra launch initiated.
echo.
echo If Ghidra doesn't appear within 2 minutes:
echo 1. Check for any error dialogs
echo 2. Try running as Administrator
echo 3. Check Windows Defender/Antivirus settings
echo.
echo Once Ghidra opens:
echo - Go to File ^> Configure ^> Extensions
echo - Enable CryptoDetect and RetSync extensions
echo - Restart Ghidra to activate extensions
echo.

pause