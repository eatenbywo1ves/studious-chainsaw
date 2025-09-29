@echo off
echo Testing Ghidra Launch...
echo ========================
echo.

echo Checking Java...
java -version
if %errorlevel% neq 0 (
    echo Java not found in PATH!
    pause
    exit /b 1
)

echo.
echo Checking Ghidra directory...
set GHIDRA_DIR=C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC
if not exist "%GHIDRA_DIR%" (
    echo Ghidra directory not found!
    pause
    exit /b 1
)

echo Ghidra directory exists: %GHIDRA_DIR%
echo.

echo Attempting to launch Ghidra...
cd /d "%GHIDRA_DIR%"

echo Current directory: %CD%
echo.

rem Try to launch with verbose output
echo Calling ghidraRun.bat...
call ghidraRun.bat

echo.
echo Press any key to exit...
pause