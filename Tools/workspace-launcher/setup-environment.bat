@echo off
REM Environment Setup and Validation Script
REM Ensures all dependencies are installed and configured

setlocal enabledelayedexpansion

cd /d C:\Users\Corbin

echo.
echo ============================================
echo    WORKSPACE ENVIRONMENT SETUP
echo ============================================
echo.

REM Check Python
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo   [X] Python is not installed
    set missing_deps=1
) else (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set pyver=%%i
    echo   [OK] Python !pyver! found
)

REM Check Node.js
echo Checking Node.js installation...
node --version >nul 2>&1
if errorlevel 1 (
    echo   [X] Node.js is not installed
    set missing_deps=1
) else (
    for /f %%i in ('node --version') do set nodever=%%i
    echo   [OK] Node.js !nodever! found
)

REM Check npm
echo Checking npm installation...
npm --version >nul 2>&1
if errorlevel 1 (
    echo   [X] npm is not installed
    set missing_deps=1
) else (
    for /f %%i in ('npm --version') do set npmver=%%i
    echo   [OK] npm !npmver! found
)

REM Check Git
echo Checking Git installation...
git --version >nul 2>&1
if errorlevel 1 (
    echo   [X] Git is not installed
    set missing_deps=1
) else (
    for /f "tokens=3" %%i in ('git --version') do set gitver=%%i
    echo   [OK] Git !gitver! found
)

REM Check Windows Terminal
echo Checking Windows Terminal...
where wt >nul 2>&1
if errorlevel 1 (
    echo   [!] Windows Terminal not found (optional)
) else (
    echo   [OK] Windows Terminal found
)

echo.
echo Checking Python packages...

REM Check Flask
python -c "import flask" 2>nul
if errorlevel 1 (
    echo   [X] Flask not installed
    echo       Installing Flask...
    pip install flask flask-cors
) else (
    echo   [OK] Flask installed
)

REM Check psutil
python -c "import psutil" 2>nul
if errorlevel 1 (
    echo   [X] psutil not installed
    echo       Installing psutil...
    pip install psutil
) else (
    echo   [OK] psutil installed
)

echo.
echo Setting up environment variables...

REM Set PYTHONPATH
set PYTHONPATH=C:\Users\Corbin\shared;C:\Users\Corbin\development\shared;%PYTHONPATH%
echo   [OK] PYTHONPATH configured

REM Create required directories
echo.
echo Creating required directories...

if not exist "Tools\workspace-launcher\logs" (
    mkdir "Tools\workspace-launcher\logs"
    echo   [OK] Created logs directory
)

if not exist "shared" (
    mkdir "shared"
    echo   [OK] Created shared directory
)

echo.
echo Checking project dependencies...

REM Check financial simulator
if exist "projects\financial-apps\financial-simulator\package.json" (
    echo   Checking financial-simulator dependencies...
    cd projects\financial-apps\financial-simulator

    if not exist "node_modules" (
        echo   [!] Installing npm packages for financial-simulator...
        call npm install
    ) else (
        echo   [OK] financial-simulator dependencies installed
    )
    cd /d C:\Users\Corbin
) else (
    echo   [!] Financial simulator not found
)

echo.
echo ============================================

if defined missing_deps (
    echo.
    echo [WARNING] Missing critical dependencies!
    echo Please install the missing components:
    echo.
    echo Python: https://www.python.org/downloads/
    echo Node.js: https://nodejs.org/
    echo Git: https://git-scm.com/
    echo.
) else (
    echo.
    echo [SUCCESS] Environment is ready!
    echo.
)

echo ============================================
echo.

REM Create a status file
echo Environment check completed: %date% %time% > Tools\workspace-launcher\logs\env-check.log
echo Python: !pyver! >> Tools\workspace-launcher\logs\env-check.log
echo Node: !nodever! >> Tools\workspace-launcher\logs\env-check.log
echo npm: !npmver! >> Tools\workspace-launcher\logs\env-check.log
echo Git: !gitver! >> Tools\workspace-launcher\logs\env-check.log

pause
exit /b 0