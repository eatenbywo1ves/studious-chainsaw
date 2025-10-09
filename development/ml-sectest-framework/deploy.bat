@echo off
REM ML-SecTest Framework - Windows Deployment Script
REM ================================================

echo.
echo ============================================================
echo ML-SecTest Framework - Deployment Script
echo ============================================================
echo.

REM Set UTF-8 encoding for console
chcp 65001 >nul

REM Check if virtual environment exists
if not exist venv\ (
    echo [STEP 1/5] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        exit /b 1
    )
    echo [OK] Virtual environment created
) else (
    echo [STEP 1/5] Virtual environment already exists
)

echo.
echo [STEP 2/5] Upgrading pip...
venv\Scripts\python.exe -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo [ERROR] Failed to upgrade pip
    exit /b 1
)
echo [OK] Pip upgraded successfully

echo.
echo [STEP 3/5] Installing dependencies...
venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    exit /b 1
)
echo [OK] Dependencies installed

echo.
echo [STEP 4/5] Validating installation...
venv\Scripts\python.exe -c "from core import SecurityOrchestrator; from agents import PromptInjectionAgent; from utils import ReportGenerator" 2>nul
if errorlevel 1 (
    echo [ERROR] Framework validation failed
    exit /b 1
)
echo [OK] Framework validated

echo.
echo [STEP 5/5] Testing CLI...
venv\Scripts\python.exe ml_sectest.py --help >nul 2>&1
if errorlevel 1 (
    echo [WARNING] CLI test had issues (may be encoding-related)
) else (
    echo [OK] CLI functional
)

echo.
echo ============================================================
echo Deployment Complete!
echo ============================================================
echo.
echo To use the framework:
echo   1. Activate environment: venv\Scripts\activate
echo   2. List challenges: python ml_sectest.py list-challenges
echo   3. Scan target: python ml_sectest.py scan http://localhost:8000
echo.
echo Environment: %CD%
echo Python: 
venv\Scripts\python.exe --version
echo.
pause
