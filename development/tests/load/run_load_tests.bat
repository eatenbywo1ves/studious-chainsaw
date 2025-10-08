@echo off
REM ============================================================================
REM Load Testing Runner - Windows Batch Script
REM Catalytic Computing SaaS Platform
REM ============================================================================

echo.
echo ===============================================================================
echo CATALYTIC COMPUTING SAAS - LOAD TESTING RUNNER (Windows)
echo ===============================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    exit /b 1
)

REM Check if Locust is installed
python -c "import locust" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Locust is not installed
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        exit /b 1
    )
)

REM Default configuration
set HOST=http://localhost:8000
set SCENARIO=all

REM Parse command line arguments
if not "%1"=="" set SCENARIO=%1
if not "%2"=="" set HOST=%2

echo Starting load tests...
echo Host: %HOST%
echo Scenario: %SCENARIO%
echo.

REM Run the test runner
python run_load_tests.py --host %HOST% --scenario %SCENARIO%

if errorlevel 1 (
    echo.
    echo ERROR: Load tests failed
    exit /b 1
)

echo.
echo ===============================================================================
echo Load testing complete! Check the results/ directory for reports.
echo ===============================================================================
echo.

pause
