@echo off
REM
REM Smoke Test Runner (Windows)
REM Runs all production smoke tests and reports results
REM

setlocal enabledelayedexpansion

REM Configuration
if not defined PRODUCTION_URL (
    set PRODUCTION_URL=http://localhost:8000
)

set SCRIPT_DIR=%~dp0
set RESULTS_DIR=%SCRIPT_DIR%results
set TIMESTAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%

echo ==============================================================================
echo                     PRODUCTION SMOKE TEST RUNNER
echo ==============================================================================
echo Target URL: %PRODUCTION_URL%
echo Timestamp: %TIMESTAMP%
echo ==============================================================================

REM Create results directory
if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"

REM Check if production URL is accessible
echo.
echo [1/4] Checking production URL accessibility...
curl -s -o nul -w "%%{http_code}" "%PRODUCTION_URL%/health" > temp_response.txt 2>nul
set /p HTTP_CODE=<temp_response.txt
del temp_response.txt 2>nul

if "%HTTP_CODE%"=="200" (
    echo [32m✓[0m Production URL is accessible
) else if "%HTTP_CODE%"=="404" (
    echo [32m✓[0m Production URL is accessible
) else (
    echo [31m✗[0m Production URL is not accessible: %PRODUCTION_URL%
    echo Please verify the PRODUCTION_URL environment variable is set correctly.
    exit /b 1
)

REM Check Python and dependencies
echo.
echo [2/4] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo [31m✗[0m Python is not installed
    exit /b 1
)

python -c "import pytest" >nul 2>&1
if errorlevel 1 (
    echo [33m⚠[0m pytest not found, installing...
    pip install pytest requests -q
)

python -c "import requests" >nul 2>&1
if errorlevel 1 (
    echo [33m⚠[0m requests not found, installing...
    pip install requests -q
)

echo [32m✓[0m Python environment ready

REM Run health check tests
echo.
echo [3/4] Running health check smoke tests...
set HEALTH_RESULTS=%RESULTS_DIR%\health_%TIMESTAMP%.xml

python -m pytest "%SCRIPT_DIR%test_production_health.py" ^
    --junitxml="%HEALTH_RESULTS%" ^
    -v ^
    --tb=short ^
    --color=yes

if errorlevel 1 (
    echo [31m✗[0m Health check tests FAILED
    set HEALTH_STATUS=FAIL
) else (
    echo [32m✓[0m Health check tests PASSED
    set HEALTH_STATUS=PASS
)

REM Run critical workflow tests
echo.
echo [4/4] Running critical workflow smoke tests...
set WORKFLOW_RESULTS=%RESULTS_DIR%\workflows_%TIMESTAMP%.xml

python -m pytest "%SCRIPT_DIR%test_critical_workflows.py" ^
    --junitxml="%WORKFLOW_RESULTS%" ^
    -v ^
    --tb=short ^
    --color=yes

if errorlevel 1 (
    echo [31m✗[0m Workflow tests FAILED
    set WORKFLOW_STATUS=FAIL
) else (
    echo [32m✓[0m Workflow tests PASSED
    set WORKFLOW_STATUS=PASS
)

REM Generate summary report
echo.
echo ==============================================================================
echo                            SMOKE TEST SUMMARY
echo ==============================================================================
echo Health Checks:        %HEALTH_STATUS%
echo Critical Workflows:   %WORKFLOW_STATUS%
echo ==============================================================================

REM Save summary to file
set SUMMARY_FILE=%RESULTS_DIR%\summary_%TIMESTAMP%.txt

(
    echo SMOKE TEST SUMMARY
    echo ==================
    echo Timestamp: %TIMESTAMP%
    echo Production URL: %PRODUCTION_URL%
    echo.
    echo Results:
    echo --------
    echo Health Checks:        %HEALTH_STATUS%
    echo Critical Workflows:   %WORKFLOW_STATUS%
    echo.
    echo Test Results Location:
    echo ----------------------
    echo Health Check Results:  %HEALTH_RESULTS%
    echo Workflow Results:      %WORKFLOW_RESULTS%
    echo Summary:               %SUMMARY_FILE%
    echo.
) > "%SUMMARY_FILE%"

echo.
echo Results saved to: %RESULTS_DIR%
echo Summary: %SUMMARY_FILE%

REM Exit with appropriate code
if "%HEALTH_STATUS%"=="PASS" if "%WORKFLOW_STATUS%"=="PASS" (
    echo.
    echo [32m✓ ALL SMOKE TESTS PASSED[0m
    exit /b 0
) else (
    echo.
    echo [31m✗ SOME SMOKE TESTS FAILED[0m
    echo Please review the test results before proceeding with deployment.
    exit /b 1
)
