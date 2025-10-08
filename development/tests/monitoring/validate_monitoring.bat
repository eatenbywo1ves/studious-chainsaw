@echo off
REM ============================================================================
REM Automated Monitoring Validation Script (Windows)
REM
REM This script runs all monitoring validation tests to ensure the monitoring
REM infrastructure is working correctly.
REM ============================================================================

echo ============================================================================
echo CATALYTIC SAAS - MONITORING VALIDATION
echo ============================================================================
echo.

REM Set working directory
cd /d "%~dp0"

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    exit /b 1
)

REM Check if pytest is installed
python -c "import pytest" >nul 2>&1
if errorlevel 1 (
    echo Installing pytest...
    pip install pytest requests >nul 2>&1
)

echo [1/4] Testing Prometheus scraping...
echo.
python test_prometheus_scraping.py
if errorlevel 1 (
    echo FAILED: Prometheus scraping validation failed
    set TEST_FAILED=1
) else (
    echo PASSED: Prometheus scraping validation
)
echo.

echo [2/4] Testing Grafana dashboards...
echo.
python test_grafana_dashboards.py
if errorlevel 1 (
    echo FAILED: Grafana dashboard validation failed
    set TEST_FAILED=1
) else (
    echo PASSED: Grafana dashboard validation
)
echo.

echo [3/4] Testing alert rules...
echo.
python test_alert_rules.py
if errorlevel 1 (
    echo FAILED: Alert rules validation failed
    set TEST_FAILED=1
) else (
    echo PASSED: Alert rules validation
)
echo.

echo [4/4] Running pytest suite...
echo.
pytest -v --tb=short
if errorlevel 1 (
    echo FAILED: Pytest suite validation failed
    set TEST_FAILED=1
) else (
    echo PASSED: Pytest suite validation
)
echo.

echo ============================================================================
if defined TEST_FAILED (
    echo RESULT: SOME VALIDATIONS FAILED
    echo ============================================================================
    exit /b 1
) else (
    echo RESULT: ALL VALIDATIONS PASSED
    echo ============================================================================
    exit /b 0
)
