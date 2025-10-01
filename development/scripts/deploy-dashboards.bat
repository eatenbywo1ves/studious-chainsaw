@echo off
REM Grafana Dashboard Deployment Script for Windows
REM Catalytic Computing Platform

echo ========================================
echo Catalytic Computing - Grafana Dashboard Deployment
echo ========================================

REM Set default values
set GRAFANA_URL=http://localhost:3000
set DASHBOARDS_DIR=monitoring\grafana\dashboards
set SCRIPT_DIR=%~dp0

REM Check if API key is provided
if "%GRAFANA_API_KEY%"=="" (
    echo Error: GRAFANA_API_KEY environment variable is not set
    echo Please set it using: set GRAFANA_API_KEY=your_api_key_here
    pause
    exit /b 1
)

echo Using Grafana URL: %GRAFANA_URL%
echo Using Dashboards Directory: %DASHBOARDS_DIR%
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Install required Python packages
echo Installing required Python packages...
pip install requests pathlib >nul 2>&1

REM Run the deployment script
echo.
echo Starting dashboard deployment...
python "%SCRIPT_DIR%deploy-grafana-dashboards.py" --grafana-url %GRAFANA_URL% --api-key %GRAFANA_API_KEY% --dashboards-dir %DASHBOARDS_DIR%

if errorlevel 1 (
    echo.
    echo Deployment failed! Check the logs for details.
    pause
    exit /b 1
) else (
    echo.
    echo ✅ Dashboard deployment completed successfully!
    echo.
    echo You can now access your dashboards at:
    echo %GRAFANA_URL%/dashboards
)

echo.
pause