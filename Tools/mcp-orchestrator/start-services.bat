@echo off
REM Start all MCP services with orchestrator
REM Windows batch script for launching MCP server infrastructure

echo ========================================
echo     MCP Services Startup Script
echo ========================================
echo.

cd /d C:\Users\Corbin

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check for required Python packages
echo Checking dependencies...
pip show psutil >nul 2>&1
if errorlevel 1 (
    echo Installing psutil...
    pip install psutil
)

pip show flask >nul 2>&1
if errorlevel 1 (
    echo Installing Flask...
    pip install flask flask-cors
)

echo.
echo Starting MCP Orchestrator...
echo ========================================

REM Start orchestrator in monitor mode
start "MCP Orchestrator" cmd /k "python Tools\mcp-orchestrator\mcp_orchestrator.py monitor"

echo.
echo Waiting for orchestrator to initialize...
timeout /t 5 /nobreak >nul

echo.
echo Would you like to start the web dashboard? (Y/N)
choice /c YN /n /m "Start Dashboard: "

if %errorlevel%==1 (
    echo Starting Dashboard at http://localhost:5000
    start "MCP Dashboard" cmd /k "python Tools\mcp-orchestrator\dashboard.py"
    timeout /t 3 /nobreak >nul
    start http://localhost:5000
)

echo.
echo ========================================
echo All services started successfully!
echo.
echo Orchestrator: Running in monitor mode
if %errorlevel%==1 (
    echo Dashboard: http://localhost:5000
)
echo.
echo Press any key to view status...
pause >nul

python Tools\mcp-orchestrator\mcp_orchestrator.py status

echo.
pause