@echo off
echo Starting Development Environment Monitoring System...
echo.

REM Check if Node.js is available
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Node.js is not installed or not in PATH
    pause
    exit /b 1
)

REM Install dependencies if needed
if not exist node_modules (
    echo Installing dependencies...
    npm install
    echo.
)

REM Start the monitoring system
echo Starting monitoring system...
echo Dashboard will be available at: http://localhost:3002
echo Press Ctrl+C to stop monitoring
echo.

node start-monitor.js