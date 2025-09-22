@echo off
echo ========================================
echo   Webhook Audio Tracker - Starting...
echo ========================================
echo.

:: Check if node_modules exists
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
    echo.
)

:: Start the server
echo Starting webhook server on port 3000...
echo Starting WebSocket server on port 3001...
echo.
echo Dashboard will be available at: http://localhost:3000/
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

:: Run the server
node server.js