@echo off
REM ============================================================================
REM Check Redis Connection Pool Status
REM Quick utility to monitor pool metrics during load testing
REM ============================================================================

echo ================================================================================
echo REDIS CONNECTION POOL STATUS
echo ================================================================================
echo.

REM Check if server is running
curl -s http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Server not responding on http://localhost:8000
    echo.
    pause
    exit /b 1
)

echo [POOL HEALTH CHECK]
echo ================================================================================
curl -s http://localhost:8000/health/redis | python -m json.tool
echo.
echo.

echo [REDIS STATISTICS]
echo ================================================================================
curl -s http://localhost:8000/redis/stats | python -m json.tool
echo.
echo.

echo [REDIS SERVER INFO]
echo ================================================================================
"C:\Program Files\Memurai\memurai-cli.exe" -a "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=" INFO stats | findstr /C:"total_connections" /C:"total_commands" /C:"rejected_connections" /C:"instantaneous_ops"
echo.
echo.

echo ================================================================================
echo Pool status check complete
echo ================================================================================
echo.
echo To monitor continuously, run this script in a loop or use:
echo   curl http://localhost:8000/health/redis
echo.
pause
