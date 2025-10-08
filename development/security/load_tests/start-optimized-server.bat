@echo off
REM ============================================================================
REM Start Optimized Redis-Integrated Mock Auth Server
REM Configured for production load testing (10K users, 4 workers)
REM ============================================================================

echo ================================================================================
echo OPTIMIZED MOCK AUTH SERVER - STARTUP SCRIPT
echo ================================================================================
echo.

REM Set environment variables
echo [1/4] Setting environment variables...
set DEPLOYMENT_ENV=production
set REDIS_HOST=localhost
set REDIS_PORT=6379
set REDIS_PASSWORD=RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=
echo     - DEPLOYMENT_ENV: %DEPLOYMENT_ENV%
echo     - REDIS_HOST: %REDIS_HOST%
echo     - REDIS_PORT: %REDIS_PORT%
echo.

REM Verify Redis is running
echo [2/4] Verifying Redis connection...
"C:\Program Files\Memurai\memurai-cli.exe" -a "%REDIS_PASSWORD%" PING >nul 2>&1
if errorlevel 1 (
    echo     [ERROR] Redis not responding! Make sure Memurai is running.
    echo     Try: net start Memurai
    pause
    exit /b 1
)
echo     [OK] Redis is running
echo.

REM Check if port 8000 is available
echo [3/4] Checking port availability...
netstat -ano | findstr :8000 >nul 2>&1
if not errorlevel 1 (
    echo     [WARNING] Port 8000 is already in use!
    echo     Kill existing process or change port.
    pause
    exit /b 1
)
echo     [OK] Port 8000 is available
echo.

REM Start the server
echo [4/4] Starting optimized mock auth server...
echo.
echo ================================================================================
echo SERVER CONFIGURATION
echo ================================================================================
echo Environment:     production
echo Target Users:    10,000 concurrent
echo Workers:         4
echo Pool Size:       160 connections (40 per worker)
echo Host:            0.0.0.0:8000
echo ================================================================================
echo.
echo Press Ctrl+C to stop the server
echo.
echo ================================================================================

REM Start uvicorn with 4 workers
uvicorn mock_auth_server_redis_optimized:app ^
    --host 0.0.0.0 ^
    --port 8000 ^
    --workers 4 ^
    --log-level info ^
    --access-log

REM If server exits
echo.
echo ================================================================================
echo Server stopped
echo ================================================================================
pause
