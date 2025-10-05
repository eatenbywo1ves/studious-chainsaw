@echo off
REM Catalytic Computing SaaS - Production Startup Script (Windows)
REM Usage: start-production.bat

echo.
echo ================================================================
echo   CATALYTIC COMPUTING SAAS - PRODUCTION STARTUP
echo ================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+
    exit /b 1
)

REM Check if Redis is running
echo [1/5] Checking Redis...
"C:\Program Files\Memurai\memurai-cli.exe" -a "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=" PING >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Redis not running. Starting Memurai...
    net start Memurai
    timeout /t 3 >nul
)
echo [OK] Redis is running

REM Check if database is initialized
echo.
echo [2/5] Checking database...
if not exist "catalytic_saas.db" (
    echo [WARN] Database not found. Initializing...
    python init_production_db.py
    if errorlevel 1 (
        echo [ERROR] Database initialization failed
        exit /b 1
    )
) else (
    echo [OK] Database exists
)

REM Check environment variables
echo.
echo [3/5] Checking environment...
if not exist ".env" (
    echo [ERROR] .env file not found
    echo Please create .env file from .env.example
    exit /b 1
)
echo [OK] Environment configured

REM Start backend API
echo.
echo [4/5] Starting backend API...
start "Catalytic Backend" cmd /k "uvicorn api.saas_server:app --host 0.0.0.0 --port 8000 --workers 4"
timeout /t 5 >nul

REM Wait for backend to start
echo Waiting for backend to start...
:wait_backend
timeout /t 1 >nul
curl -s http://localhost:8000/health >nul 2>&1
if errorlevel 1 goto wait_backend
echo [OK] Backend started successfully

REM Start frontend (optional)
echo.
echo [5/5] Frontend deployment...
if exist "frontend\package.json" (
    echo Would you like to start the frontend? (Y/N)
    set /p START_FRONTEND=
    if /i "%START_FRONTEND%"=="Y" (
        cd frontend
        start "Catalytic Frontend" cmd /k "npm start"
        cd ..
    )
)

echo.
echo ================================================================
echo   DEPLOYMENT COMPLETE!
echo ================================================================
echo.
echo Backend API: http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo Health Check: http://localhost:8000/health
echo.
echo Frontend (if started): http://localhost:3000
echo.
echo Press Ctrl+C in each window to stop services
echo ================================================================
echo.

pause
