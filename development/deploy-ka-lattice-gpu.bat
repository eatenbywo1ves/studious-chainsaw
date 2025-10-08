@echo off
REM KA Lattice GPU Deployment Script
REM Uses Python 3.12 for GPU acceleration

echo ============================================================
echo KA Lattice GPU Production Deployment
echo ============================================================
echo.

REM Check Python 3.12
py -3.12 --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.12 required for GPU acceleration
    pause
    exit /b 1
)

echo [OK] Python 3.12 found
echo.
echo Deploying KA Lattice with GPU acceleration...
echo.

REM Run deployment script with Python 3.12
py -3.12 deploy-ka-lattice-local.py %*