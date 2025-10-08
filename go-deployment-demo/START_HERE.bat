@echo off
REM START HERE - Quick Deployment Launcher
REM Double-click this file to begin deployment

echo.
echo ==========================================
echo   GO DEPLOYMENT DEMO - QUICK START
echo ==========================================
echo.
echo This script will help you deploy to:
echo   1. Docker Hub (automated)
echo   2. Railway.app (web-based)
echo   3. Render.com (web-based)
echo.
echo ==========================================
echo.

REM Check if we're in the correct directory
if not exist "auto-deploy-all.bat" (
    echo ERROR: Please run this from the go-deployment-demo directory
    pause
    exit /b 1
)

REM Prompt for Docker Hub username
echo Before we begin, we need your Docker Hub username.
echo If you don't have an account, create one at: https://hub.docker.com
echo.
set /p DOCKER_USERNAME="Enter your Docker Hub username: "

if "%DOCKER_USERNAME%"=="" (
    echo ERROR: Username cannot be empty
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Configuration Set:
echo   Username: %DOCKER_USERNAME%
echo ==========================================
echo.
echo Press any key to start deployment...
pause >nul

REM Run the automated deployment script
call auto-deploy-all.bat

echo.
echo ==========================================
echo Deployment script completed!
echo ==========================================
echo.
echo Next steps:
echo   1. Follow Railway.app instructions (browser should be open)
echo   2. Follow Render.com instructions (browser should be open)
echo   3. Run verify-deployment.sh to test deployments
echo.
pause
