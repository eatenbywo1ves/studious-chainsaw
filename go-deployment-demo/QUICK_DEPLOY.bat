@echo off
REM Quick Deployment Script for Windows
REM This script will guide you through deploying to Docker Hub

echo ========================================
echo  DEPLOYMENT STARTED
echo ========================================
echo.

REM Step 1: Docker Hub Login
echo Step 1: Docker Hub Login
echo ========================================
echo.
echo Please enter your Docker Hub username:
set /p DOCKER_USERNAME="Username: "
echo.

echo Logging in to Docker Hub...
docker login -u %DOCKER_USERNAME%
if %errorlevel% neq 0 (
    echo ERROR: Docker Hub login failed!
    pause
    exit /b 1
)
echo.
echo ✓ Login successful!
echo.

REM Step 2: Tag and Push Image
echo Step 2: Tagging and Pushing Image
echo ========================================
echo.
echo Tagging image for Docker Hub...
docker tag go-deployment-demo:1.0.0 %DOCKER_USERNAME%/go-deployment-demo:1.0.0
docker tag go-deployment-demo:1.0.0 %DOCKER_USERNAME%/go-deployment-demo:latest

echo.
echo Pushing to Docker Hub...
echo This may take 2-3 minutes...
docker push %DOCKER_USERNAME%/go-deployment-demo:1.0.0
docker push %DOCKER_USERNAME%/go-deployment-demo:latest

if %errorlevel% neq 0 (
    echo ERROR: Docker push failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo  ✅ DOCKER HUB DEPLOYMENT COMPLETE!
echo ========================================
echo.
echo Your image is now available at:
echo https://hub.docker.com/r/%DOCKER_USERNAME%/go-deployment-demo
echo.
echo Next steps:
echo 1. Deploy to Railway.app (web-based)
echo 2. Deploy to Render.com (web-based)
echo.
echo See START_DEPLOYMENT.md for detailed instructions.
echo.

REM Step 3: Display Railway Instructions
echo ========================================
echo  RAILWAY.APP DEPLOYMENT
echo ========================================
echo.
echo 1. Visit: https://railway.app
echo 2. Click "New Project" ^> "Deploy from Docker Image"
echo 3. Enter image: %DOCKER_USERNAME%/go-deployment-demo:latest
echo 4. Add environment variables:
echo    PORT=8080
echo    ENVIRONMENT=production
echo    VERSION=1.0.0
echo 5. Click "Deploy"
echo.

REM Step 4: Display Render Instructions
echo ========================================
echo  RENDER.COM DEPLOYMENT
echo ========================================
echo.
echo 1. Visit: https://render.com
echo 2. Click "New +" ^> "Web Service" ^> "Existing Image"
echo 3. Enter image: docker.io/%DOCKER_USERNAME%/go-deployment-demo:latest
echo 4. Configure:
echo    - Port: 8080
echo    - Health Check Path: /health
echo 5. Add environment variables:
echo    PORT=8080
echo    ENVIRONMENT=production
echo    VERSION=1.0.0
echo 6. Click "Create Web Service"
echo.

echo ========================================
echo  DEPLOYMENT GUIDE COMPLETE
echo ========================================
echo.
echo Press any key to open START_DEPLOYMENT.md for full instructions...
pause >nul
start START_DEPLOYMENT.md
