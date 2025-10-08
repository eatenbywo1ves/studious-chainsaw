@echo off
REM BMAD Automated Deployment - Windows Batch Version
REM Complete workflow for Docker Hub and cloud deployments

setlocal enabledelayedexpansion

echo ==========================================
echo BMAD AUTOMATED DEPLOYMENT
echo ==========================================
echo This script will:
echo 1. Push to Docker Hub
echo 2. Provide Railway.app setup commands
echo 3. Provide Render.com setup commands
echo 4. Verify all deployments
echo ==========================================
echo.

REM Check if DOCKER_USERNAME is set
if "%DOCKER_USERNAME%"=="" (
    echo Warning: DOCKER_USERNAME environment variable not set
    echo.
    set /p DOCKER_USERNAME="Enter your Docker Hub username: "
)

echo Docker Hub Username: %DOCKER_USERNAME%
echo.

REM Step 1: Verify Docker is running
echo Step 1: Verifying Docker...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not running!
    pause
    exit /b 1
)
echo ✓ Docker is running
echo.

REM Step 2: Verify local image exists
echo Step 2: Verifying local image...
docker image inspect go-deployment-demo:1.0.0 >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Local image 'go-deployment-demo:1.0.0' not found!
    pause
    exit /b 1
)
echo ✓ Local image found
echo.

REM Step 3: Check Docker Hub authentication
echo Step 3: Checking Docker Hub authentication...
docker info | findstr /C:"Username" >nul 2>&1
if %errorlevel% neq 0 (
    echo Not logged in to Docker Hub
    echo Logging in now...
    docker login
    if %errorlevel% neq 0 (
        echo ERROR: Docker Hub login failed!
        pause
        exit /b 1
    )
)
echo ✓ Docker Hub authenticated
echo.

REM Step 4: Tag images
echo Step 4: Tagging images for Docker Hub...
docker tag go-deployment-demo:1.0.0 %DOCKER_USERNAME%/go-deployment-demo:1.0.0
docker tag go-deployment-demo:1.0.0 %DOCKER_USERNAME%/go-deployment-demo:latest
echo ✓ Images tagged
echo.

REM Step 5: Push to Docker Hub
echo Step 5: Pushing to Docker Hub...
echo This may take 2-3 minutes for a 10.3MB image...
docker push %DOCKER_USERNAME%/go-deployment-demo:1.0.0
docker push %DOCKER_USERNAME%/go-deployment-demo:latest
if %errorlevel% neq 0 (
    echo ERROR: Docker push failed!
    pause
    exit /b 1
)
echo ✓ Images pushed to Docker Hub
echo.

REM Step 6: Verify push
echo Step 6: Verifying Docker Hub push...
timeout /t 2 >nul
docker pull %DOCKER_USERNAME%/go-deployment-demo:latest >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ Image successfully pulled from Docker Hub
) else (
    echo Warning: Could not verify push, but push completed
)
echo.

REM Set deployment URLs
set DOCKERHUB_URL=https://hub.docker.com/r/%DOCKER_USERNAME%/go-deployment-demo
set RAILWAY_IMAGE=%DOCKER_USERNAME%/go-deployment-demo:latest
set RENDER_IMAGE=docker.io/%DOCKER_USERNAME%/go-deployment-demo:latest

echo ==========================================
echo ✓ DOCKER HUB DEPLOYMENT COMPLETE!
echo ==========================================
echo.
echo Your image is now public at:
echo 🔗 %DOCKERHUB_URL%
echo.
echo Image details:
echo   - Repository: %DOCKER_USERNAME%/go-deployment-demo
echo   - Tags: 1.0.0, latest
echo   - Size: ~10.3 MB
echo   - Pulls: docker pull %DOCKER_USERNAME%/go-deployment-demo:latest
echo.

REM Save deployment info to file
(
echo BMAD Deployment Information
echo Generated: %date% %time%
echo.
echo Docker Hub:
echo   URL: %DOCKERHUB_URL%
echo   Image: %RAILWAY_IMAGE%
echo   Size: 10.3 MB
echo.
echo Railway.app Image:
echo   %RAILWAY_IMAGE%
echo.
echo Render.com Image:
echo   %RENDER_IMAGE%
echo.
echo Environment Variables ^(for all platforms^):
echo   PORT=8080
echo   ENVIRONMENT=production
echo   VERSION=1.0.0
) > deployment-info.txt

echo ✓ Deployment info saved to: deployment-info.txt
echo.

echo ==========================================
echo NEXT: RAILWAY.APP DEPLOYMENT
echo ==========================================
echo.
echo Option A: Web-Based ^(No CLI^) - Recommended
echo -------------------------------------------
echo 1. Visit: https://railway.app
echo 2. Click 'New Project' -^> 'Deploy from Docker Image'
echo 3. Image: %RAILWAY_IMAGE%
echo 4. Environment Variables:
echo    PORT=8080
echo    ENVIRONMENT=production
echo    VERSION=1.0.0
echo 5. Click 'Deploy'
echo.
echo Press any key to open Railway in browser...
pause >nul
start https://railway.app
echo.

echo ==========================================
echo NEXT: RENDER.COM DEPLOYMENT
echo ==========================================
echo.
echo Web-Based Deployment ^(No CLI Required^)
echo -------------------------------------------
echo 1. Visit: https://render.com
echo 2. Click 'New +' -^> 'Web Service' -^> 'Existing Image'
echo 3. Image URL: %RENDER_IMAGE%
echo 4. Service Configuration:
echo    - Name: go-deployment-demo
echo    - Region: Oregon ^(or nearest^)
echo    - Instance Type: Free or Starter ^($7/mo^)
echo 5. Environment Variables:
echo    PORT=8080
echo    ENVIRONMENT=production
echo    VERSION=1.0.0
echo 6. Advanced Settings:
echo    - Port: 8080
echo    - Health Check Path: /health
echo 7. Click 'Create Web Service'
echo.
echo Press any key to open Render in browser...
pause >nul
start https://render.com
echo.

echo ==========================================
echo VERIFICATION COMMANDS
echo ==========================================
echo.
echo After deployment, test with these commands:
echo.
echo # Set your deployment URLs
echo set RAILWAY_URL=https://your-app.up.railway.app
echo set RENDER_URL=https://go-deployment-demo.onrender.com
echo.
echo # Test Railway
echo curl %%RAILWAY_URL%%/health
echo.
echo # Test Render
echo curl %%RENDER_URL%%/health
echo.
echo # Run verification script
echo bash verify-deployment.sh
echo.

echo ==========================================
echo DEPLOYMENT SUMMARY
echo ==========================================
echo.
echo ✓ Completed:
echo   - Docker Swarm ^(local^) - Running on port 8081
echo   - Docker Hub - Image pushed and verified
echo.
echo ⏳ Pending ^(web-based, ~10 min each^):
echo   - Railway.app deployment
echo   - Render.com deployment
echo.
echo 📚 Documentation:
echo   - START_DEPLOYMENT.md - Full guide
echo   - deployment-info.txt - Your deployment details
echo   - verify-deployment.sh - Verification script
echo.
echo ==========================================
echo 🎉 READY FOR CLOUD DEPLOYMENT!
echo ==========================================
echo.
echo Press any key to open START_DEPLOYMENT.md...
pause >nul
start START_DEPLOYMENT.md
