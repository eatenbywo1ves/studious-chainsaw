@echo off
REM Deploy go-deployment-demo to Google Cloud Run (Windows)
REM Prerequisites: Google Cloud SDK installed and authenticated

setlocal enabledelayedexpansion

REM Configuration
set PROJECT_ID=%GCP_PROJECT_ID%
if "%PROJECT_ID%"=="" set PROJECT_ID=your-project-id
set REGION=%GCP_REGION%
if "%REGION%"=="" set REGION=us-central1
set SERVICE_NAME=go-deployment-demo
set IMAGE_NAME=gcr.io/%PROJECT_ID%/%SERVICE_NAME%:1.0.0

echo ==========================================
echo GCP Cloud Run Deployment Script
echo ==========================================
echo Project ID: %PROJECT_ID%
echo Region: %REGION%
echo Service: %SERVICE_NAME%
echo Image: %IMAGE_NAME%
echo ==========================================
echo.

REM Step 1: Check if gcloud is installed
echo Step 1: Checking Google Cloud SDK installation...
where gcloud >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Google Cloud SDK not found!
    echo Please install from: C:\Users\Corbin\GoogleCloudSDKInstaller.exe
    echo Or download from: https://cloud.google.com/sdk/docs/install
    pause
    exit /b 1
)

REM Step 2: Set the project
echo Step 2: Setting GCP project...
gcloud config set project %PROJECT_ID%

REM Step 3: Enable required APIs
echo Step 3: Enabling required GCP APIs...
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

REM Step 4: Configure Docker authentication
echo Step 4: Configuring Docker authentication...
gcloud auth configure-docker

REM Step 5: Tag the Docker image
echo Step 5: Tagging Docker image for GCR...
docker tag go-deployment-demo:1.0.0 %IMAGE_NAME%

REM Step 6: Push to GCR
echo Step 6: Pushing image to GCR...
docker push %IMAGE_NAME%

REM Step 7: Deploy to Cloud Run
echo Step 7: Deploying to Cloud Run...
gcloud run deploy %SERVICE_NAME% ^
    --image %IMAGE_NAME% ^
    --platform managed ^
    --region %REGION% ^
    --allow-unauthenticated ^
    --port 8080 ^
    --memory 128Mi ^
    --cpu 1 ^
    --min-instances 0 ^
    --max-instances 10 ^
    --timeout 60s ^
    --set-env-vars "PORT=8080,ENV=production"

REM Step 8: Get service URL
echo Step 8: Retrieving service URL...
for /f "usebackq tokens=*" %%i in (`gcloud run services describe %SERVICE_NAME% --platform managed --region %REGION% --format "value(status.url)"`) do set SERVICE_URL=%%i

echo ==========================================
echo Deployment Complete!
echo ==========================================
echo Service URL: %SERVICE_URL%
echo.
echo Test endpoints:
echo   Health:    %SERVICE_URL%/health
echo   Readiness: %SERVICE_URL%/ready
echo   Metrics:   %SERVICE_URL%/metrics
echo   Home:      %SERVICE_URL%/
echo ==========================================
echo.

REM Optional health check
set /p HEALTH_CHECK="Run health check? (y/n): "
if /i "%HEALTH_CHECK%"=="y" (
    echo Running health check...
    curl -s %SERVICE_URL%/health
)

pause
