@echo off
REM ============================================================
REM Catalytic Lattice K8s Deployment Script for Windows
REM ============================================================

setlocal enabledelayedexpansion

echo ============================================================
echo   Catalytic Lattice API - Kubernetes Deployment
echo ============================================================
echo.

REM Check prerequisites
echo Checking prerequisites...
echo.

REM Check Docker
docker version >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Docker is not installed or not running
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    exit /b 1
) else (
    echo [✓] Docker is installed
)

REM Check kubectl
kubectl version --client >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] kubectl is not installed
    echo Please install kubectl from https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/
    exit /b 1
) else (
    echo [✓] kubectl is installed
)

echo.
echo ============================================================
echo   Select Deployment Target
echo ============================================================
echo.
echo 1. Local Kubernetes (Docker Desktop / Minikube)
echo 2. Google Kubernetes Engine (GKE)
echo 3. Amazon Elastic Kubernetes Service (EKS)
echo 4. Azure Kubernetes Service (AKS)
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    set PROVIDER=local
    echo.
    echo Selected: Local Kubernetes
) else if "%choice%"=="2" (
    set PROVIDER=gke
    echo.
    echo Selected: Google Kubernetes Engine
    set /p CLUSTER_NAME="Enter GKE cluster name: "
) else if "%choice%"=="3" (
    set PROVIDER=eks
    echo.
    echo Selected: Amazon EKS
    set /p CLUSTER_NAME="Enter EKS cluster name: "
) else if "%choice%"=="4" (
    set PROVIDER=aks
    echo.
    echo Selected: Azure AKS
    set /p CLUSTER_NAME="Enter AKS cluster name: "
    set /p RESOURCE_GROUP="Enter Azure resource group: "
) else (
    echo Invalid choice!
    exit /b 1
)

echo.
echo ============================================================
echo   Building Docker Image
echo ============================================================
echo.

REM Check if Dockerfile exists
if not exist "..\Dockerfile" (
    echo Creating sample Dockerfile...
    (
        echo FROM node:18-alpine
        echo WORKDIR /app
        echo COPY package*.json ./
        echo RUN npm ci --only=production
        echo COPY . .
        echo EXPOSE 8080
        echo CMD ["npm", "start"]
    ) > ..\Dockerfile
)

echo Building Docker image...
docker build -t catalytic/api:latest .. >nul 2>&1

if %errorlevel% neq 0 (
    echo [X] Failed to build Docker image
    exit /b 1
) else (
    echo [✓] Docker image built successfully
)

echo.
echo ============================================================
echo   Deploying to Kubernetes
echo ============================================================
echo.

REM Run Python deployment agent
python ..\deployment\deploy-agent.py %PROVIDER%

if %errorlevel% neq 0 (
    echo.
    echo [X] Deployment failed!
    exit /b 1
)

echo.
echo ============================================================
echo   Deployment Complete!
echo ============================================================
echo.

REM Get service endpoint
kubectl get service catalytic-api-service -n catalytic-lattice >nul 2>&1
if %errorlevel% equ 0 (
    echo Service Information:
    kubectl get service catalytic-api-service -n catalytic-lattice
    echo.
)

REM Show pod status
echo Pod Status:
kubectl get pods -n catalytic-lattice -l app=catalytic-api
echo.

echo ============================================================
echo   Post-Deployment Options
echo ============================================================
echo.
echo 1. Start Health Monitoring
echo 2. Start Auto-Scaling Agent
echo 3. View Logs
echo 4. Scale Manually
echo 5. Exit
echo.

:menu
set /p action="Select action (1-5): "

if "%action%"=="1" (
    echo.
    echo Starting Health Monitor...
    start cmd /k python ..\monitoring\health-monitor-agent.py
    echo Health monitor started in new window.
    echo.
    goto menu
) else if "%action%"=="2" (
    echo.
    echo Starting Auto-Scaling Agent...
    start cmd /k python ..\scaling\auto-scaling-agent.py --namespace catalytic-lattice
    echo Auto-scaling agent started in new window.
    echo.
    goto menu
) else if "%action%"=="3" (
    echo.
    echo Fetching logs...
    kubectl logs -f deployment/catalytic-api -n catalytic-lattice --tail=50
    echo.
    goto menu
) else if "%action%"=="4" (
    echo.
    set /p replicas="Enter number of replicas: "
    kubectl scale deployment/catalytic-api --replicas=!replicas! -n catalytic-lattice
    echo Scaled to !replicas! replicas.
    echo.
    goto menu
) else if "%action%"=="5" (
    echo.
    echo Goodbye!
    exit /b 0
) else (
    echo Invalid choice!
    goto menu
)

endlocal