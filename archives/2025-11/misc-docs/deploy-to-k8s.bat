@echo off
REM Windows deployment script for Catalytic Lattice Computing on Kubernetes

echo ==========================================
echo Catalytic Lattice Kubernetes Deployment
echo ==========================================

set NAMESPACE=catalytic-lattice
set IMAGE_NAME=catalytic-lattice
set IMAGE_TAG=latest

REM Check prerequisites
echo.
echo Checking prerequisites...
where docker >nul 2>nul
if errorlevel 1 (
    echo Docker is required but not installed. Aborting.
    exit /b 1
)

where kubectl >nul 2>nul
if errorlevel 1 (
    echo kubectl is required but not installed. Aborting.
    exit /b 1
)

REM Detect Kubernetes environment
echo.
kubectl config current-context
set K8S_CONTEXT=%errorlevel%

REM Build Docker image
echo.
echo Building Docker image...
docker build -t %IMAGE_NAME%:%IMAGE_TAG% .
if errorlevel 1 (
    echo Failed to build Docker image
    exit /b 1
)

REM For Docker Desktop, image is automatically available
echo Image built successfully: %IMAGE_NAME%:%IMAGE_TAG%

REM Apply Kubernetes manifests
echo.
echo Deploying to Kubernetes...

echo Creating namespace and configurations...
kubectl apply -f k8s-namespace.yaml
if errorlevel 1 goto :error

timeout /t 2 /nobreak >nul

echo Setting up storage...
kubectl apply -f k8s-storage.yaml
if errorlevel 1 goto :error

echo Creating services...
kubectl apply -f k8s-services.yaml
if errorlevel 1 goto :error

echo Deploying applications...
kubectl apply -f k8s-deployments.yaml
if errorlevel 1 goto :error

echo.
echo Waiting for deployments to be ready...
kubectl -n %NAMESPACE% wait --for=condition=available --timeout=300s deployment/catalytic-api
kubectl -n %NAMESPACE% wait --for=condition=available --timeout=300s deployment/catalytic-worker

REM Check deployment status
echo.
echo Deployment Status:
echo ==================
kubectl -n %NAMESPACE% get deployments
echo.
kubectl -n %NAMESPACE% get pods
echo.
kubectl -n %NAMESPACE% get services

REM Setup port forwarding
echo.
echo Setting up port forwarding for local access...
start /b kubectl -n %NAMESPACE% port-forward service/catalytic-api-service 8000:80

timeout /t 5 /nobreak >nul

REM Health check
echo.
echo Running health check...
curl -s http://localhost:8000/health

echo.
echo ==========================================
echo Deployment Complete!
echo ==========================================
echo.
echo API available at: http://localhost:8000
echo.
echo Useful commands:
echo   View logs:     kubectl -n %NAMESPACE% logs -f deployment/catalytic-api
echo   Scale API:     kubectl -n %NAMESPACE% scale deployment/catalytic-api --replicas=5
echo   View metrics:  kubectl -n %NAMESPACE% top pods
echo   Delete all:    kubectl delete namespace %NAMESPACE%
echo.
echo Press any key to stop port forwarding and exit...
pause >nul

REM Cleanup
taskkill /f /im kubectl.exe 2>nul
exit /b 0

:error
echo Deployment failed!
exit /b 1