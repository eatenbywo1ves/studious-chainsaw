@echo off
REM ============================================================
REM Local Deployment Script for STOOPIDPC
REM Complete setup for Catalytic Lattice K8s on Windows
REM ============================================================

setlocal enabledelayedexpansion
color 0A

echo.
echo ============================================================
echo   CATALYTIC LATTICE - LOCAL DEPLOYMENT ON STOOPIDPC
echo ============================================================
echo.
echo [SYSTEM CHECK] Your hardware is FULLY CAPABLE:
echo   - RAM: 64GB (Excellent)
echo   - CPU: 6 cores / 12 threads (Very Good)
echo   - Can run 5+ pods locally
echo.

:MENU
echo ============================================================
echo   SELECT DEPLOYMENT OPTION
echo ============================================================
echo.
echo 1. Install Prerequisites (Docker Desktop + kubectl)
echo 2. Quick Simulation (No Docker Required)
echo 3. Deploy with Docker Compose (Alternative to K8s)
echo 4. Full Kubernetes Deployment (Requires Docker Desktop)
echo 5. Run Agents Only (Manage Remote Clusters)
echo 6. Exit
echo.
set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto INSTALL
if "%choice%"=="2" goto SIMULATE
if "%choice%"=="3" goto DOCKER_COMPOSE
if "%choice%"=="4" goto KUBERNETES
if "%choice%"=="5" goto AGENTS_ONLY
if "%choice%"=="6" goto END

:INSTALL
echo.
echo ============================================================
echo   INSTALLATION INSTRUCTIONS
echo ============================================================
echo.
echo [STEP 1] Install Docker Desktop:
echo.
echo   1. Download from: https://www.docker.com/products/docker-desktop/
echo   2. Run the installer (Docker Desktop Installer.exe)
echo   3. After installation, start Docker Desktop
echo   4. Go to Settings - Kubernetes
echo   5. Check "Enable Kubernetes"
echo   6. Click "Apply & Restart"
echo.
echo [STEP 2] Install kubectl:
echo.
echo   Option A - Using Chocolatey:
echo   choco install kubernetes-cli
echo.
echo   Option B - Direct Download:
echo   1. Download from: https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/
echo   2. Add to PATH environment variable
echo.
echo [STEP 3] Verify Installation:
echo   docker --version
echo   kubectl version --client
echo.
pause
goto MENU

:SIMULATE
echo.
echo ============================================================
echo   RUNNING SIMULATED DEPLOYMENT (No Docker Required)
echo ============================================================
echo.
cd /d "%~dp0"
echo Starting simulation...
python demo.py
goto MENU

:DOCKER_COMPOSE
echo.
echo ============================================================
echo   DOCKER COMPOSE DEPLOYMENT (Alternative to K8s)
echo ============================================================
echo.

REM Create docker-compose.yml
echo Creating docker-compose.yml...
(
echo version: '3.8'
echo.
echo services:
echo   catalytic-api-1:
echo     image: nginx:alpine
echo     container_name: catalytic-pod-1
echo     ports:
echo       - "8081:80"
echo     environment:
echo       - POD_NAME=catalytic-api-1
echo       - NODE_ENV=production
echo     deploy:
echo       resources:
echo         limits:
echo           cpus: '2'
echo           memory: 4G
echo         reservations:
echo           cpus: '1'
echo           memory: 2G
echo.
echo   catalytic-api-2:
echo     image: nginx:alpine
echo     container_name: catalytic-pod-2
echo     ports:
echo       - "8082:80"
echo     environment:
echo       - POD_NAME=catalytic-api-2
echo       - NODE_ENV=production
echo     deploy:
echo       resources:
echo         limits:
echo           cpus: '2'
echo           memory: 4G
echo.
echo   catalytic-api-3:
echo     image: nginx:alpine
echo     container_name: catalytic-pod-3
echo     ports:
echo       - "8083:80"
echo     environment:
echo       - POD_NAME=catalytic-api-3
echo       - NODE_ENV=production
echo     deploy:
echo       resources:
echo         limits:
echo           cpus: '2'
echo           memory: 4G
echo.
echo   postgres:
echo     image: postgres:14
echo     container_name: catalytic-db
echo     environment:
echo       - POSTGRES_DB=catalytic
echo       - POSTGRES_USER=admin
echo       - POSTGRES_PASSWORD=secret
echo     volumes:
echo       - postgres_data:/var/lib/postgresql/data
echo     deploy:
echo       resources:
echo         limits:
echo           cpus: '2'
echo           memory: 2G
echo.
echo   load-balancer:
echo     image: nginx:alpine
echo     container_name: catalytic-lb
echo     ports:
echo       - "8080:80"
echo     depends_on:
echo       - catalytic-api-1
echo       - catalytic-api-2
echo       - catalytic-api-3
echo.
echo volumes:
echo   postgres_data:
) > docker-compose.yml

echo.
echo Docker Compose file created!
echo.
echo To deploy: docker-compose up -d
echo To stop: docker-compose down
echo To view logs: docker-compose logs -f
echo.
pause
goto MENU

:KUBERNETES
echo.
echo ============================================================
echo   FULL KUBERNETES DEPLOYMENT
echo ============================================================
echo.

REM Check if Docker is running
docker version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed or not running!
    echo Please install Docker Desktop first (Option 1)
    pause
    goto MENU
)

REM Check if kubectl exists
kubectl version --client >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] kubectl is not installed!
    echo Please install kubectl first (Option 1)
    pause
    goto MENU
)

echo [OK] Prerequisites found
echo.
echo Deploying to Kubernetes...
echo.

REM Apply the optimized deployment
echo Applying deployment configuration...
kubectl apply -f stoopidpc-deployment.yaml

echo.
echo Deployment started! Checking status...
kubectl get all -n catalytic-lattice

echo.
pause
goto MENU

:AGENTS_ONLY
echo.
echo ============================================================
echo   RUNNING MANAGEMENT AGENTS
echo ============================================================
echo.
echo Starting agents for remote cluster management...
echo.

REM Start agents in separate windows
echo [1] Starting Deployment Agent...
start cmd /k "cd /d %~dp0 && python deployment\deploy-agent.py"

timeout /t 2 >nul

echo [2] Starting Health Monitor...
start cmd /k "cd /d %~dp0 && python monitoring\health-monitor-agent.py"

timeout /t 2 >nul

echo [3] Starting Auto-Scaling Agent...
start cmd /k "cd /d %~dp0 && python scaling\auto-scaling-agent.py --dry-run"

echo.
echo Agents started in separate windows!
echo.
pause
goto MENU

:END
echo.
echo Thank you for using Catalytic Lattice K8s Deployment!
echo.
endlocal
exit /b 0