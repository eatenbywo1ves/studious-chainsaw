@echo off
REM Production Deployment Script for Catalytic Computing SaaS
REM Sets persistent environment variables for multi-worker uvicorn

setlocal

REM Set production environment variables
set DEPLOYMENT_ENV=production
set REDIS_HOST=localhost
set REDIS_PORT=6379

REM SECURITY: Check for .env.production.local file (gitignored)
if not exist .env.production.local (
    echo ERROR: .env.production.local not found!
    echo Create this file with: REDIS_PASSWORD=your_secure_password
    echo Generate password: python -c "import secrets; print(secrets.token_urlsafe(32))"
    exit /b 1
)

REM Load Redis password from secure file
for /f "tokens=1,* delims==" %%a in (.env.production.local) do (
    if "%%a"=="REDIS_PASSWORD" set REDIS_PASSWORD=%%b
)

REM Validate password is set
if "%REDIS_PASSWORD%"=="" (
    echo ERROR: REDIS_PASSWORD not found in .env.production.local
    exit /b 1
)

echo [OK] Redis password loaded from .env.production.local

REM Display configuration
echo ========================================
echo Catalytic Computing SaaS - Production Deploy
echo ========================================
echo Environment: %DEPLOYMENT_ENV%
echo Redis: %REDIS_HOST%:%REDIS_PORT%
echo Workers: 4 (production configuration)
echo ========================================
echo.

REM Navigate to SaaS directory
cd /d C:\Users\Corbin\development\saas

REM Start uvicorn with 4 workers
echo Starting uvicorn with 4 workers...
uvicorn api.saas_server:app --host 0.0.0.0 --port 8000 --workers 4 --env-file .env.production

endlocal
