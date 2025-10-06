@echo off
REM Production Deployment Script for Catalytic Computing SaaS
REM Sets persistent environment variables for multi-worker uvicorn

setlocal

REM Set production environment variables
set DEPLOYMENT_ENV=production
set REDIS_HOST=localhost
set REDIS_PORT=6379
set REDIS_PASSWORD=RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=

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
