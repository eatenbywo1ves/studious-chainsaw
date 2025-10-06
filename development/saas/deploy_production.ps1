# Production Deployment Script for Catalytic Computing SaaS
# Sets environment variables and starts uvicorn with 4 workers

Write-Host "========================================"  -ForegroundColor Cyan
Write-Host "Catalytic Computing SaaS - Production Deploy" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Set production environment variables
$env:DEPLOYMENT_ENV = "production"
$env:REDIS_HOST = "localhost"
$env:REDIS_PORT = "6379"
$env:REDIS_PASSWORD = "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo="

Write-Host "Environment: $env:DEPLOYMENT_ENV" -ForegroundColor Green
Write-Host "Redis: ${env:REDIS_HOST}:${env:REDIS_PORT}" -ForegroundColor Green
Write-Host "Workers: 4 (production configuration)" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Navigate to SaaS directory
Set-Location "C:\Users\Corbin\development\saas"

# Start uvicorn with 4 workers
Write-Host "Starting uvicorn with 4 workers..." -ForegroundColor Yellow
uvicorn api.saas_server:app --host 0.0.0.0 --port 8000 --workers 4
