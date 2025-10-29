# Production Deployment Script for Catalytic Computing SaaS
# Sets environment variables and starts uvicorn with 4 workers

Write-Host "========================================"  -ForegroundColor Cyan
Write-Host "Catalytic Computing SaaS - Production Deploy" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Set production environment variables
$env:DEPLOYMENT_ENV = "production"
$env:REDIS_HOST = "localhost"
$env:REDIS_PORT = "6379"

# SECURITY: Load Redis password from secure .env.production.local file (gitignored)
$envFile = ".env.production.local"
if (-not (Test-Path $envFile)) {
    Write-Host "ERROR: $envFile not found!" -ForegroundColor Red
    Write-Host "Create this file with: REDIS_PASSWORD=your_secure_password" -ForegroundColor Yellow
    Write-Host "Generate password: python -c 'import secrets; print(secrets.token_urlsafe(32))'" -ForegroundColor Cyan
    exit 1
}

# Load environment variables from secure file
Get-Content $envFile | ForEach-Object {
    if ($_ -match '^REDIS_PASSWORD=(.+)$') {
        $env:REDIS_PASSWORD = $matches[1]
        Write-Host "✓ Redis password loaded from $envFile" -ForegroundColor Green
    }
}

# Validate password is set
if (-not $env:REDIS_PASSWORD) {
    Write-Host "ERROR: REDIS_PASSWORD not found in $envFile" -ForegroundColor Red
    exit 1
}

Write-Host "Environment: $env:DEPLOYMENT_ENV" -ForegroundColor Green
Write-Host "Redis: ${env:REDIS_HOST}:${env:REDIS_PORT}" -ForegroundColor Green
Write-Host "Workers: 4 (production configuration)" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Navigate to SaaS directory
Set-Location "C:\Users\Corbin\development\saas"

# Start uvicorn with 4 workers
Write-Host "Starting uvicorn with 4 workers..." -ForegroundColor Yellow
uvicorn api.saas_server:app --host 0.0.0.0 --port 8000 --workers 4
