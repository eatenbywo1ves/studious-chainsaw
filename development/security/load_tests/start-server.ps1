# Start Optimized Redis Mock Auth Server
# PowerShell script for Windows

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "OPTIMIZED REDIS MOCK AUTH SERVER - STARTUP" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Set environment variables
Write-Host "[1/4] Setting environment variables..." -ForegroundColor Yellow
$env:DEPLOYMENT_ENV = "production"
$env:REDIS_PASSWORD = "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo="
$env:REDIS_HOST = "localhost"
$env:REDIS_PORT = "6379"
Write-Host "  Environment: $env:DEPLOYMENT_ENV" -ForegroundColor Green
Write-Host "  Redis: $env:REDIS_HOST:$env:REDIS_PORT" -ForegroundColor Green
Write-Host ""

# Verify Redis
Write-Host "[2/4] Verifying Redis connection..." -ForegroundColor Yellow
try {
    $redisTest = & "C:\Program Files\Memurai\memurai-cli.exe" -a $env:REDIS_PASSWORD PING 2>&1
    if ($redisTest -like "*PONG*") {
        Write-Host "  [OK] Redis is running" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Redis not responding!" -ForegroundColor Red
        Write-Host "  Start Memurai: net start Memurai" -ForegroundColor Yellow
        pause
        exit 1
    }
} catch {
    Write-Host "  [ERROR] Cannot connect to Redis: $_" -ForegroundColor Red
    pause
    exit 1
}
Write-Host ""

# Check port availability
Write-Host "[3/4] Checking port availability..." -ForegroundColor Yellow
$portInUse = Get-NetTCPConnection -LocalPort 8001 -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "  [WARNING] Port 8001 is in use. Trying port 8002..." -ForegroundColor Yellow
    $PORT = 8002
} else {
    Write-Host "  [OK] Port 8001 is available" -ForegroundColor Green
    $PORT = 8001
}
Write-Host ""

# Start server
Write-Host "[4/4] Starting optimized server..." -ForegroundColor Yellow
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "SERVER CONFIGURATION" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Environment:      production" -ForegroundColor White
Write-Host "Target Users:     10,000 concurrent" -ForegroundColor White
Write-Host "Pool Size:        160 connections" -ForegroundColor White
Write-Host "Host:             0.0.0.0:$PORT" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Navigate to directory and start
Set-Location "C:\Users\Corbin\development\security\load_tests"

# Start with single worker for testing
python mock_auth_server_redis_optimized.py
