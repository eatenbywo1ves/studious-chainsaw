# Deploy SaaS Application to WSL2
# This script deploys and tests the optimized application in WSL2 Linux environment

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "SaaS Application - WSL2 Deployment Script" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Check if WSL2 is available
Write-Host "[1/7] Checking WSL2 availability..." -ForegroundColor Yellow
$wslVersion = wsl --status 2>&1 | Select-String "Default Version" | Out-String
if ($wslVersion -match "Version : 2") {
    Write-Host "✓ WSL2 is available" -ForegroundColor Green
} else {
    Write-Host "✗ WSL2 not available. Please upgrade WSL first." -ForegroundColor Red
    Write-Host "  Run: wsl --set-version kali-linux 2" -ForegroundColor Yellow
    exit 1
}

# Check Linux kernel version
Write-Host "[2/7] Verifying Linux kernel..." -ForegroundColor Yellow
$kernelVersion = wsl -d kali-linux uname -r
Write-Host "✓ Kernel: $kernelVersion" -ForegroundColor Green

# Navigate to project directory in WSL
Write-Host "[3/7] Setting up project directory..." -ForegroundColor Yellow
$projectPath = "/mnt/c/Users/Corbin/development/saas"
wsl -d kali-linux bash -c "cd $projectPath && pwd"
Write-Host "✓ Project path accessible" -ForegroundColor Green

# Configure ulimit
Write-Host "[4/7] Configuring file descriptor limit..." -ForegroundColor Yellow
$currentUlimit = wsl -d kali-linux bash -c "ulimit -n"
Write-Host "  Current limit: $currentUlimit"

if ([int]$currentUlimit -lt 65536) {
    wsl -d kali-linux bash -c "ulimit -n 65536"
    $newUlimit = wsl -d kali-linux bash -c "ulimit -n"
    Write-Host "✓ Increased to: $newUlimit" -ForegroundColor Green
} else {
    Write-Host "✓ Already sufficient: $currentUlimit" -ForegroundColor Green
}

# Install Python dependencies
Write-Host "[5/7] Installing Python dependencies..." -ForegroundColor Yellow
wsl -d kali-linux bash -c "cd $projectPath && python3 -m venv venv && source venv/bin/activate && pip install --quiet -r requirements.txt"
Write-Host "✓ Dependencies installed" -ForegroundColor Green

# Start the server
Write-Host "[6/7] Starting optimized server (4 workers)..." -ForegroundColor Yellow
wsl -d kali-linux bash -c "cd $projectPath && source venv/bin/activate && nohup python start_server_optimized.py --workers 4 --port 8000 > wsl2_server.log 2>&1 &"
Start-Sleep -Seconds 5

# Wait for server to be healthy
Write-Host "  Waiting for server to be ready..."
$maxRetries = 30
$retry = 0
$serverReady = $false

while ($retry -lt $maxRetries -and -not $serverReady) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            $serverReady = $true
            Write-Host "✓ Server is responding" -ForegroundColor Green
            break
        }
    } catch {
        Start-Sleep -Seconds 1
        $retry++
    }
}

if (-not $serverReady) {
    Write-Host "✗ Server failed to start within 30 seconds" -ForegroundColor Red
    Write-Host "  Check logs: wsl -d kali-linux cat /mnt/c/Users/Corbin/development/saas/wsl2_server.log"
    exit 1
}

# Run validation
Write-Host "[7/7] Running deployment validation..." -ForegroundColor Yellow
wsl -d kali-linux bash -c "cd $projectPath && source venv/bin/activate && python validate_deployment.py --host http://localhost:8000 --no-color"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "DEPLOYMENT COMPLETE" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Server Status:" -ForegroundColor Yellow
Write-Host "  URL: http://localhost:8000" -ForegroundColor White
Write-Host "  Workers: 4" -ForegroundColor White
Write-Host "  Platform: WSL2 Linux" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Review validation results above" -ForegroundColor White
Write-Host "  2. Run load test:" -ForegroundColor White
Write-Host "     wsl -d kali-linux bash -c 'cd $projectPath && source venv/bin/activate && locust -f tests/performance/simple_loadtest.py --users 500 --spawn-rate 50 --run-time 120 --host http://localhost:8000 --headless --html wsl2_load_test.html'" -ForegroundColor Gray
Write-Host "  3. View server logs:" -ForegroundColor White
Write-Host "     wsl -d kali-linux cat /mnt/c/Users/Corbin/development/saas/wsl2_server.log" -ForegroundColor Gray
Write-Host ""
Write-Host "To stop server:" -ForegroundColor Yellow
Write-Host "  wsl -d kali-linux pkill -f start_server_optimized" -ForegroundColor Gray
Write-Host ""
