# Test Optimized Redis Mock Auth Server
# Quick health check and pool status

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "REDIS POOL STATUS CHECK" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Try different ports
$ports = @(8001, 8002, 8000)
$serverUrl = $null

foreach ($port in $ports) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$port/health" -TimeoutSec 2 -ErrorAction Stop
        $serverUrl = "http://localhost:$port"
        Write-Host "[OK] Server found on port $port" -ForegroundColor Green
        break
    } catch {
        # Try next port
    }
}

if (-not $serverUrl) {
    Write-Host "[ERROR] Server not responding on any port!" -ForegroundColor Red
    Write-Host "Start the server first with: .\start-server.ps1" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host ""
Write-Host "Server URL: $serverUrl" -ForegroundColor Cyan
Write-Host ""

# Get Redis pool health
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "POOL HEALTH CHECK" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
try {
    $health = Invoke-RestMethod -Uri "$serverUrl/health/redis"

    Write-Host "Status:              " -NoNewline
    if ($health.healthy) {
        Write-Host "HEALTHY" -ForegroundColor Green
    } else {
        Write-Host "DEGRADED" -ForegroundColor Red
    }

    Write-Host "Environment:         $($health.pool.environment)" -ForegroundColor White
    Write-Host "Max Connections:     $($health.pool.max_connections)" -ForegroundColor White
    Write-Host "In Use:              $($health.pool.in_use_connections)" -ForegroundColor White
    Write-Host "Available:           $($health.pool.available_connections)" -ForegroundColor White
    Write-Host "Utilization:         $($health.pool.utilization_percent)%" -ForegroundColor White

    Write-Host ""
    Write-Host "Recommendations:" -ForegroundColor Cyan
    foreach ($rec in $health.recommendations) {
        if ($rec -like "*CRITICAL*") {
            Write-Host "  - $rec" -ForegroundColor Red
        } elseif ($rec -like "*WARNING*") {
            Write-Host "  - $rec" -ForegroundColor Yellow
        } else {
            Write-Host "  - $rec" -ForegroundColor Green
        }
    }

} catch {
    Write-Host "[ERROR] Failed to get pool health: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "REDIS STATISTICS" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

try {
    $stats = Invoke-RestMethod -Uri "$serverUrl/redis/stats"

    Write-Host "Commands Processed:  $($stats.redis.total_commands_processed)" -ForegroundColor White
    Write-Host "Ops/Sec:             $($stats.redis.instantaneous_ops_per_sec)" -ForegroundColor White
    Write-Host "Memory Used:         $($stats.redis.used_memory_human)" -ForegroundColor White
    Write-Host "Connected Clients:   $($stats.redis.connected_clients)" -ForegroundColor White
    Write-Host "Keyspace Size:       $($stats.redis.keyspace)" -ForegroundColor White

} catch {
    Write-Host "[ERROR] Failed to get Redis stats: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
pause
