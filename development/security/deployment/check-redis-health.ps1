# Redis/Memurai Health Check Script
# Purpose: Monitor Redis health and alert on issues
# Schedule: Run every 5-15 minutes via Task Scheduler

param(
    [string]$RedisPassword = $env:REDIS_PASSWORD,
    [string]$MemuraiCliPath = "C:\Program Files\Memurai\memurai-cli.exe",
    [int]$MemoryWarningThresholdPercent = 80,
    [int]$SlowLogThreshold = 10,
    [string]$AlertEmail = "",  # Optional: email for alerts
    [switch]$Verbose = $false
)

# Color output helpers
function Write-Success { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warning { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Info { param($msg) if ($Verbose) { Write-Host "[INFO] $msg" -ForegroundColor Cyan } }

$issues = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host ""
Write-Host "======================================"
Write-Host "Redis Health Check - $timestamp"
Write-Host "======================================"
Write-Host ""

# Test 1: Connection Check
Write-Info "Testing Redis connection..."
try {
    if ($RedisPassword) {
        $ping = & $MemuraiCliPath -a $RedisPassword PING 2>&1
    } else {
        $ping = & $MemuraiCliPath PING 2>&1
    }

    if ($ping -match "PONG") {
        Write-Success "Redis is running and accessible"
    } else {
        Write-Error "Redis PING failed: $ping"
        $issues += "Redis connection failed"
    }
} catch {
    Write-Error "Unable to connect to Redis: $_"
    $issues += "Redis connection error: $_"
}

# Test 2: Memory Usage
Write-Info "Checking memory usage..."
try {
    if ($RedisPassword) {
        $memInfo = & $MemuraiCliPath -a $RedisPassword INFO memory 2>&1 | Out-String
    } else {
        $memInfo = & $MemuraiCliPath INFO memory 2>&1 | Out-String
    }

    $usedMemory = ($memInfo | Select-String "used_memory_human:(.*)").Matches.Groups[1].Value.Trim()
    $maxMemory = ($memInfo | Select-String "maxmemory_human:(.*)").Matches.Groups[1].Value.Trim()
    $usedMemoryBytes = [long](($memInfo | Select-String "used_memory:(\d+)").Matches.Groups[1].Value)
    $maxMemoryBytes = [long](($memInfo | Select-String "maxmemory:(\d+)").Matches.Groups[1].Value)

    if ($maxMemoryBytes -gt 0) {
        $memoryPercent = [math]::Round(($usedMemoryBytes / $maxMemoryBytes) * 100, 2)

        if ($memoryPercent -ge $MemoryWarningThresholdPercent) {
            Write-Warning "Memory usage high: $usedMemory / $maxMemory ($memoryPercent%)"
            $issues += "High memory usage: $memoryPercent%"
        } else {
            Write-Success "Memory usage: $usedMemory / $maxMemory ($memoryPercent%)"
        }
    } else {
        Write-Success "Memory usage: $usedMemory (no maxmemory limit)"
    }
} catch {
    Write-Warning "Unable to check memory: $_"
}

# Test 3: Persistence Status (AOF)
Write-Info "Checking persistence status..."
try {
    if ($RedisPassword) {
        $persistInfo = & $MemuraiCliPath -a $RedisPassword INFO persistence 2>&1 | Out-String
    } else {
        $persistInfo = & $MemuraiCliPath INFO persistence 2>&1 | Out-String
    }

    $aofEnabled = ($persistInfo | Select-String "aof_enabled:(.*)").Matches.Groups[1].Value.Trim()
    $rdbLastSave = ($persistInfo | Select-String "rdb_last_save_time:(.*)").Matches.Groups[1].Value.Trim()
    $lastSaveTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$rdbLastSave).LocalDateTime

    if ($aofEnabled -eq "1") {
        Write-Success "AOF persistence: ENABLED"

        $aofLastRewrite = ($persistInfo | Select-String "aof_last_rewrite_time_sec:(.*)").Matches.Groups[1].Value.Trim()
        $aofLastWriteStatus = ($persistInfo | Select-String "aof_last_write_status:(.*)").Matches.Groups[1].Value.Trim()

        if ($aofLastWriteStatus -ne "ok") {
            Write-Error "AOF last write status: $aofLastWriteStatus"
            $issues += "AOF write error: $aofLastWriteStatus"
        }
    } else {
        Write-Warning "AOF persistence: DISABLED (only RDB enabled)"
    }

    Write-Success "RDB last save: $lastSaveTime"

    # Check if last save is recent (within 24 hours)
    $hoursSinceLastSave = ((Get-Date) - $lastSaveTime).TotalHours
    if ($hoursSinceLastSave -gt 24) {
        Write-Warning "Last RDB save was $([math]::Round($hoursSinceLastSave, 1)) hours ago"
    }
} catch {
    Write-Warning "Unable to check persistence: $_"
}

# Test 4: Replication Status (if configured)
Write-Info "Checking replication status..."
try {
    if ($RedisPassword) {
        $replInfo = & $MemuraiCliPath -a $RedisPassword INFO replication 2>&1 | Out-String
    } else {
        $replInfo = & $MemuraiCliPath INFO replication 2>&1 | Out-String
    }

    $role = ($replInfo | Select-String "role:(.*)").Matches.Groups[1].Value.Trim()

    if ($role -eq "master") {
        $connectedSlaves = ($replInfo | Select-String "connected_slaves:(.*)").Matches.Groups[1].Value.Trim()
        Write-Success "Role: MASTER with $connectedSlaves connected replica(s)"
    } elseif ($role -eq "slave") {
        $masterLinkStatus = ($replInfo | Select-String "master_link_status:(.*)").Matches.Groups[1].Value.Trim()

        if ($masterLinkStatus -eq "up") {
            Write-Success "Role: REPLICA (connected to master)"
        } else {
            Write-Error "Role: REPLICA (master link: $masterLinkStatus)"
            $issues += "Replica master link down: $masterLinkStatus"
        }
    }
} catch {
    Write-Info "Unable to check replication (may not be configured)"
}

# Test 5: Keyspace Statistics
Write-Info "Checking keyspace statistics..."
try {
    if ($RedisPassword) {
        $keyspaceInfo = & $MemuraiCliPath -a $RedisPassword INFO keyspace 2>&1 | Out-String
    } else {
        $keyspaceInfo = & $MemuraiCliPath INFO keyspace 2>&1 | Out-String
    }

    $dbLines = $keyspaceInfo | Select-String "db\d+:"
    if ($dbLines) {
        Write-Success "Keyspace statistics:"
        foreach ($line in $dbLines) {
            Write-Host "  $line" -ForegroundColor Cyan
        }
    } else {
        Write-Info "No keys in database"
    }
} catch {
    Write-Warning "Unable to check keyspace: $_"
}

# Test 6: Slow Log Check
Write-Info "Checking slow log..."
try {
    if ($RedisPassword) {
        $slowLog = & $MemuraiCliPath -a $RedisPassword SLOWLOG GET $SlowLogThreshold 2>&1 | Out-String
    } else {
        $slowLog = & $MemuraiCliPath SLOWLOG GET $SlowLogThreshold 2>&1 | Out-String
    }

    if ($slowLog -match "empty") {
        Write-Success "No slow queries in log"
    } else {
        $slowLogLines = ($slowLog -split "`n" | Measure-Object).Count
        if ($slowLogLines -gt 5) {
            Write-Warning "Found $slowLogLines slow queries - review with: memurai-cli SLOWLOG GET"
        } else {
            Write-Success "Slow log: $slowLogLines entries"
        }
    }
} catch {
    Write-Warning "Unable to check slow log: $_"
}

# Test 7: Client Connections
Write-Info "Checking client connections..."
try {
    if ($RedisPassword) {
        $clientInfo = & $MemuraiCliPath -a $RedisPassword INFO clients 2>&1 | Out-String
    } else {
        $clientInfo = & $MemuraiCliPath INFO clients 2>&1 | Out-String
    }

    $connectedClients = ($clientInfo | Select-String "connected_clients:(.*)").Matches.Groups[1].Value.Trim()
    $blockedClients = ($clientInfo | Select-String "blocked_clients:(.*)").Matches.Groups[1].Value.Trim()

    Write-Success "Connected clients: $connectedClients (blocked: $blockedClients)"
} catch {
    Write-Warning "Unable to check client connections: $_"
}

# Test 8: Server Info
Write-Info "Checking server info..."
try {
    if ($RedisPassword) {
        $serverInfo = & $MemuraiCliPath -a $RedisPassword INFO server 2>&1 | Out-String
    } else {
        $serverInfo = & $MemuraiCliPath INFO server 2>&1 | Out-String
    }

    $redisVersion = ($serverInfo | Select-String "redis_version:(.*)").Matches.Groups[1].Value.Trim()
    $uptimeSeconds = [long](($serverInfo | Select-String "uptime_in_seconds:(.*)").Matches.Groups[1].Value.Trim())
    $uptimeDays = [math]::Round($uptimeSeconds / 86400, 2)

    Write-Success "Redis version: $redisVersion"
    Write-Success "Uptime: $uptimeDays days"
} catch {
    Write-Warning "Unable to check server info: $_"
}

# Summary
Write-Host ""
Write-Host "======================================"
Write-Host "Health Check Summary"
Write-Host "======================================"

if ($issues.Count -eq 0) {
    Write-Success "ALL CHECKS PASSED - Redis is healthy!"
    exit 0
} else {
    Write-Error "ISSUES FOUND ($($issues.Count)):"
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }

    # Optional: Send alert email (requires SMTP configuration)
    if ($AlertEmail) {
        Write-Info "Sending alert email to $AlertEmail..."
        # TODO: Implement email alert using Send-MailMessage
    }

    exit 1
}
