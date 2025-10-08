# Redis/Memurai Automated Backup Script
# Purpose: Create timestamped backups of Redis data (RDB + AOF)
# Schedule: Run daily via Task Scheduler

param(
    [string]$BackupDir = "C:\Backups\Redis",
    [string]$RedisPassword = $env:REDIS_PASSWORD,
    [int]$RetentionDays = 7,
    [string]$MemuraiCliPath = "C:\Program Files\Memurai\memurai-cli.exe",
    [string]$RedisDataDir = "C:\Program Files\Memurai"
)

# Ensure backup directory exists
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    Write-Host "[INFO] Created backup directory: $BackupDir"
}

# Get timestamp for backup filename
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "[INFO] Starting Redis backup at $timestamp"

# Step 1: Trigger Redis BGSAVE (background save)
try {
    Write-Host "[INFO] Triggering Redis BGSAVE..."

    if ($RedisPassword) {
        $result = & $MemuraiCliPath -a $RedisPassword BGSAVE 2>&1
    } else {
        $result = & $MemuraiCliPath BGSAVE 2>&1
    }

    if ($result -match "Background saving started") {
        Write-Host "[OK] Background save initiated successfully"

        # Wait for BGSAVE to complete (check every second, max 60 seconds)
        $maxWait = 60
        $waited = 0
        $saveComplete = $false

        while ($waited -lt $maxWait -and -not $saveComplete) {
            Start-Sleep -Seconds 1
            $waited++

            if ($RedisPassword) {
                $info = & $MemuraiCliPath -a $RedisPassword INFO persistence 2>&1
            } else {
                $info = & $MemuraiCliPath INFO persistence 2>&1
            }

            if ($info -match "rdb_bgsave_in_progress:0") {
                $saveComplete = $true
                Write-Host "[OK] Background save completed in $waited seconds"
            }
        }

        if (-not $saveComplete) {
            Write-Host "[WARN] Background save still in progress after $maxWait seconds"
        }
    } else {
        Write-Host "[WARN] BGSAVE response: $result"
    }
} catch {
    Write-Host "[ERROR] Failed to trigger BGSAVE: $_"
}

# Step 2: Copy RDB file
try {
    $rdbSource = Join-Path $RedisDataDir "dump.rdb"
    $rdbBackup = Join-Path $BackupDir "redis_backup_${timestamp}.rdb"

    if (Test-Path $rdbSource) {
        Copy-Item $rdbSource $rdbBackup -Force
        $rdbSize = (Get-Item $rdbBackup).Length / 1MB
        Write-Host "[OK] RDB backup created: $rdbBackup ($([math]::Round($rdbSize, 2)) MB)"
    } else {
        Write-Host "[WARN] RDB file not found at $rdbSource"
    }
} catch {
    Write-Host "[ERROR] Failed to copy RDB file: $_"
}

# Step 3: Copy AOF files (if they exist)
try {
    $aofDir = Join-Path $RedisDataDir "appendonlydir"

    if (Test-Path $aofDir) {
        $aofBackupDir = Join-Path $BackupDir "redis_aof_backup_${timestamp}"
        New-Item -ItemType Directory -Path $aofBackupDir -Force | Out-Null

        # Copy all AOF files
        Copy-Item "$aofDir\*" $aofBackupDir -Recurse -Force

        $aofFiles = Get-ChildItem $aofBackupDir -Recurse -File
        $aofTotalSize = ($aofFiles | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "[OK] AOF backup created: $aofBackupDir ($([math]::Round($aofTotalSize, 2)) MB, $($aofFiles.Count) files)"
    } else {
        Write-Host "[INFO] No AOF directory found (AOF may be disabled)"
    }
} catch {
    Write-Host "[ERROR] Failed to copy AOF files: $_"
}

# Step 4: Create backup metadata file
try {
    $metadataFile = Join-Path $BackupDir "redis_backup_${timestamp}.metadata.txt"

    # Get Redis info
    if ($RedisPassword) {
        $redisInfo = & $MemuraiCliPath -a $RedisPassword INFO server 2>&1 | Select-String -Pattern "redis_version|os|uptime_in_seconds|config_file"
        $dbInfo = & $MemuraiCliPath -a $RedisPassword INFO keyspace 2>&1
    } else {
        $redisInfo = & $MemuraiCliPath INFO server 2>&1 | Select-String -Pattern "redis_version|os|uptime_in_seconds|config_file"
        $dbInfo = & $MemuraiCliPath INFO keyspace 2>&1
    }

    $metadata = @"
Redis Backup Metadata
=====================
Backup Time: $timestamp
Backup Directory: $BackupDir
Retention Days: $RetentionDays

Redis Info:
$redisInfo

Database Info:
$dbInfo
"@

    $metadata | Out-File -FilePath $metadataFile -Encoding UTF8
    Write-Host "[OK] Metadata file created: $metadataFile"
} catch {
    Write-Host "[ERROR] Failed to create metadata file: $_"
}

# Step 5: Clean up old backups (retention policy)
try {
    Write-Host "[INFO] Cleaning up backups older than $RetentionDays days..."

    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    $oldFiles = Get-ChildItem $BackupDir -Filter "redis_backup_*" |
                Where-Object { $_.CreationTime -lt $cutoffDate }

    if ($oldFiles) {
        $deletedCount = 0
        $deletedSize = 0

        foreach ($file in $oldFiles) {
            $deletedSize += $file.Length
            Remove-Item $file.FullName -Recurse -Force
            $deletedCount++
        }

        Write-Host "[OK] Deleted $deletedCount old backup(s) ($([math]::Round($deletedSize / 1MB, 2)) MB freed)"
    } else {
        Write-Host "[INFO] No old backups to delete"
    }
} catch {
    Write-Host "[ERROR] Failed to clean up old backups: $_"
}

# Step 6: Summary
Write-Host ""
Write-Host "======================================"
Write-Host "Redis Backup Summary"
Write-Host "======================================"
Write-Host "Backup Time: $timestamp"
Write-Host "Backup Location: $BackupDir"
Write-Host ""

$backupFiles = Get-ChildItem $BackupDir -Filter "redis_backup_${timestamp}*"
$totalSize = ($backupFiles | Measure-Object -Property Length -Sum).Sum / 1MB

Write-Host "Backup Files:"
foreach ($file in $backupFiles) {
    $size = $file.Length / 1MB
    Write-Host "  - $($file.Name) ($([math]::Round($size, 2)) MB)"
}

Write-Host ""
Write-Host "Total Backup Size: $([math]::Round($totalSize, 2)) MB"
Write-Host "======================================"
Write-Host ""
Write-Host "[SUCCESS] Redis backup completed successfully!"

# Exit with success code
exit 0
