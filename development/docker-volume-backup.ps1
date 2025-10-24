# ============================================================================
# Docker Volume Backup Automation Script
# B-MAD Implementation - Phase 2: Volume Backup
# ============================================================================
# Created: 2025-10-22
# Purpose: Automated backup and restoration of Docker volumes
# Usage:
#   Backup all volumes:     .\docker-volume-backup.ps1 -Action Backup
#   Backup specific volume: .\docker-volume-backup.ps1 -Action Backup -VolumeName prometheus_data
#   Restore volume:         .\docker-volume-backup.ps1 -Action Restore -VolumeName prometheus_data -BackupFile backup.tar.gz
#   List backups:           .\docker-volume-backup.ps1 -Action List
# ============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Backup", "Restore", "List", "Verify")]
    [string]$Action,

    [string]$VolumeName = "",
    [string]$BackupFile = "",
    [string]$BackupDir = "C:\Users\Corbin\development\backups\docker-volumes"
)

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Critical volumes that should be backed up
$CriticalVolumes = @(
    "development_prometheus_data",
    "development_grafana_data",
    "development_postgres_data",
    "development_redis_data",
    "monitoring_prometheus_data",
    "monitoring_grafana_data"
)

# ============================================================================
# Functions
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    $colors = @{
        "INFO" = "White"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$ts] [$Level] $Message"

    Write-Host $logMessage -ForegroundColor $colors[$Level]
}

function Ensure-BackupDir {
    if (-not (Test-Path $BackupDir)) {
        Write-Log "Creating backup directory: $BackupDir" "INFO"
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
}

function Get-VolumeSize {
    param([string]$Volume)

    try {
        $result = docker run --rm -v "${Volume}:/data" busybox du -sh /data 2>&1
        if ($LASTEXITCODE -eq 0) {
            return ($result -split '\s+')[0]
        }
        return "Unknown"
    } catch {
        return "Unknown"
    }
}

function Backup-Volume {
    param([string]$Volume)

    Write-Log "Starting backup of volume: $Volume" "INFO"

    # Check if volume exists
    $volumeExists = docker volume inspect $Volume 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Volume $Volume does not exist" "ERROR"
        return $false
    }

    # Get volume size
    $size = Get-VolumeSize -Volume $Volume
    Write-Log "Volume size: $size" "INFO"

    # Create backup filename
    $backupFileName = "${Volume}_${timestamp}.tar"
    $backupPath = Join-Path $BackupDir $backupFileName

    Write-Log "Backing up to: $backupPath" "INFO"

    # Create backup using a temporary container
    try {
        # Backup volume to tar file
        docker run --rm -v "${Volume}:/data" -v "${BackupDir}:/backup" busybox tar -czf "/backup/${backupFileName}.gz" -C /data .

        if ($LASTEXITCODE -eq 0) {
            $backupSize = [math]::Round((Get-Item "$backupPath.gz").Length / 1MB, 2)
            Write-Log "Backup completed successfully: ${backupFileName}.gz ($backupSize MB)" "SUCCESS"

            # Create metadata file
            $metadata = @{
                volume = $Volume
                timestamp = $timestamp
                size = $size
                backupFile = "${backupFileName}.gz"
                backupSize = "$backupSize MB"
                hostname = $env:COMPUTERNAME
            }

            $metadata | ConvertTo-Json | Out-File "$backupPath.meta.json"

            return $true
        } else {
            Write-Log "Backup failed for volume: $Volume" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Exception during backup: $_" "ERROR"
        return $false
    }
}

function Restore-Volume {
    param(
        [string]$Volume,
        [string]$BackupFilePath
    )

    Write-Log "Starting restore of volume: $Volume" "WARNING"

    # Check if backup file exists
    if (-not (Test-Path $BackupFilePath)) {
        Write-Log "Backup file not found: $BackupFilePath" "ERROR"
        return $false
    }

    # Verify it's a tar.gz file
    if (-not ($BackupFilePath -match '\.tar\.gz$')) {
        Write-Log "Backup file must be a .tar.gz file" "ERROR"
        return $false
    }

    # Check if volume exists, create if not
    $volumeExists = docker volume inspect $Volume 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Volume $Volume does not exist, creating..." "WARNING"
        docker volume create $Volume
    } else {
        Write-Log "WARNING: Volume $Volume exists and will be OVERWRITTEN!" "WARNING"
        $confirmation = Read-Host "Type 'YES' to confirm restoration (this will DELETE existing data)"
        if ($confirmation -ne "YES") {
            Write-Log "Restoration cancelled by user" "INFO"
            return $false
        }
    }

    # Get backup file info
    $backupSize = [math]::Round((Get-Item $BackupFilePath).Length / 1MB, 2)
    Write-Log "Restoring from: $BackupFilePath ($backupSize MB)" "INFO"

    try {
        # Copy backup file to a location accessible by Docker
        $tempBackupName = Split-Path $BackupFilePath -Leaf

        # Restore volume from tar.gz file
        docker run --rm -v "${Volume}:/data" -v "${BackupDir}:/backup" busybox sh -c "rm -rf /data/* /data/..?* /data/.[!.]* 2>/dev/null; tar -xzf /backup/${tempBackupName} -C /data"

        if ($LASTEXITCODE -eq 0) {
            Write-Log "Restore completed successfully for volume: $Volume" "SUCCESS"
            return $true
        } else {
            Write-Log "Restore failed for volume: $Volume" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Exception during restore: $_" "ERROR"
        return $false
    }
}

function List-Backups {
    Write-Log "Listing all backups in: $BackupDir" "INFO"

    if (-not (Test-Path $BackupDir)) {
        Write-Log "No backup directory found" "WARNING"
        return
    }

    $backups = Get-ChildItem "$BackupDir\*.tar.gz" | Sort-Object LastWriteTime -Descending

    if ($backups.Count -eq 0) {
        Write-Log "No backups found" "WARNING"
        return
    }

    Write-Host "`n=== AVAILABLE BACKUPS ===" -ForegroundColor Cyan
    Write-Host ("{0,-50} {1,-15} {2,-20}" -f "Backup File", "Size (MB)", "Created") -ForegroundColor Cyan
    Write-Host ("{0}" -f ("-" * 85)) -ForegroundColor Cyan

    foreach ($backup in $backups) {
        $size = [math]::Round($backup.Length / 1MB, 2)
        $created = $backup.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

        # Try to find metadata
        $metaFile = "$($backup.FullName).meta.json"
        if (Test-Path $metaFile) {
            $meta = Get-Content $metaFile | ConvertFrom-Json
            Write-Host ("{0,-50} {1,-15} {2,-20}" -f $backup.Name, $size, $created) -ForegroundColor White
            Write-Host ("  Volume: {0}, Original Size: {1}" -f $meta.volume, $meta.size) -ForegroundColor Gray
        } else {
            Write-Host ("{0,-50} {1,-15} {2,-20}" -f $backup.Name, $size, $created) -ForegroundColor White
        }
    }

    Write-Host ""
}

function Verify-Backup {
    param([string]$BackupFilePath)

    Write-Log "Verifying backup: $BackupFilePath" "INFO"

    if (-not (Test-Path $BackupFilePath)) {
        Write-Log "Backup file not found: $BackupFilePath" "ERROR"
        return $false
    }

    try {
        # Test tar.gz integrity
        docker run --rm -v "${BackupDir}:/backup" busybox tar -tzf "/backup/$(Split-Path $BackupFilePath -Leaf)" > $null

        if ($LASTEXITCODE -eq 0) {
            Write-Log "Backup verification successful: $BackupFilePath" "SUCCESS"
            return $true
        } else {
            Write-Log "Backup verification failed: $BackupFilePath" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Exception during verification: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Docker Volume Backup Automation" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

Ensure-BackupDir

switch ($Action) {
    "Backup" {
        if ($VolumeName) {
            # Backup single volume
            $success = Backup-Volume -Volume $VolumeName
            if ($success) { exit 0 } else { exit 1 }
        } else {
            # Backup all critical volumes
            Write-Log "Backing up all critical volumes..." "INFO"
            $successCount = 0
            $failCount = 0

            foreach ($volume in $CriticalVolumes) {
                if (Backup-Volume -Volume $volume) {
                    $successCount++
                } else {
                    $failCount++
                }
                Write-Host ""
            }

            Write-Log "Backup Summary: $successCount successful, $failCount failed" "INFO"
            if ($failCount -eq 0) { exit 0 } else { exit 1 }
        }
    }

    "Restore" {
        if (-not $VolumeName -or -not $BackupFile) {
            Write-Log "ERROR: VolumeName and BackupFile are required for restore" "ERROR"
            Write-Host "Usage: .\docker-volume-backup.ps1 -Action Restore -VolumeName volumeName -BackupFile backup.tar.gz"
            exit 1
        }

        $backupPath = if ([System.IO.Path]::IsPathRooted($BackupFile)) {
            $BackupFile
        } else {
            Join-Path $BackupDir $BackupFile
        }

        $success = Restore-Volume -Volume $VolumeName -BackupFilePath $backupPath
        if ($success) { exit 0 } else { exit 1 }
    }

    "List" {
        List-Backups
        exit 0
    }

    "Verify" {
        if (-not $BackupFile) {
            Write-Log "ERROR: BackupFile is required for verify" "ERROR"
            exit 1
        }

        $backupPath = if ([System.IO.Path]::IsPathRooted($BackupFile)) {
            $BackupFile
        } else {
            Join-Path $BackupDir $BackupFile
        }

        $success = Verify-Backup -BackupFilePath $backupPath
        if ($success) { exit 0 } else { exit 1 }
    }
}

# ============================================================================
# End of Script
# ============================================================================
