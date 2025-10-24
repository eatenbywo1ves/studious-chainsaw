# ============================================================================
# Docker Volume Backup - Automated Scheduling Setup
# B-MAD Implementation - Phase 2: Backup Automation
# ============================================================================
# Purpose: Configure Windows Task Scheduler for automated daily backups
# Usage: Run as Administrator
#        .\setup-backup-automation.ps1
# ============================================================================

#Requires -RunAsAdministrator

param(
    [string]$BackupTime = "02:00",  # Default: 2 AM daily
    [string]$TaskName = "DockerVolumeBackup-Daily",
    [string]$ScriptPath = "C:\Users\Corbin\development\docker-volume-backup.ps1"
)

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    $colors = @{
        "INFO" = "White"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    Write-Host $logMessage -ForegroundColor $colors[$Level]
}

# ============================================================================
# Main Setup
# ============================================================================

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Docker Volume Backup Automation Setup" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Check if backup script exists
if (-not (Test-Path $ScriptPath)) {
    Write-Log "Backup script not found at: $ScriptPath" "ERROR"
    exit 1
}

Write-Log "Found backup script: $ScriptPath" "SUCCESS"

# Create the scheduled task action
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$ScriptPath`" -Action Backup"

# Create the trigger (daily at specified time)
$trigger = New-ScheduledTaskTrigger -Daily -At $BackupTime

# Create the principal (run whether user is logged on or not)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Create settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

# Check if task already exists
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($existingTask) {
    Write-Log "Task '$TaskName' already exists, removing..." "WARNING"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Register the scheduled task
try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Automated daily backup of critical Docker volumes at $BackupTime"

    Write-Log "Scheduled task created successfully!" "SUCCESS"
    Write-Log "Task Name: $TaskName" "INFO"
    Write-Log "Schedule: Daily at $BackupTime" "INFO"
    Write-Log "Script: $ScriptPath" "INFO"

    # Display task information
    Write-Host "`n=== Scheduled Task Details ===" -ForegroundColor Cyan
    Get-ScheduledTask -TaskName $TaskName | Format-List TaskName, State, TaskPath

    Write-Host "`n=== Next Run Times ===" -ForegroundColor Cyan
    (Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo).NextRunTime

    Write-Log "`nTo manually run the task: schtasks /run /tn `"$TaskName`"" "INFO"
    Write-Log "To view task logs: Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' | Where-Object {`$_.Message -like '*$TaskName*'}" "INFO"

} catch {
    Write-Log "Failed to create scheduled task: $_" "ERROR"
    exit 1
}

# ============================================================================
# End of Script
# ============================================================================
