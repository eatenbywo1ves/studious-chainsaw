# Setup Redis Scheduled Tasks
# Purpose: Register daily backups and health monitoring in Windows Task Scheduler
# Run as Administrator

param(
    [switch]$UninstallOnly = $false
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "======================================"
Write-Host "Redis Scheduled Tasks Setup"
Write-Host "======================================"
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Task definitions
$tasks = @(
    @{
        Name = "Redis-Daily-Backup"
        Description = "Daily Redis backup at 2 AM"
        XmlFile = Join-Path $scriptDir "task-scheduler-redis-backup.xml"
    },
    @{
        Name = "Redis-Health-Check"
        Description = "Redis health monitoring every 15 minutes"
        XmlFile = Join-Path $scriptDir "task-scheduler-redis-health.xml"
    }
)

# Uninstall existing tasks if they exist
Write-Host "[INFO] Checking for existing tasks..."
foreach ($task in $tasks) {
    $existingTask = Get-ScheduledTask -TaskName $task.Name -ErrorAction SilentlyContinue

    if ($existingTask) {
        Write-Host "[INFO] Removing existing task: $($task.Name)..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $task.Name -Confirm:$false
        Write-Host "[OK] Task removed: $($task.Name)" -ForegroundColor Green
    }
}

if ($UninstallOnly) {
    Write-Host ""
    Write-Host "[SUCCESS] All Redis scheduled tasks have been removed." -ForegroundColor Green
    exit 0
}

# Create logs directory if it doesn't exist
$logsDir = Join-Path $scriptDir "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    Write-Host "[INFO] Created logs directory: $logsDir"
}

# Create backups directory if it doesn't exist
$backupsDir = "C:\Backups\Redis"
if (-not (Test-Path $backupsDir)) {
    New-Item -ItemType Directory -Path $backupsDir -Force | Out-Null
    Write-Host "[INFO] Created backups directory: $backupsDir"
}

# Register new tasks
Write-Host ""
Write-Host "[INFO] Registering new scheduled tasks..."
Write-Host ""

foreach ($task in $tasks) {
    if (-not (Test-Path $task.XmlFile)) {
        Write-Host "[ERROR] XML file not found: $($task.XmlFile)" -ForegroundColor Red
        continue
    }

    try {
        Register-ScheduledTask -Xml (Get-Content $task.XmlFile | Out-String) -TaskName $task.Name -Force | Out-Null
        Write-Host "[OK] Registered: $($task.Name)" -ForegroundColor Green
        Write-Host "    Description: $($task.Description)" -ForegroundColor Cyan
    } catch {
        Write-Host "[ERROR] Failed to register $($task.Name): $_" -ForegroundColor Red
    }
}

# Verify tasks were created
Write-Host ""
Write-Host "[INFO] Verifying task registration..."
Write-Host ""

$allSuccess = $true
foreach ($task in $tasks) {
    $scheduledTask = Get-ScheduledTask -TaskName $task.Name -ErrorAction SilentlyContinue

    if ($scheduledTask) {
        $state = $scheduledTask.State
        $nextRun = (Get-ScheduledTaskInfo -TaskName $task.Name).NextRunTime

        Write-Host "[OK] Task: $($task.Name)" -ForegroundColor Green
        Write-Host "    State: $state" -ForegroundColor Cyan
        Write-Host "    Next Run: $nextRun" -ForegroundColor Cyan
    } else {
        Write-Host "[ERROR] Task not found: $($task.Name)" -ForegroundColor Red
        $allSuccess = $false
    }
}

# Summary
Write-Host ""
Write-Host "======================================"
Write-Host "Setup Summary"
Write-Host "======================================"

if ($allSuccess) {
    Write-Host ""
    Write-Host "[SUCCESS] All scheduled tasks configured successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Scheduled Tasks:" -ForegroundColor Cyan
    Write-Host "  1. Redis-Daily-Backup    - Daily at 2:00 AM"
    Write-Host "  2. Redis-Health-Check    - Every 15 minutes"
    Write-Host ""
    Write-Host "Logs Location:" -ForegroundColor Cyan
    Write-Host "  $logsDir"
    Write-Host ""
    Write-Host "Backups Location:" -ForegroundColor Cyan
    Write-Host "  $backupsDir"
    Write-Host ""
    Write-Host "To view tasks in Task Scheduler:" -ForegroundColor Yellow
    Write-Host "  1. Press Win+R"
    Write-Host "  2. Type: taskschd.msc"
    Write-Host "  3. Look for 'Redis-Daily-Backup' and 'Redis-Health-Check'"
    Write-Host ""
    Write-Host "To test tasks manually:" -ForegroundColor Yellow
    Write-Host "  Start-ScheduledTask -TaskName 'Redis-Daily-Backup'"
    Write-Host "  Start-ScheduledTask -TaskName 'Redis-Health-Check'"
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "[ERROR] Some tasks failed to configure. Check errors above." -ForegroundColor Red
    Write-Host ""
}
