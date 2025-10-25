# ============================================================================
# Docker Log Rotation Configuration
# B-MAD Implementation - Phase 3: Log Rotation
# ============================================================================
# Purpose: Apply log rotation settings to Docker daemon
# Usage: Run as Administrator
#        .\apply-docker-log-rotation.ps1
# ============================================================================

#Requires -RunAsAdministrator

param(
    [string]$DaemonJsonPath = "$env:USERPROFILE\.docker\daemon.json",
    [switch]$SkipRestart
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
# Main Execution
# ============================================================================

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Docker Log Rotation Configuration" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Check if daemon.json exists
if (-not (Test-Path $DaemonJsonPath)) {
    Write-Log "daemon.json not found at: $DaemonJsonPath" "ERROR"
    exit 1
}

# Read and validate daemon.json
try {
    $config = Get-Content $DaemonJsonPath | ConvertFrom-Json
    Write-Log "Current daemon.json configuration:" "INFO"
    Write-Host ($config | ConvertTo-Json -Depth 10) -ForegroundColor Gray
} catch {
    Write-Log "Failed to parse daemon.json: $_" "ERROR"
    exit 1
}

# Verify log rotation settings
if ($config."log-opts") {
    Write-Log "`nLog rotation settings found:" "SUCCESS"
    Write-Host "  Max Size: $($config.'log-opts'.'max-size')" -ForegroundColor White
    Write-Host "  Max Files: $($config.'log-opts'.'max-file')" -ForegroundColor White
    Write-Host "  Compression: $($config.'log-opts'.compress)" -ForegroundColor White
} else {
    Write-Log "No log rotation settings found in daemon.json" "WARNING"
    exit 1
}

# Check Docker service status
$dockerService = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue

if (-not $dockerService) {
    Write-Log "Docker service not found. Are you running Docker Desktop?" "ERROR"
    exit 1
}

Write-Log "`nCurrent Docker service status: $($dockerService.Status)" "INFO"

if ($SkipRestart) {
    Write-Log "Skipping Docker restart (-SkipRestart specified)" "WARNING"
    Write-Log "Changes will take effect after manual Docker restart" "WARNING"
    exit 0
}

# Restart Docker to apply changes
Write-Log "`nRestarting Docker Desktop to apply log rotation settings..." "WARNING"
Write-Host "This will temporarily stop all running containers..." -ForegroundColor Yellow

$confirmation = Read-Host "`nType 'YES' to restart Docker Desktop"
if ($confirmation -ne "YES") {
    Write-Log "Restart cancelled by user" "INFO"
    Write-Log "To apply changes manually, restart Docker Desktop from the system tray" "INFO"
    exit 0
}

try {
    # Stop Docker Desktop
    Write-Log "Stopping Docker Desktop..." "INFO"
    Stop-Process -Name "Docker Desktop" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    # Stop Docker service
    Stop-Service -Name "com.docker.service" -Force
    Start-Sleep -Seconds 3

    # Start Docker service
    Write-Log "Starting Docker Desktop..." "INFO"
    Start-Service -Name "com.docker.service"
    Start-Sleep -Seconds 5

    # Start Docker Desktop GUI
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

    Write-Log "Waiting for Docker to be ready..." "INFO"
    $maxAttempts = 30
    $attempt = 0

    while ($attempt -lt $maxAttempts) {
        try {
            $result = docker info 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Docker is ready!" "SUCCESS"
                break
            }
        } catch {}

        $attempt++
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 2
    }

    if ($attempt -ge $maxAttempts) {
        Write-Log "`nDocker failed to start within expected time" "WARNING"
        Write-Log "Please check Docker Desktop manually" "WARNING"
        exit 1
    }

    Write-Host ""
    Write-Log "Docker restarted successfully!" "SUCCESS"

} catch {
    Write-Log "Failed to restart Docker: $_" "ERROR"
    exit 1
}

# Verify new settings
Write-Log "`nVerifying log rotation configuration..." "INFO"
$logDriver = docker info --format '{{.LoggingDriver}}'
Write-Host "  Logging Driver: $logDriver" -ForegroundColor White

# Create test container to verify settings
Write-Log "`nCreating test container to verify log rotation..." "INFO"
docker run --name log-rotation-test --rm -d busybox sh -c "while true; do echo 'Test log entry'; sleep 1; done" | Out-Null
Start-Sleep -Seconds 5

# Check container log configuration
$containerInfo = docker inspect log-rotation-test | ConvertFrom-Json
$logConfig = $containerInfo[0].HostConfig.LogConfig

Write-Host "  Container Log Config:" -ForegroundColor White
Write-Host "    Driver: $($logConfig.Type)" -ForegroundColor Gray
Write-Host "    Max-Size: $($logConfig.Config.'max-size')" -ForegroundColor Gray
Write-Host "    Max-File: $($logConfig.Config.'max-file')" -ForegroundColor Gray

# Stop test container
docker stop log-rotation-test | Out-Null

Write-Log "`nLog rotation configuration applied successfully!" "SUCCESS"
Write-Log "All new containers will use these log rotation settings" "INFO"
Write-Log "Existing containers will need to be recreated to use new settings" "INFO"

# ============================================================================
# End of Script
# ============================================================================
