# Comprehensive Security Monitoring Script
# Run this daily or set up as scheduled task

param(
    [string]$LogPath = "C:\Users\Corbin\development\security_logs",
    [switch]$SendAlert
)

$report = @{}
$alerts = @()

Write-Host "=== Security Monitor Starting ===" -ForegroundColor Cyan
$date = Get-Date -Format "yyyy-MM-dd_HHmmss"

# 1. Check for unusual SSH connections
Write-Host "Checking SSH connections..." -ForegroundColor Yellow
$sshEvents = Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'} -MaxEvents 100 -ErrorAction SilentlyContinue
$suspiciousIPs = $sshEvents | Where-Object {
    $_.Message -match "(\d+\.\d+\.\d+\.\d+)" -and 
    $Matches[1] -notmatch "^100\.|^127\.|^192\.168\.|^::1"
}
if ($suspiciousIPs) {
    $alerts += "ALERT: SSH connections from unexpected IPs detected"
    $report['SSH_Suspicious'] = $suspiciousIPs | Select-Object TimeCreated, Message
}

# 2. Check for new listening ports
Write-Host "Checking for new listening ports..." -ForegroundColor Yellow
$currentPorts = netstat -an | findstr "LISTENING" | ForEach-Object {
    if ($_ -match ":(\d+)\s+") { $Matches[1] }
} | Sort-Object -Unique

$knownPorts = @(22, 135, 445, 3389, 5040, 5357) # Add your known ports
$newPorts = $currentPorts | Where-Object { $_ -notin $knownPorts }
if ($newPorts) {
    $alerts += "ALERT: New listening ports detected: $($newPorts -join ', ')"
    $report['New_Ports'] = $newPorts
}

# 3. Check for failed login attempts
Write-Host "Checking failed login attempts..." -ForegroundColor Yellow
$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
} -MaxEvents 50 -ErrorAction SilentlyContinue

if ($failedLogins.Count -gt 10) {
    $alerts += "ALERT: $($failedLogins.Count) failed login attempts in recent logs"
    $report['Failed_Logins'] = $failedLogins | Group-Object -Property {$_.Properties[5].Value} | 
        Select-Object Count, Name | Sort-Object Count -Descending
}

# 4. Check Tailscale status
Write-Host "Checking Tailscale status..." -ForegroundColor Yellow
$tailscaleStatus = tailscale status 2>&1
if ($tailscaleStatus -match "Logged out|NoState") {
    $alerts += "ALERT: Tailscale is not connected"
}

# 5. Check for unauthorized scheduled tasks
Write-Host "Checking scheduled tasks..." -ForegroundColor Yellow
$recentTasks = Get-ScheduledTask | Where-Object {
    $_.Date -gt (Get-Date).AddDays(-7) -and
    $_.Author -notmatch "Microsoft|Windows"
}
if ($recentTasks) {
    $alerts += "ALERT: New non-Microsoft scheduled tasks detected"
    $report['New_Tasks'] = $recentTasks | Select-Object TaskName, Author, Date
}

# 6. Check for unusual processes
Write-Host "Checking for unusual processes..." -ForegroundColor Yellow
$suspiciousProcesses = Get-Process | Where-Object {
    $_.Path -and (
        $_.Path -match "\\AppData\\Local\\Temp\\" -or
        $_.Path -match "\\Downloads\\" -or
        $_.ProcessName -match "^[a-z]{8}$"  # Random 8-char names
    )
}
if ($suspiciousProcesses) {
    $alerts += "WARNING: Potentially suspicious processes detected"
    $report['Suspicious_Processes'] = $suspiciousProcesses | Select-Object ProcessName, Path, StartTime
}

# 7. Check SSH key modifications
Write-Host "Checking SSH keys..." -ForegroundColor Yellow
$sshPath = "C:\Users\Corbin\.ssh"
$keyFiles = Get-ChildItem $sshPath -File | Where-Object {
    $_.LastWriteTime -gt (Get-Date).AddDays(-1)
}
if ($keyFiles) {
    $alerts += "ALERT: SSH keys were recently modified"
    $report['SSH_Key_Changes'] = $keyFiles | Select-Object Name, LastWriteTime
}

# 8. Check Windows Defender status
Write-Host "Checking Windows Defender..." -ForegroundColor Yellow
$defenderStatus = Get-MpComputerStatus
if (-not $defenderStatus.RealTimeProtectionEnabled) {
    $alerts += "CRITICAL: Windows Defender Real-Time Protection is disabled!"
}
if ($defenderStatus.QuickScanAge -gt 7) {
    $alerts += "WARNING: Windows Defender scan is overdue (last: $($defenderStatus.QuickScanAge) days ago)"
}

# Generate Report
Write-Host "`n=== Security Report ===" -ForegroundColor Green
if ($alerts.Count -eq 0) {
    Write-Host "✓ No security issues detected" -ForegroundColor Green
} else {
    Write-Host "⚠ $($alerts.Count) issue(s) found:" -ForegroundColor Yellow
    $alerts | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

# Save detailed log
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$logFile = Join-Path $LogPath "security_audit_$date.json"
$report['Timestamp'] = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report['Alerts'] = $alerts
$report | ConvertTo-Json -Depth 5 | Out-File $logFile

Write-Host "`nDetailed report saved to: $logFile" -ForegroundColor Cyan

# Optional: Send email alert
if ($SendAlert -and $alerts.Count -gt 0) {
    # Configure email settings here
    # Send-MailMessage -To "your@email.com" -Subject "Security Alert" -Body ($alerts -join "`n")
}

# Return status code
exit $alerts.Count