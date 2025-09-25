# GitHub Token Automation Scripts
# Automated rotation, monitoring, and security checks

# ============================================
# Token Monitoring Functions
# ============================================

function Start-GitHubTokenMonitor {
    <#
    .SYNOPSIS
    Monitor GitHub token usage and health
    
    .DESCRIPTION
    Continuously monitors token rate limits, expiration, and unusual activity
    
    .PARAMETER CheckInterval
    Interval in minutes between checks (default: 60)
    
    .PARAMETER LogPath
    Path to save monitoring logs
    #>
    [CmdletBinding()]
    param(
        [int]$CheckInterval = 60,
        [string]$LogPath = "C:\Users\Corbin\development\github-token-management\monitoring-logs"
    )
    
    Write-Host "Starting GitHub Token Monitor..." -ForegroundColor Cyan
    
    # Create log directory if it doesn't exist
    if (!(Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
    
    while ($true) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logFile = Join-Path $LogPath "token-monitor-$(Get-Date -Format 'yyyy-MM-dd').log"
        
        try {
            # Check rate limit
            $rateLimit = gh api rate_limit --jq '.rate' | ConvertFrom-Json
            $percentUsed = [math]::Round(($rateLimit.used / $rateLimit.limit) * 100, 2)
            
            # Check authentication status
            $authStatus = gh auth status 2>&1
            $isAuthenticated = $authStatus -match "Logged in"
            
            # Create log entry
            $logEntry = @{
                Timestamp = $timestamp
                Authenticated = $isAuthenticated
                RateLimit = @{
                    Used = $rateLimit.used
                    Limit = $rateLimit.limit
                    Remaining = $rateLimit.remaining
                    PercentUsed = $percentUsed
                }
            }
            
            # Check for warnings
            $warnings = @()
            
            if ($percentUsed -gt 80) {
                $warnings += "High API usage: ${percentUsed}%"
            }
            
            if ($rateLimit.remaining -lt 100) {
                $warnings += "Low rate limit remaining: $($rateLimit.remaining)"
            }
            
            if (!$isAuthenticated) {
                $warnings += "Authentication failed"
            }
            
            if ($warnings.Count -gt 0) {
                $logEntry.Warnings = $warnings
                Write-Host "⚠ Warnings detected at ${timestamp}:" -ForegroundColor Yellow
                $warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
            }
            
            # Write to log file
            $logEntry | ConvertTo-Json -Compress | Add-Content -Path $logFile
            
            # Display status
            Write-Host "[$timestamp] Rate: $($rateLimit.used)/$($rateLimit.limit) (${percentUsed}%) | Auth: $isAuthenticated" -ForegroundColor Gray
            
        } catch {
            Write-Host "Error monitoring token: $_" -ForegroundColor Red
            @{
                Timestamp = $timestamp
                Error = $_.ToString()
            } | ConvertTo-Json -Compress | Add-Content -Path $logFile
        }
        
        # Wait for next check
        Start-Sleep -Seconds ($CheckInterval * 60)
    }
}

function Get-GitHubTokenUsageReport {
    <#
    .SYNOPSIS
    Generate a usage report for GitHub tokens
    
    .DESCRIPTION
    Analyzes monitoring logs and generates a usage report
    #>
    [CmdletBinding()]
    param(
        [string]$LogPath = "C:\Users\Corbin\development\github-token-management\monitoring-logs",
        [int]$DaysBack = 7
    )
    
    Write-Host "=== GitHub Token Usage Report ===" -ForegroundColor Cyan
    Write-Host "Period: Last $DaysBack days`n" -ForegroundColor Yellow
    
    $startDate = (Get-Date).AddDays(-$DaysBack)
    $logs = @()
    
    # Read log files
    Get-ChildItem -Path $LogPath -Filter "*.log" | Where-Object {
        $_.LastWriteTime -gt $startDate
    } | ForEach-Object {
        $content = Get-Content $_.FullName | ForEach-Object {
            $_ | ConvertFrom-Json
        }
        $logs += $content
    }
    
    if ($logs.Count -eq 0) {
        Write-Host "No logs found for the specified period" -ForegroundColor Yellow
        return
    }
    
    # Analyze usage
    $totalApiCalls = ($logs | Measure-Object -Property 'RateLimit.Used' -Sum).Sum
    $avgApiCalls = [math]::Round(($logs | Measure-Object -Property 'RateLimit.Used' -Average).Average, 2)
    $maxApiCalls = ($logs | Measure-Object -Property 'RateLimit.Used' -Maximum).Maximum
    $authFailures = ($logs | Where-Object { $_.Authenticated -eq $false }).Count
    $warnings = $logs | Where-Object { $_.Warnings } | ForEach-Object { $_.Warnings } | Group-Object
    
    Write-Host "API Usage Statistics:" -ForegroundColor Green
    Write-Host "  Total API Calls: $totalApiCalls"
    Write-Host "  Average per Check: $avgApiCalls"
    Write-Host "  Maximum per Hour: $maxApiCalls"
    Write-Host ""
    
    Write-Host "Authentication:" -ForegroundColor Green
    Write-Host "  Successful Checks: $($logs.Count - $authFailures)"
    Write-Host "  Failed Checks: $authFailures"
    Write-Host ""
    
    if ($warnings) {
        Write-Host "Warnings Summary:" -ForegroundColor Yellow
        $warnings | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Count) occurrences"
        }
    }
}

# ============================================
# Automated Token Rotation
# ============================================

function Enable-AutoTokenRotation {
    <#
    .SYNOPSIS
    Set up automated token rotation with Windows Task Scheduler
    
    .DESCRIPTION
    Creates a scheduled task to check token expiration and notify for rotation
    
    .PARAMETER CheckDays
    Days before expiration to trigger notification (default: 7)
    #>
    [CmdletBinding()]
    param(
        [int]$CheckDays = 7
    )
    
    Write-Host "Setting up automated token rotation checks..." -ForegroundColor Cyan
    
    $taskName = "GitHub Token Rotation Check"
    $scriptPath = "C:\Users\Corbin\development\github-token-management\Check-TokenExpiration.ps1"
    
    # Create the check script
    $checkScript = @'
# Token Expiration Check Script
$logPath = "C:\Users\Corbin\development\github-token-management\rotation-log.json"
$checkDays = 7

if (Test-Path $logPath) {
    $logs = Get-Content $logPath | ConvertFrom-Json
    $notifications = @()
    
    foreach ($log in $logs) {
        $expiryDate = [DateTime]::Parse($log.ExpiresAt)
        $daysRemaining = ($expiryDate - (Get-Date)).Days
        
        if ($daysRemaining -le $checkDays -and $daysRemaining -ge 0) {
            $notifications += "$($log.Context) token expires in $daysRemaining days"
        } elseif ($daysRemaining -lt 0) {
            $notifications += "$($log.Context) token has EXPIRED"
        }
    }
    
    if ($notifications.Count -gt 0) {
        # Create notification
        Add-Type -AssemblyName System.Windows.Forms
        $message = "GitHub Token Expiration Warning:`n`n" + ($notifications -join "`n")
        [System.Windows.Forms.MessageBox]::Show($message, "GitHub Token Manager", "OK", "Warning")
        
        # Log the notification
        $notificationLog = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Notifications = $notifications
        }
        $notificationLog | ConvertTo-Json | Add-Content -Path "C:\Users\Corbin\development\github-token-management\notification.log"
    }
}
'@
    
    $checkScript | Out-File -FilePath $scriptPath -Encoding UTF8
    
    # Create scheduled task
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -Daily -At "09:00AM"
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
        Write-Host "✓ Scheduled task created: $taskName" -ForegroundColor Green
        Write-Host "  Runs daily at 9:00 AM" -ForegroundColor Yellow
        Write-Host "  Checks for tokens expiring within $CheckDays days" -ForegroundColor Yellow
    } catch {
        Write-Host "Failed to create scheduled task: $_" -ForegroundColor Red
    }
}

# ============================================
# Security Audit Functions
# ============================================

function Invoke-GitHubTokenSecurityAudit {
    <#
    .SYNOPSIS
    Perform a security audit of GitHub token configuration
    
    .DESCRIPTION
    Checks for security best practices and potential vulnerabilities
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "=== GitHub Token Security Audit ===" -ForegroundColor Cyan
    $auditResults = @{
        Passed = @()
        Failed = @()
        Warnings = @()
    }
    
    # Check 1: Token in environment variables
    Write-Host "`nChecking environment variables..." -ForegroundColor Yellow
    $envVars = Get-ChildItem env: | Where-Object { $_.Name -like "*GITHUB*" -or $_.Name -like "*TOKEN*" }
    if ($envVars) {
        $tokenVars = $envVars | Where-Object { $_.Value -like "ghp_*" -or $_.Value -like "gho_*" }
        if ($tokenVars) {
            $auditResults.Failed += "Tokens found in plain text environment variables"
        } else {
            $auditResults.Passed += "No tokens exposed in environment variables"
        }
    }
    
    # Check 2: Git credential storage
    Write-Host "Checking Git credential storage..." -ForegroundColor Yellow
    $credHelper = git config --global credential.helper
    if ($credHelper -eq "manager" -or $credHelper -eq "manager-core") {
        $auditResults.Passed += "Using secure credential manager"
    } elseif ($credHelper -eq "store") {
        $auditResults.Warnings += "Using 'store' credential helper (tokens saved in plain text)"
    } else {
        $auditResults.Warnings += "Unknown credential helper: $credHelper"
    }
    
    # Check 3: Token scopes
    Write-Host "Checking token scopes..." -ForegroundColor Yellow
    $tokenScopes = gh api user --jq '.plan.name' 2>$null
    if ($tokenScopes) {
        $auditResults.Passed += "Token has valid authentication"
        
        # Check for overly broad scopes
        $authStatus = gh auth status 2>&1
        if ($authStatus -match "admin:") {
            $auditResults.Warnings += "Token has admin scopes - consider using more restrictive tokens"
        }
    }
    
    # Check 4: SSH keys
    Write-Host "Checking SSH configuration..." -ForegroundColor Yellow
    $sshDir = "$env:USERPROFILE\.ssh"
    if (Test-Path $sshDir) {
        $sshKeys = Get-ChildItem -Path $sshDir -Filter "id_*" | Where-Object { !$_.Name.EndsWith(".pub") }
        if ($sshKeys) {
            $permissions = $sshKeys | ForEach-Object {
                (Get-Acl $_.FullName).Access | Where-Object { $_.IdentityReference -notmatch $env:USERNAME }
            }
            if ($permissions) {
                $auditResults.Failed += "SSH keys have overly permissive permissions"
            } else {
                $auditResults.Passed += "SSH keys have correct permissions"
            }
        }
    }
    
    # Check 5: Token files
    Write-Host "Checking for token files..." -ForegroundColor Yellow
    $tokenFiles = Get-ChildItem -Path "C:\Users\Corbin" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "token|pat|github.*key" -and $_.Extension -in ".txt", ".env", ".json" } |
        Select-Object -First 10
    
    if ($tokenFiles) {
        $auditResults.Warnings += "Found potential token files: $($tokenFiles.Count) files"
    } else {
        $auditResults.Passed += "No obvious token files found"
    }
    
    # Display results
    Write-Host "`n=== Audit Results ===" -ForegroundColor Cyan
    
    if ($auditResults.Passed) {
        Write-Host "`nPassed Checks:" -ForegroundColor Green
        $auditResults.Passed | ForEach-Object { Write-Host "  ✓ $_" -ForegroundColor Green }
    }
    
    if ($auditResults.Warnings) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        $auditResults.Warnings | ForEach-Object { Write-Host "  ⚠ $_" -ForegroundColor Yellow }
    }
    
    if ($auditResults.Failed) {
        Write-Host "`nFailed Checks:" -ForegroundColor Red
        $auditResults.Failed | ForEach-Object { Write-Host "  ✗ $_" -ForegroundColor Red }
    }
    
    # Calculate score
    $totalChecks = $auditResults.Passed.Count + $auditResults.Warnings.Count + $auditResults.Failed.Count
    $score = [math]::Round(($auditResults.Passed.Count / $totalChecks) * 100, 0)
    
    Write-Host "`nSecurity Score: $score%" -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
    
    # Save audit report
    $reportPath = "C:\Users\Corbin\development\github-token-management\security-audit-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').json"
    $auditResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportPath
    Write-Host "`nAudit report saved to: $reportPath" -ForegroundColor Cyan
}

# ============================================
# Quick Backup and Restore
# ============================================

function Backup-GitHubTokenConfig {
    <#
    .SYNOPSIS
    Backup all GitHub token configurations
    #>
    [CmdletBinding()]
    param(
        [string]$BackupPath = "C:\Users\Corbin\development\github-token-management\backups"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
    $backupDir = Join-Path $BackupPath "backup-$timestamp"
    
    Write-Host "Creating backup..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    # Files to backup
    $filesToBackup = @(
        "$env:USERPROFILE\.gitconfig",
        "$env:USERPROFILE\.gitconfig-*",
        "C:\Users\Corbin\development\github-token-management\rotation-log.json"
    )
    
    foreach ($pattern in $filesToBackup) {
        Get-Item $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName -Destination $backupDir
            Write-Host "  Backed up: $($_.Name)" -ForegroundColor Green
        }
    }
    
    # Export current environment variables (names only, not values)
    $envVars = Get-ChildItem env: | Where-Object { $_.Name -like "*GITHUB*" } | Select-Object -ExpandProperty Name
    $envVars | Out-File -FilePath (Join-Path $backupDir "environment-variables.txt")
    
    Write-Host "Backup completed: $backupDir" -ForegroundColor Green
}

# ============================================
# Aliases
# ============================================

Set-Alias -Name mongh -Value Start-GitHubTokenMonitor
Set-Alias -Name repgh -Value Get-GitHubTokenUsageReport
Set-Alias -Name autogh -Value Enable-AutoTokenRotation
Set-Alias -Name auditgh -Value Invoke-GitHubTokenSecurityAudit
Set-Alias -Name backupgh -Value Backup-GitHubTokenConfig

Write-Host @"
GitHub Token Automation Loaded!

Commands:
  mongh    - Start token monitor
  repgh    - Generate usage report
  autogh   - Enable auto rotation
  auditgh  - Run security audit
  backupgh - Backup configuration

"@ -ForegroundColor Green