# Restrict SSH to Tailscale Only
# This script will configure OpenSSH to only listen on your Tailscale IP

$ErrorActionPreference = "Stop"

Write-Host "=== Restricting SSH to Tailscale Interface Only ===" -ForegroundColor Cyan
Write-Host "This will make SSH accessible ONLY via Tailscale VPN" -ForegroundColor Yellow

$configPath = "C:\ProgramData\ssh\sshd_config"
$backupPath = "C:\ProgramData\ssh\sshd_config.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$tailscaleIP = "100.108.218.15"

try {
    # Step 1: Backup current configuration
    Write-Host "`n[1/5] Creating backup of current SSH configuration..." -ForegroundColor Yellow
    Copy-Item -Path $configPath -Destination $backupPath -Force
    Write-Host "✅ Backup saved to: $backupPath" -ForegroundColor Green

    # Step 2: Read current configuration
    Write-Host "[2/5] Reading current configuration..." -ForegroundColor Yellow
    $currentConfig = Get-Content -Path $configPath -Raw

    # Step 3: Check if ListenAddress is already configured
    Write-Host "[3/5] Modifying SSH configuration..." -ForegroundColor Yellow
    
    # Remove any existing ListenAddress lines (commented or not)
    $currentConfig = $currentConfig -replace '(?m)^.*ListenAddress.*$', ''
    
    # Remove any existing Port lines to ensure we control it
    $currentConfig = $currentConfig -replace '(?m)^.*Port\s+\d+.*$', ''
    
    # Clean up multiple blank lines
    $currentConfig = $currentConfig -replace '(\r?\n){3,}', "`r`n`r`n"
    
    # Add our secure configuration at the top
    $secureConfig = @"
# === SECURITY HARDENING - Added $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===
# SSH is restricted to Tailscale VPN interface only
ListenAddress $tailscaleIP
Port 22

# Authentication settings
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
PermitRootLogin no

# Security settings
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel INFO
# === END SECURITY HARDENING ===

"@

    # Combine new config with existing
    $newConfig = $secureConfig + $currentConfig
    
    # Step 4: Write new configuration
    Write-Host "[4/5] Writing new configuration..." -ForegroundColor Yellow
    Set-Content -Path $configPath -Value $newConfig -Force
    Write-Host "✅ SSH configuration updated" -ForegroundColor Green
    
    # Step 5: Test configuration syntax
    Write-Host "[5/5] Testing configuration syntax..." -ForegroundColor Yellow
    $testResult = & sshd -t 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Configuration syntax is valid" -ForegroundColor Green
        
        # Restart SSH service
        Write-Host "`nRestarting SSH service..." -ForegroundColor Yellow
        Restart-Service sshd -Force
        Start-Sleep -Seconds 2
        
        $sshStatus = Get-Service sshd
        if ($sshStatus.Status -eq 'Running') {
            Write-Host "✅ SSH service restarted successfully" -ForegroundColor Green
        } else {
            throw "SSH service failed to restart"
        }
        
    } else {
        Write-Host "❌ Configuration syntax error detected:" -ForegroundColor Red
        Write-Host $testResult -ForegroundColor Red
        
        # Restore backup
        Write-Host "Restoring backup configuration..." -ForegroundColor Yellow
        Copy-Item -Path $backupPath -Destination $configPath -Force
        Restart-Service sshd -Force
        throw "Configuration syntax error - backup restored"
    }
    
    # Verify the change
    Write-Host "`n=== Verification ===" -ForegroundColor Cyan
    $listening = netstat -an | Select-String "22.*LISTENING"
    Write-Host "SSH is now listening on:" -ForegroundColor Cyan
    $listening | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
    
    if ($listening -match $tailscaleIP) {
        Write-Host "`n✅ SUCCESS: SSH is now restricted to Tailscale only!" -ForegroundColor Green
        Write-Host "   SSH will ONLY accept connections via: $tailscaleIP" -ForegroundColor Green
    } else {
        Write-Host "`n⚠ WARNING: Could not verify binding. Check after service restart." -ForegroundColor Yellow
    }
    
    # Test local connectivity
    Write-Host "`nTesting SSH connectivity..." -ForegroundColor Yellow
    $testConnection = Test-NetConnection -ComputerName $tailscaleIP -Port 22 -WarningAction SilentlyContinue
    if ($testConnection.TcpTestSucceeded) {
        Write-Host "✅ SSH is responding on Tailscale IP" -ForegroundColor Green
    }
    
    Write-Host "`n=== IMPORTANT NOTES ===" -ForegroundColor Yellow
    Write-Host "1. SSH is now ONLY accessible via Tailscale VPN" -ForegroundColor White
    Write-Host "2. Direct local/network SSH connections will fail" -ForegroundColor White
    Write-Host "3. Your mobile device will connect via: $tailscaleIP" -ForegroundColor White
    Write-Host "4. Backup saved at: $backupPath" -ForegroundColor White
    
} catch {
    Write-Host "`n❌ Error occurred: $_" -ForegroundColor Red
    Write-Host "Attempting to restore backup..." -ForegroundColor Yellow
    
    if (Test-Path $backupPath) {
        Copy-Item -Path $backupPath -Destination $configPath -Force
        Restart-Service sshd -Force -ErrorAction SilentlyContinue
        Write-Host "Backup restored. SSH service restarted." -ForegroundColor Yellow
    }
}

Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")