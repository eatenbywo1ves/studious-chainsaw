# Run this script as Administrator to complete SSH setup
# Right-click and select "Run as Administrator"

Write-Host "Setting up SSH Server for Claude Code Remote Access" -ForegroundColor Green

# Check if running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "This script needs to be run as Administrator. Exiting..." -ForegroundColor Red
    Write-Host "Please right-click the script and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "`n1. Starting SSH Server..." -ForegroundColor Cyan
try {
    Start-Service sshd -ErrorAction Stop
    Write-Host "   SSH Server started successfully" -ForegroundColor Green
} catch {
    Write-Host "   Error starting SSH Server: $_" -ForegroundColor Red
}

Write-Host "`n2. Setting SSH Server to start automatically..." -ForegroundColor Cyan
try {
    Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
    Write-Host "   SSH Server set to automatic startup" -ForegroundColor Green
} catch {
    Write-Host "   Error setting automatic startup: $_" -ForegroundColor Red
}

Write-Host "`n3. Configuring Windows Firewall..." -ForegroundColor Cyan
try {
    $rule = Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue
    if ($rule) {
        Write-Host "   Firewall rule already exists" -ForegroundColor Yellow
    } else {
        New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction Stop
        Write-Host "   Firewall rule created successfully" -ForegroundColor Green
    }
} catch {
    Write-Host "   Error configuring firewall: $_" -ForegroundColor Red
}

Write-Host "`n4. Verifying SSH configuration..." -ForegroundColor Cyan
$sshdConfig = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $sshdConfig) {
    Write-Host "   SSH config file found at $sshdConfig" -ForegroundColor Green
    
    # Backup config
    $backup = "$sshdConfig.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $sshdConfig $backup
    Write-Host "   Backup created: $backup" -ForegroundColor Gray
} else {
    Write-Host "   SSH config file not found!" -ForegroundColor Red
}

Write-Host "`n5. Checking service status..." -ForegroundColor Cyan
$service = Get-Service sshd
Write-Host "   Service Name: $($service.Name)" -ForegroundColor Gray
Write-Host "   Status: $($service.Status)" -ForegroundColor $(if($service.Status -eq 'Running'){'Green'}else{'Red'})
Write-Host "   Startup Type: $($service.StartType)" -ForegroundColor Gray

Write-Host "`n6. Getting local network information..." -ForegroundColor Cyan
$localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet -ErrorAction SilentlyContinue).IPAddress
if (-not $localIP) {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Wi-Fi -ErrorAction SilentlyContinue).IPAddress
}
if ($localIP) {
    Write-Host "   Local IP: $localIP" -ForegroundColor Green
} else {
    Write-Host "   Could not determine local IP" -ForegroundColor Yellow
}

$hostname = hostname
Write-Host "   Hostname: $hostname" -ForegroundColor Green
Write-Host "   Username: $env:USERNAME" -ForegroundColor Green

Write-Host "`n7. Testing SSH locally..." -ForegroundColor Cyan
Write-Host "   Run this command to test:" -ForegroundColor Yellow
Write-Host "   ssh $env:USERNAME@localhost" -ForegroundColor White

Write-Host "`n=== Setup Complete ===" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Install Tailscale from https://tailscale.com/download/windows" -ForegroundColor White
Write-Host "2. Copy the private key from C:\Users\$env:USERNAME\.ssh\id_ed25519 to your phone" -ForegroundColor White
Write-Host "3. Follow the instructions in samsung_fold_claude_code_setup.md" -ForegroundColor White

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
pause