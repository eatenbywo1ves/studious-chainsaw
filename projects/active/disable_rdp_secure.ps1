# Comprehensive RDP Disable Script
# This will completely disable Remote Desktop for maximum security

Write-Host "=== Disabling Remote Desktop Protocol (RDP) ===" -ForegroundColor Red
Write-Host "This will improve your security significantly!" -ForegroundColor Yellow

try {
    # Step 1: Stop the Remote Desktop Service
    Write-Host "[1/5] Stopping Remote Desktop Service..." -ForegroundColor Yellow
    Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "SessionEnv" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "UmRdpService" -Force -ErrorAction SilentlyContinue
    
    # Step 2: Disable the Remote Desktop Service
    Write-Host "[2/5] Disabling Remote Desktop Service from starting..." -ForegroundColor Yellow
    Set-Service -Name "TermService" -StartupType Disabled
    Set-Service -Name "SessionEnv" -StartupType Disabled  
    Set-Service -Name "UmRdpService" -StartupType Disabled
    
    # Step 3: Disable RDP in the registry
    Write-Host "[3/5] Updating registry to deny RDP connections..." -ForegroundColor Yellow
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1
    
    # Step 4: Disable RDP firewall rules
    Write-Host "[4/5] Blocking RDP in Windows Firewall..." -ForegroundColor Yellow
    Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Disable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -ErrorAction SilentlyContinue
    Disable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)" -ErrorAction SilentlyContinue
    
    # Step 5: Add explicit block rule for port 3389
    Write-Host "[5/5] Adding explicit firewall block for port 3389..." -ForegroundColor Yellow
    New-NetFirewallRule -DisplayName "Block RDP Port 3389" `
        -Direction Inbound -Protocol TCP -LocalPort 3389 `
        -Action Block -Enabled True -ErrorAction SilentlyContinue
    
    Write-Host "`n✅ SUCCESS: Remote Desktop has been completely disabled!" -ForegroundColor Green
    Write-Host "Your system is now much more secure." -ForegroundColor Green
    
    # Verify the changes
    Write-Host "`n=== Verification ===" -ForegroundColor Cyan
    $rdpStatus = Get-Service -Name "TermService" | Select-Object Status, StartType
    Write-Host "RDP Service Status: $($rdpStatus.Status) (StartType: $($rdpStatus.StartType))" -ForegroundColor Cyan
    
    $regValue = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections"
    if ($regValue.fDenyTSConnections -eq 1) {
        Write-Host "Registry: RDP connections DENIED ✅" -ForegroundColor Green
    }
    
} catch {
    Write-Host "Error occurred: $_" -ForegroundColor Red
    Write-Host "You may need to run this script as Administrator" -ForegroundColor Yellow
}

Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")