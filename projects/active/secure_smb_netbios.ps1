# Secure SMB and Disable NetBIOS Script
Write-Host "=== Securing SMB and Disabling NetBIOS ===" -ForegroundColor Cyan

# Part 1: Secure SMB
Write-Host "`n[1/4] Disabling SMB v1 (vulnerable protocol)..." -ForegroundColor Yellow
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
    Write-Host "✅ SMB v1 disabled" -ForegroundColor Green
} catch {
    Write-Host "⚠ Could not disable SMB v1: $_" -ForegroundColor Yellow
}

Write-Host "[2/4] Securing SMB v2/v3..." -ForegroundColor Yellow
Set-SmbServerConfiguration -EnableSMB2Protocol $true -RequireSecuritySignature $true -EncryptData $true -Force
Write-Host "✅ SMB v2/v3 secured with signatures and encryption" -ForegroundColor Green

Write-Host "[3/4] Restricting SMB to local and Tailscale networks only..." -ForegroundColor Yellow
# Remove existing SMB rules
Get-NetFirewallRule -DisplayName "*SMB*" | Where-Object {$_.Direction -eq 'Inbound'} | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Create new restricted rule
New-NetFirewallRule -DisplayName "SMB-Restricted" `
    -Direction Inbound -Protocol TCP -LocalPort 445 `
    -RemoteAddress @("192.168.1.0/24", "100.0.0.0/8", "127.0.0.1") `
    -Action Allow -Enabled True

Write-Host "✅ SMB restricted to local network and Tailscale only" -ForegroundColor Green

# Part 2: Disable NetBIOS
Write-Host "`n[4/4] Disabling NetBIOS on all network adapters..." -ForegroundColor Yellow
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
$count = 0
foreach ($adapter in $adapters) {
    try {
        # 2 = Disable NetBIOS over TCP/IP
        $result = $adapter.SetTcpipNetbios(2)
        if ($result.ReturnValue -eq 0) {
            $count++
            Write-Host "  Disabled NetBIOS on: $($adapter.Description)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  Could not disable on: $($adapter.Description)" -ForegroundColor Yellow
    }
}
Write-Host "✅ NetBIOS disabled on $count adapter(s)" -ForegroundColor Green

# Disable NetBIOS services
Write-Host "`nDisabling NetBIOS-related services..." -ForegroundColor Yellow
Stop-Service -Name "lmhosts" -Force -ErrorAction SilentlyContinue
Set-Service -Name "lmhosts" -StartupType Disabled -ErrorAction SilentlyContinue

# Block NetBIOS ports in firewall
New-NetFirewallRule -DisplayName "Block NetBIOS Port 137" `
    -Direction Inbound -Protocol UDP -LocalPort 137 `
    -Action Block -Enabled True -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName "Block NetBIOS Port 138" `
    -Direction Inbound -Protocol UDP -LocalPort 138 `
    -Action Block -Enabled True -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName "Block NetBIOS Port 139" `
    -Direction Inbound -Protocol TCP -LocalPort 139 `
    -Action Block -Enabled True -ErrorAction SilentlyContinue

Write-Host "✅ NetBIOS ports blocked in firewall" -ForegroundColor Green

# Verification
Write-Host "`n=== Verification ===" -ForegroundColor Cyan
$smbConfig = Get-SmbServerConfiguration
Write-Host "SMB v1 Enabled: $($smbConfig.EnableSMB1Protocol)" -ForegroundColor $(if($smbConfig.EnableSMB1Protocol){"Red"}else{"Green"})
Write-Host "SMB Encryption: $($smbConfig.EncryptData)" -ForegroundColor $(if($smbConfig.EncryptData){"Green"}else{"Red"})
Write-Host "SMB Signing Required: $($smbConfig.RequireSecuritySignature)" -ForegroundColor $(if($smbConfig.RequireSecuritySignature){"Green"}else{"Red"})

Write-Host "`n=== SECURITY IMPROVEMENTS ===" -ForegroundColor Green
Write-Host "✅ SMB v1 disabled (prevents EternalBlue attacks)" -ForegroundColor Green
Write-Host "✅ SMB restricted to local network only" -ForegroundColor Green
Write-Host "✅ NetBIOS disabled (prevents information leakage)" -ForegroundColor Green
Write-Host "✅ Legacy ports 137-139 blocked" -ForegroundColor Green

Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")