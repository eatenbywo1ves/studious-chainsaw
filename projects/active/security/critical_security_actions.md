# 🔴 CRITICAL SECURITY ACTIONS REQUIRED

## Immediate Actions (Do Today)

### 1. **DISABLE Remote Desktop (RDP) - Port 3389**
RDP is extremely high-risk and constantly targeted by attackers.

```powershell
# Run as Administrator
# Option 1: Disable RDP completely
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Option 2: If you MUST use RDP, restrict it to Tailscale only
New-NetFirewallRule -DisplayName "RDP-Tailscale-Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 100.0.0.0/8 -Action Allow
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress 100.0.0.0/8
```

### 2. **Restrict SMB/File Sharing - Port 445**
SMB is frequently exploited (WannaCry, NotPetya, etc.)

```powershell
# Disable SMB on public networks
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $true -RequireSecuritySignature $true -Force

# Restrict to local network only
New-NetFirewallRule -DisplayName "SMB-LocalOnly" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress 192.168.1.0/24,100.0.0.0/8 -Action Allow
Remove-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
```

### 3. **Disable NetBIOS - Port 139**
Legacy protocol, no longer needed in modern networks

```powershell
# Disable NetBIOS over TCP/IP
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS
}
```

## Security Automation Setup

### Daily Security Check (Schedule as Task)
```powershell
# Create scheduled task for daily security monitoring
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Users\Corbin\development\security_monitor.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 9AM
Register-ScheduledTask -TaskName "DailySecurityAudit" -Action $action -Trigger $trigger -RunLevel Highest
```

## Complete Security Checklist

### Network Security
- [ ] Disable RDP or restrict to Tailscale only
- [ ] Disable SMB v1 completely
- [ ] Restrict SMB v2/3 to local network
- [ ] Disable NetBIOS on all adapters
- [ ] Bind SSH to Tailscale IP only
- [ ] Review and close unnecessary ports

### Authentication & Access
- [ ] Enable MFA on Tailscale account
- [ ] Rotate SSH keys quarterly
- [ ] Set up SSH certificate authority (advanced)
- [ ] Implement fail2ban equivalent
- [ ] Review authorized_keys regularly

### System Hardening
- [ ] Enable BitLocker encryption
- [ ] Configure Windows Firewall deny-by-default
- [ ] Enable Exploit Protection
- [ ] Disable PowerShell v2
- [ ] Enable AppLocker or WDAC

### Monitoring & Logging
- [ ] Set up daily security monitoring script
- [ ] Enable PowerShell script block logging
- [ ] Configure Windows Event forwarding
- [ ] Set up alerts for suspicious activity
- [ ] Regular review of connection logs

### Mobile Security (Samsung Fold)
- [ ] Enable biometric lock on Termius
- [ ] Use certificate pinning for SSH
- [ ] Enable "Require authentication" per connection
- [ ] Regular cleanup of known_hosts
- [ ] Use separate SSH key for mobile

### Backup & Recovery
- [ ] Backup SSH keys securely (encrypted)
- [ ] Document recovery procedures
- [ ] Test restore procedures quarterly
- [ ] Maintain offline configuration backups

## Port Reference Guide

| Port | Service | Risk Level | Action Required |
|------|---------|------------|-----------------|
| 22 | SSH | Medium | Bind to Tailscale only |
| 139 | NetBIOS | High | Disable completely |
| 445 | SMB | Critical | Restrict to local network |
| 3389 | RDP | Critical | Disable or Tailscale only |
| 5357 | WSDAPI | Low | Keep for network discovery |
| 135 | RPC | Medium | Windows system (keep) |

## Quick Audit Commands

```powershell
# Check exposed services
netstat -an | findstr LISTENING

# Check recent RDP attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Where {$_.Message -match "RDP"}

# Check SMB connections
Get-SmbSession

# Verify firewall rules
Get-NetFirewallRule | Where {$_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True'}

# Check for suspicious processes
Get-Process | Where {$_.Path -match "\\Temp\\" -or $_.Path -match "\\AppData\\Local\\"}
```

## Emergency Response

If you suspect compromise:
1. Disconnect from network (except Tailscale)
2. Run full Windows Defender scan
3. Check Event Viewer for Security log anomalies
4. Review recent PowerShell history: `Get-History`
5. Check scheduled tasks: `Get-ScheduledTask | Where {$_.Author -notmatch "Microsoft"}`
6. Rotate all credentials and keys

## Priority Order

1. **TODAY**: Disable/restrict RDP (highest risk)
2. **THIS WEEK**: Restrict SMB, disable NetBIOS
3. **THIS MONTH**: Implement monitoring automation
4. **QUARTERLY**: Key rotation and security review

---
**Remember**: Security is not a one-time task but an ongoing process. Regular audits and updates are essential.