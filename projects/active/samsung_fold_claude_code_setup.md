# Samsung Fold 7 - Claude Code Remote Access Setup

## Prerequisites on Windows Host (Your PC)

### 1. Enable OpenSSH Server (Run as Administrator)
```powershell
# Open PowerShell as Administrator and run:
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Configure Windows Firewall for SSH
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 2. Install Tailscale on Windows
1. Download from: https://tailscale.com/download/windows
2. Install and sign in with your account
3. Note your machine name (e.g., `corbin-pc`)

### 3. SSH Key Setup (Already completed)
Your SSH keys have been generated at:
- Private key: `C:\Users\Corbin\.ssh\id_ed25519`
- Public key: `C:\Users\Corbin\.ssh\id_ed25519.pub`

## Samsung Fold 7 Setup

### Option 1: Termius (Recommended - Best for Fold)
1. **Install Termius** from Google Play Store
2. **Import SSH Key:**
   - Open Termius → Settings → Keychain
   - Tap "+" → Import from file
   - Copy this private key to your phone and import:
   ```
   C:\Users\Corbin\.ssh\id_ed25519
   ```
3. **Add Host:**
   - Tap "+" → New Host
   - Label: `Claude Code PC`
   - Hostname: `localhost` (will change to Tailscale IP)
   - Port: `22`
   - Username: `Corbin`
   - Key: Select the imported key

### Option 2: JuiceSSH (Alternative)
1. Install JuiceSSH from Play Store
2. Import the same private key
3. Create connection with same details

### Setting up Tailscale on Samsung Fold 7
1. **Install Tailscale** from Google Play Store
2. **Sign in** with the same account as Windows
3. **Find your PC's Tailscale IP:**
   - Open Tailscale app
   - Look for your PC (e.g., `corbin-pc`)
   - Note the IP (usually `100.x.x.x`)
4. **Update SSH client:**
   - Change hostname from `localhost` to Tailscale IP
   - Test connection

## Running Claude Code Remotely

### Basic Commands
```bash
# Start Claude Code
claude

# Navigate to project
cd /c/Users/Corbin/development/your-project
claude

# Run in specific directory
claude --directory /c/Users/Corbin/projects
```

### Samsung Fold 7 Optimizations

#### Split Screen Mode
1. Open Termius in full screen
2. Swipe up from bottom → Select split screen
3. Add browser/documentation on other half
4. Perfect for coding + reference

#### Cover Screen Quick Access
- Set Termius as cover screen app
- Quick command checks without unfolding

#### Keyboard Shortcuts (with Bluetooth keyboard)
- `Ctrl+Shift+N`: New terminal session
- `Ctrl+Tab`: Switch sessions  
- `Ctrl+D`: Disconnect

## Security Best Practices

### 1. SSH Configuration (Already Applied)
```bash
# Location: C:\ProgramData\ssh\sshd_config
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
```

### 2. Tailscale Security
- Uses WireGuard encryption
- No port forwarding needed
- Private network only
- Enable 2FA on Tailscale account

### 3. Mobile Security
- Use biometric lock on Termius
- Don't save passwords, only use keys
- Enable "Require authentication" for each connection

## Troubleshooting

### Can't connect via SSH
```powershell
# Check SSH service status
Get-Service sshd

# Restart if needed (as Admin)
Restart-Service sshd

# Check firewall
Get-NetFirewallRule -Name sshd
```

### Tailscale not connecting
1. Ensure both devices on same Tailscale network
2. Check Tailscale admin console: https://login.tailscale.com/admin/machines
3. Try `tailscale ping corbin-pc` from phone

### Permission denied
```bash
# Fix permissions on Windows
icacls C:\Users\Corbin\.ssh /inheritance:r /grant:r "Corbin:F"
icacls C:\Users\Corbin\.ssh\authorized_keys /inheritance:r /grant:r "Corbin:F"
```

## Advanced Features

### Voice Input with Claude Code
1. Use Samsung Fold's voice-to-text
2. In Termius: Long-press space bar → Voice input
3. Speak natural commands:
   - "Create a React component for user authentication"
   - "Fix the TypeScript errors in this file"

### File Transfer
```bash
# Upload from phone to PC
scp /storage/emulated/0/Download/file.txt Corbin@100.x.x.x:C:/Users/Corbin/

# Download from PC to phone  
scp Corbin@100.x.x.x:C:/Users/Corbin/file.txt /storage/emulated/0/Download/
```

### Multiple Sessions
- Termius supports multiple concurrent sessions
- Perfect for running Claude Code + monitoring logs
- Use tabs or split view

## Quick Start Checklist

- [ ] Windows: OpenSSH Server running
- [ ] Windows: Tailscale installed and connected
- [ ] Windows: SSH keys generated
- [ ] Phone: Tailscale app installed
- [ ] Phone: Termius/JuiceSSH installed
- [ ] Phone: Private key imported
- [ ] Phone: Connection configured with Tailscale IP
- [ ] Test: Successfully connected via SSH
- [ ] Test: Claude Code launches properly

## Support Resources

- Tailscale Status: https://status.tailscale.com/
- Claude Code Docs: https://docs.anthropic.com/claude-code
- Termius Support: https://support.termius.com/

## Your Connection Details

**PC Hostname:** Corbin-PC  
**Username:** Corbin  
**SSH Port:** 22  
**Key Location:** `~/.ssh/id_ed25519`  
**Tailscale Network:** (Check app for IP)

---
Generated: 2025-09-08