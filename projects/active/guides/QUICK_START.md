# Quick Start - Samsung Fold 7 Claude Code Access

## ⚡ Immediate Next Steps

### 1. Run Admin Setup (Windows)
```powershell
# Right-click PowerShell, Run as Administrator
cd C:\Users\Corbin\development
.\setup_ssh_admin.ps1
```

### 2. Install Tailscale (Windows)
- Download: https://tailscale.com/download/windows
- Sign in with Google/GitHub/Microsoft account
- Note your device name after setup

### 3. On Samsung Fold 7

#### Install Apps:
1. **Tailscale** - From Play Store
2. **Termius** - From Play Store (free version works)

#### Transfer SSH Key:
- Copy this file to your phone: `C:\Users\Corbin\.ssh\id_ed25519`
- Options:
  - Email it to yourself (secure)
  - Use OneDrive/Google Drive
  - USB cable transfer

#### Configure Termius:
1. Import the key file
2. Create new host:
   - Hostname: [Your Tailscale IP]
   - Username: `Corbin`
   - Port: `22`
   - Use imported key

## 📱 Samsung Fold 7 Tips

### Fold-Specific Features:
- **Unfolded**: Full terminal + documentation side-by-side
- **Folded**: Quick command checks on cover screen
- **Flex Mode**: Prop up bottom screen as keyboard, top as display

### Voice Commands Work Great:
- Long-press spacebar in Termius
- Say: "claude create a python script to..."

## 🔐 Security Summary

✅ **What's Secured:**
- SSH key authentication (no passwords)
- Tailscale encrypted tunnel
- No port forwarding needed
- Private network only

❌ **Never Do:**
- Share your private key publicly
- Disable Tailscale while connected
- Use public WiFi without Tailscale

## 🚀 Test Commands

Once connected via SSH:
```bash
# Check Claude Code
claude --version

# Start Claude Code
claude

# Navigate to projects
cd /c/Users/Corbin/development
ls
```

## 📋 Your System Info
- **PC Name**: StoopidPC
- **Username**: Corbin
- **SSH Port**: 22
- **Key Location**: `~/.ssh/id_ed25519`

## ❓ Troubleshooting

**"Connection Refused"**
- Run `setup_ssh_admin.ps1` as Administrator

**"Permission Denied"**
- Verify key is imported in Termius
- Check username is exactly `Corbin`

**Can't find Tailscale IP**
- Open Tailscale app on both devices
- Look for `StoopidPC` in device list
- IP format: `100.x.x.x`

---
Ready to code from anywhere! 🚀