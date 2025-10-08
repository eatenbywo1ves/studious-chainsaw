# SSH from Samsung Fold 7 to Desktop via Termux

Auto-reconnecting SSH client script for maintaining persistent connection from your phone to your desktop PC via Tailscale.

---

## Overview

This script runs **on your Samsung Fold 7 in Termux** and maintains a persistent SSH connection **to your Windows desktop PC**.

**Direction:** Phone → Desktop (opposite of the previous solution)

```
┌─────────────────┐         ┌──────────────┐
│  Samsung        │         │  Windows     │
│  Fold 7         │────────>│  Desktop PC  │
│                 │   SSH   │              │
│  - Termux       │         │  - OpenSSH   │
│  - This script  │         │    Server    │
│  - Tailscale    │         │  - Tailscale │
└─────────────────┘         └──────────────┘
```

---

## Prerequisites

### On Your Desktop PC (Windows)

1. **Enable OpenSSH Server**:
   ```powershell
   # Run in PowerShell as Administrator

   # Check if installed
   Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

   # Install if needed
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

   # Start service
   Start-Service sshd

   # Set to auto-start
   Set-Service -Name sshd -StartupType 'Automatic'

   # Confirm firewall rule (should exist automatically)
   Get-NetFirewallRule -Name *ssh*
   ```

2. **Install Tailscale** (if not already):
   - Download: https://tailscale.com/download/windows
   - Sign in to your tailnet

3. **Find your desktop's Tailscale hostname**:
   ```cmd
   tailscale status
   ```
   Look for your desktop's machine name (e.g., `DESKTOP-ABC123`)

### On Your Samsung Fold 7 (Android)

1. **Install Termux** from GitHub or F-Droid
2. **Install Tailscale** from Play Store
3. Connect to same tailnet as desktop

---

## Installation

### Step 1: Transfer Script to Phone

**Option A: Direct download in Termux**
```bash
# In Termux on phone:
cd ~
curl -O https://raw.githubusercontent.com/your-repo/termux_ssh_to_desktop.sh
chmod +x termux_ssh_to_desktop.sh
```

**Option B: Copy from PC**

If you already have SSH working in some capacity:
```bash
# On PC (Git Bash or PowerShell):
scp C:\Users\Corbin\development\termux_ssh_to_desktop.sh user@fold7:~/

# In Termux on phone:
chmod +x termux_ssh_to_desktop.sh
```

**Option C: Manual paste**
```bash
# In Termux on phone:
nano ~/termux_ssh_to_desktop.sh
# Paste the script content
# Press Ctrl+X, Y, Enter to save

chmod +x termux_ssh_to_desktop.sh
```

### Step 2: Create Configuration File

```bash
# In Termux, run:
./termux_ssh_to_desktop.sh --create-config
```

This creates `~/.ssh/desktop_connection.conf` with default settings.

### Step 3: Edit Configuration

```bash
nano ~/.ssh/desktop_connection.conf
```

**Required changes:**
```bash
# Your desktop's Tailscale hostname
DESKTOP_HOST="your-desktop-hostname.tailnet.ts.net"

# Your Windows username
DESKTOP_USER="Corbin"

# SSH port (usually 22 on Windows)
DESKTOP_PORT="22"
```

**Optional settings:**
```bash
# Auto-reconnect on disconnect
AUTO_RECONNECT=true

# Check every 30 seconds
CHECK_INTERVAL=30

# Use wake lock (prevents phone sleep)
USE_WAKELOCK=true

# Send Android notifications
SEND_NOTIFICATIONS=true

# Remote command to run (e.g., "pwsh" for PowerShell)
REMOTE_COMMAND=""
```

Save with `Ctrl+X`, `Y`, `Enter`

---

## Step 4: Setup SSH Keys (Recommended)

### Generate SSH Key on Phone

```bash
# In Termux:
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "fold7-to-desktop"
```

Press Enter for no passphrase (or add one for extra security)

### Copy Public Key to Desktop

**Option A: Manual copy**
```bash
# In Termux, display your public key:
cat ~/.ssh/id_ed25519.pub
```

Copy the output, then **on your Windows desktop**:

```powershell
# In PowerShell on desktop:
cd ~
mkdir .ssh -ErrorAction SilentlyContinue

# Paste your public key into authorized_keys
notepad .ssh\authorized_keys
# Paste the public key, save and close

# Set correct permissions
icacls .ssh\authorized_keys /inheritance:r
icacls .ssh\authorized_keys /grant:r "$($env:USERNAME):F"
```

**Option B: Use ssh-copy-id (if you can connect)**
```bash
# In Termux:
ssh-copy-id -i ~/.ssh/id_ed25519.pub Corbin@your-desktop.tailnet.ts.net
```

---

## Usage

### Test Connection

```bash
# In Termux:
./termux_ssh_to_desktop.sh --test
```

Should output: `[SUCCESS] Connection test successful!`

### Connect Once (Interactive)

```bash
./termux_ssh_to_desktop.sh --once
```

This connects you to your desktop in a normal SSH session.

### Auto-Reconnect Mode (Persistent)

```bash
./termux_ssh_to_desktop.sh
```

This starts the monitoring loop that:
- Connects to desktop
- Monitors connection health
- Automatically reconnects if disconnected
- Sends notifications on connection events
- Maintains wake lock to prevent phone sleep

### Run in Background

```bash
# Use tmux to keep it running
pkg install tmux
tmux new -s desktop-ssh
./termux_ssh_to_desktop.sh

# Detach with Ctrl+B, then D
# Reattach later with: tmux attach -t desktop-ssh
```

Or use Termux:Boot to start automatically.

---

## Auto-Start on Boot

### Install Termux:Boot

```bash
pkg install termux-boot
```

### Create Boot Script

```bash
mkdir -p ~/.termux/boot
nano ~/.termux/boot/start-desktop-ssh
```

Add:
```bash
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 10
$HOME/termux_ssh_to_desktop.sh > $HOME/ssh-boot.log 2>&1 &
```

Make executable:
```bash
chmod +x ~/.termux/boot/start-desktop-ssh
```

Now the script will auto-start when your phone boots!

---

## Features

### Auto-Reconnection
- Automatically reconnects if connection drops
- Exponential backoff on repeated failures
- Configurable retry limits and intervals

### Connection Monitoring
- Tests connection before attempting
- Monitors Tailscale reachability
- Logs all connection events

### Android Integration
- Acquires wake lock to prevent sleep
- Sends notifications on connection events
- Integrates with Termux:API

### Logging
- Detailed logs to `~/ssh_desktop_monitor.log`
- Colored console output
- Timestamps on all events

### Flexible Configuration
- Single config file for all settings
- Override with command-line arguments
- Support for SSH keys or passwords

---

## Configuration Options

Full list of options in `~/.ssh/desktop_connection.conf`:

```bash
# Connection settings
DESKTOP_HOST="desktop.tailnet.ts.net"    # Desktop Tailscale hostname
DESKTOP_PORT="22"                         # SSH port
DESKTOP_USER="username"                   # Desktop username
SSH_KEY="$HOME/.ssh/id_ed25519"          # SSH key path (or empty)

# Monitoring settings
CHECK_INTERVAL=30                         # Seconds between checks
CONNECTION_TIMEOUT=10                     # Connection timeout
MAX_RETRIES=5                            # Retries before backoff
AUTO_RECONNECT=true                      # Enable auto-reconnect
KEEPALIVE_INTERVAL=60                    # SSH keep-alive interval

# Behavior settings
USE_WAKELOCK=true                        # Prevent phone sleep
SEND_NOTIFICATIONS=true                  # Android notifications
VERBOSE=false                            # Detailed logging
REMOTE_COMMAND=""                        # Command to run (optional)

# Logging
LOG_FILE="$HOME/ssh_desktop_monitor.log"
```

---

## Troubleshooting

### "Cannot resolve hostname"

**Problem:** Can't find desktop via Tailscale

**Solutions:**
1. Check Tailscale is connected on phone: `tailscale status`
2. Check Tailscale is connected on desktop: `tailscale status`
3. Verify hostname is correct in config
4. Try IP address instead: `tailscale ip -4` on desktop

### "Connection test failed"

**Problem:** Can't connect via SSH

**Solutions:**
1. Check SSH server is running on desktop:
   ```powershell
   Get-Service sshd
   ```
2. Check firewall allows SSH (port 22)
3. Test from Termux manually:
   ```bash
   ssh -v Corbin@desktop.tailnet.ts.net
   ```
4. Check SSH keys are properly configured

### "Permission denied (publickey)"

**Problem:** SSH key authentication failed

**Solutions:**
1. Verify public key is in desktop's `~/.ssh/authorized_keys`
2. Check permissions on Windows:
   ```powershell
   icacls .ssh\authorized_keys
   ```
3. Try password authentication first (remove `SSH_KEY` from config)
4. Check SSH key path is correct in config

### Script exits immediately

**Problem:** Script not running in background

**Solutions:**
1. Use tmux: `tmux new -s ssh; ./termux_ssh_to_desktop.sh`
2. Check logs: `cat ~/ssh_desktop_monitor.log`
3. Run with `--test` to check configuration
4. Verify `AUTO_RECONNECT=true` in config

### Battery optimization killing script

**Problem:** Script stops when phone sleeps

**Solutions:**
1. Disable battery optimization for Termux (see main setup guide)
2. Enable wake lock: `USE_WAKELOCK=true` in config
3. Add Termux to "Never sleeping apps"
4. Keep phone charging while testing

---

## Usage Examples

### Connect and Run PowerShell on Desktop

```bash
# Edit config:
REMOTE_COMMAND="pwsh"

# Run script:
./termux_ssh_to_desktop.sh
```

### Connect to Specific tmux Session on Desktop

```bash
# Edit config:
REMOTE_COMMAND="tmux attach -t work"

# Run script:
./termux_ssh_to_desktop.sh
```

### One-Time Connection for File Transfer

```bash
# Connect once:
./termux_ssh_to_desktop.sh --once

# Then in SSH session on desktop:
# Transfer files, run commands, etc.
```

### Background Monitor with Notifications

```bash
# Start in tmux:
tmux new -s ssh-monitor
./termux_ssh_to_desktop.sh

# Detach: Ctrl+B, D
# You'll get notifications on phone for connection events
```

---

## Security Best Practices

### 1. Use SSH Keys (Not Passwords)
```bash
ssh-keygen -t ed25519
ssh-copy-id Corbin@desktop.tailnet.ts.net
```

### 2. Restrict SSH Access on Desktop

Edit `C:\ProgramData\ssh\sshd_config`:
```
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
```

Restart SSH service:
```powershell
Restart-Service sshd
```

### 3. Use Tailscale ACLs

Restrict which devices can SSH to your desktop in Tailscale admin panel.

### 4. Monitor Connection Logs

```bash
# Check recent connections
tail -f ~/ssh_desktop_monitor.log

# Check Windows SSH logs
Get-EventLog -LogName Security -Newest 50 | Where-Object {$_.EventID -eq 4624}
```

---

## Command Reference

```bash
# Create config file
./termux_ssh_to_desktop.sh --create-config

# Test connection
./termux_ssh_to_desktop.sh --test

# Connect once (interactive)
./termux_ssh_to_desktop.sh --once

# Start auto-reconnect monitor
./termux_ssh_to_desktop.sh

# Use custom config file
./termux_ssh_to_desktop.sh /path/to/custom.conf

# View logs
cat ~/ssh_desktop_monitor.log
tail -f ~/ssh_desktop_monitor.log

# Check if running
pgrep -a bash | grep termux_ssh

# Stop running monitor
pkill -f termux_ssh_to_desktop.sh
```

---

## Comparison: This Script vs fold7_ssh_monitor.py

| Feature | This Script (Phone→Desktop) | fold7_ssh_monitor.py (Desktop→Phone) |
|---------|------------------------------|--------------------------------------|
| **Runs On** | Termux on phone | Python on desktop |
| **Direction** | Phone connects TO desktop | Desktop connects TO phone |
| **Language** | Bash | Python |
| **Use Case** | Access desktop from phone | Access phone from desktop |
| **Auto-start** | Termux:Boot | Windows Task Scheduler |
| **Notifications** | Termux:API (on phone) | Console/log file |

You can run **both** simultaneously for bi-directional SSH access!

---

## Integration with Previous Solution

You can use both solutions together:

**Setup 1: SSH INTO phone** (fold7_ssh_monitor.py)
- Desktop monitors connection TO phone
- Access Termux on phone from desktop
- Good for: Remote phone management

**Setup 2: SSH FROM phone** (this script)
- Phone monitors connection TO desktop
- Access desktop from phone
- Good for: Remote desktop access on-the-go

**Combined**: Full bi-directional SSH access via Tailscale!

---

Last updated: 2025-09-30