# Samsung Fold 7 SSH Auto-Reconnection Setup

Complete guide to maintaining persistent SSH connectivity to your Samsung Fold 7 via Tailscale.

---

## ⚠️ IMPORTANT: Choose Your SSH Server App First

**This guide is for Termux only.** If you're not sure which SSH app you have, or if you have a different app:

**→ READ FIRST:** `IDENTIFY_YOUR_SSH_APP.md`

### Quick App Selection:

- ✓ **Have Termux?** → Continue reading this guide
- ✓ **Have SSH/SFTP Server - Terminal (xnano)?** → Use `setup_xnano_ssh_server.md` instead
- ✓ **Not sure which app?** → See `IDENTIFY_YOUR_SSH_APP.md`
- ✓ **Have neither?** → Choose one:
  - **Termux** (complex, full Linux) → Continue this guide
  - **xnano SSH Server** (easy, GUI-based) → Use `setup_xnano_ssh_server.md`

---

## Problem Overview

Samsung devices running One UI have aggressive battery management that kills background services, including:
- **Tailscale VPN** - Disconnects randomly, especially when switching between WiFi/cellular
- **SSH daemon** - Terminates during deep sleep or when app is "sleeping"
- **Network transitions** - Drops connections when moving between networks

## Solution Components

This solution uses a **two-pronged approach**:

1. **Device-side**: Configure Samsung Fold 7 to keep services running
2. **PC-side**: Python monitoring script that automatically reconnects

**Note**: The Python monitoring script (`fold7_ssh_monitor.py`) works with **any SSH server app** - you just need to configure the correct port and username.

---

## Part 1: Samsung Fold 7 Configuration

### Step 1: Configure Tailscale Battery Settings

#### A. Disable Battery Optimization
1. Open **Settings** → **Apps** → **Tailscale**
2. Tap **Battery**
3. Select **Unrestricted**
4. Enable **Allow background activity** (if available)

#### B. Add to Never Sleeping Apps
1. Open **Settings** → **Device Care** → **Battery**
2. Tap **3-dot menu** (⋮) → **Settings**
3. Tap **Never sleeping apps**
4. Tap **+** and add **Tailscale**

#### C. Enable Always-On VPN
1. Open **Settings** → **Connections** → **More connection settings** → **VPN**
2. Tap ⚙️ next to **Tailscale**
3. Enable **Always-on VPN**
4. Enable **Block connections without VPN** (optional but recommended)

### Step 2: Configure SSH Server App Battery Settings

Repeat the same battery configuration for **your SSH server app** (Termux, xnano, etc.):

1. **Settings** → **Apps** → **[Your SSH App]** → **Battery** → **Unrestricted**
2. Add **[Your SSH App]** to **Never sleeping apps** list

**Note**: If using xnano SSH Server, also enable its built-in auto-start on boot setting in the app.

### Step 3: Disable Global Battery Restrictions

1. Open **Settings** → **Device Care** → **Battery**
2. Tap **3-dot menu** → **Settings**
3. **Disable** the following:
   - ❌ Put unused apps to sleep
   - ❌ Auto-disable unused apps
   - ❌ Adaptive battery (optional - test both ways)

### Step 4: Install Termux (If Not Already Installed)

**⚠️ Important:** Do NOT use the Play Store version - it's deprecated and broken!

#### Download Termux (Choose One Method):

**Method 1: GitHub (Latest Stable)**
- Direct download: [Termux v0.118.3 APK](https://github.com/termux/termux-app/releases/download/v0.118.3/termux-app_v0.118.3+apt-android-7-github-debug_universal.apk)
- Enable "Install from unknown sources" for your browser
- Install the downloaded APK

**Method 2: F-Droid (Auto-Updates)**
- Install F-Droid: https://f-droid.org/
- Search for "Termux" in F-Droid
- Install from F-Droid

**If you have Play Store version:**
1. Backup any data
2. Uninstall completely
3. Install from GitHub or F-Droid (never mix sources!)

### Step 5: Setup Termux Auto-Start SSH

#### A. Install Required Packages

Open Termux and run:

```bash
pkg update && pkg upgrade
pkg install openssh termux-api termux-boot termux-services
```

#### B. Run Auto-Setup Script

Transfer `setup_termux_ssh_server.sh` to your phone and run it:

```bash
# Option 1: Download directly in Termux
curl -O https://your-server/setup_termux_ssh_server.sh
chmod +x setup_termux_ssh_server.sh
./setup_termux_ssh_server.sh

# Option 2: Copy from PC via SSH (if already connected)
# On PC: scp -P 8022 setup_termux_ssh_server.sh user@fold7:~/
# On phone: chmod +x setup_termux_ssh_server.sh && ./setup_termux_ssh_server.sh
```

The script will:
- Install required packages
- Configure SSH daemon
- Setup boot scripts with wake lock
- Add auto-start to `.bashrc`
- Display your SSH connection details

#### C. Manual Setup (Alternative)

If you prefer manual setup:

1. **Create boot script:**
```bash
mkdir -p ~/.termux/boot
nano ~/.termux/boot/start-sshd
```

Add content:
```bash
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 5
sshd
echo "[$(date)] SSH started" >> ~/sshd-boot.log
```

Make executable:
```bash
chmod +x ~/.termux/boot/start-sshd
```

2. **Configure .bashrc:**
```bash
nano ~/.bashrc
```

Add at the end:
```bash
# Auto-start SSH
if ! pgrep -x sshd > /dev/null; then
    termux-wake-lock
    sshd
fi
```

### Step 5: Configure SSH Authentication

#### Option A: SSH Key (Recommended)

On your PC:
```bash
ssh-keygen -t ed25519 -C "fold7-access"
ssh-copy-id -p 8022 u0_a123@fold7-hostname
```

#### Option B: Password

In Termux:
```bash
passwd
```

### Step 6: Test Initial Connection

From your PC:
```bash
ssh -p 8022 u0_a123@fold7-tailscale-hostname
```

Replace:
- `u0_a123` with your actual Termux user (run `whoami` in Termux)
- `fold7-tailscale-hostname` with your device's Tailscale hostname

---

## Part 2: PC-Side Monitoring Script

### Step 1: Install Python Dependencies

The script uses only standard library modules. Python 3.7+ required.

```bash
# Verify Python version
python --version

# No additional packages needed!
```

### Step 2: Configure Monitor Settings

Edit `fold7_config.json`:

```json
{
  "device": {
    "name": "Samsung Fold 7",
    "tailscale_hostname": "your-actual-hostname",  // ← Change this!
    "ssh_port": 8022,
    "ssh_user": "u0_a123"  // ← Change this! (run 'whoami' in Termux)
  },
  "monitoring": {
    "check_interval_seconds": 30,
    "connection_timeout_seconds": 10,
    "max_retry_attempts": 5,
    "exponential_backoff": true
  }
}
```

**How to find your Tailscale hostname:**

In Termux:
```bash
tailscale status
```

Or on PC:
```bash
tailscale status | grep fold
```

### Step 3: Run the Monitor

#### Linux/Mac:
```bash
python3 fold7_ssh_monitor.py
```

#### Windows:
```cmd
python fold7_ssh_monitor.py
```

You should see:
```
============================================================
Samsung Fold 7 SSH Monitor - Auto-Reconnection Service
============================================================

2025-09-30 10:30:15 - INFO - Starting SSH monitor for Samsung Fold 7
2025-09-30 10:30:15 - INFO - Target: fold7
2025-09-30 10:30:45 - INFO - Status: Connected | Uptime: 30s | Total reconnects: 0
```

### Step 4: Run as Background Service

#### Linux (systemd):

Create `/etc/systemd/system/fold7-ssh-monitor.service`:

```ini
[Unit]
Description=Samsung Fold 7 SSH Monitor
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/path/to/scripts
ExecStart=/usr/bin/python3 fold7_ssh_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable fold7-ssh-monitor.service
sudo systemctl start fold7-ssh-monitor.service
sudo systemctl status fold7-ssh-monitor.service
```

#### Windows (Task Scheduler):

1. Open **Task Scheduler**
2. Create Task → **General**:
   - Name: `Fold7 SSH Monitor`
   - ✓ Run whether user is logged on or not
3. **Triggers** → New:
   - Begin: At startup
4. **Actions** → New:
   - Program: `C:\Python\python.exe`
   - Arguments: `C:\path\to\fold7_ssh_monitor.py`
   - Start in: `C:\path\to\`
5. **Conditions**:
   - ✓ Start only if network connection is available
6. **Settings**:
   - ✓ If task fails, restart every 5 minutes

#### Mac (launchd):

Create `~/Library/LaunchAgents/com.fold7.ssh-monitor.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fold7.ssh-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Users/you/scripts/fold7_ssh_monitor.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/you/scripts</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load:
```bash
launchctl load ~/Library/LaunchAgents/com.fold7.ssh-monitor.plist
```

---

## Monitoring and Logs

### View Monitor Logs

```bash
# Real-time monitoring
tail -f fold7_ssh_monitor.log

# Recent failures
grep "FAILED\|RECOVERED" fold7_ssh_monitor.log
```

### Check Termux SSH Status

On the phone in Termux:
```bash
# Check if SSH is running
pgrep -a sshd

# Check boot log
cat ~/sshd-boot.log

# Check wake lock
cat $PREFIX/var/run/termux-wake-lock.pid

# Test from localhost
ssh localhost -p 8022
```

### Monitor Connection Uptime

The script logs periodic status:
```
2025-09-30 14:30:15 - INFO - Status: Connected | Uptime: 7200s | Total reconnects: 3
```

---

## Troubleshooting

### Issue: "Connection refused"

**Possible causes:**
1. SSH daemon not running in Termux
2. Wrong port (should be 8022 for Termux)
3. Termux killed by Android

**Solutions:**
```bash
# On phone in Termux:
whoami              # Note your username
sshd                # Start SSH manually
pgrep sshd          # Verify it's running
termux-wake-lock    # Prevent sleep
```

### Issue: "No route to host" or "Network unreachable"

**Possible causes:**
1. Tailscale not connected on phone
2. Phone on different network
3. Tailscale app was killed

**Solutions:**
1. Open Tailscale app on phone
2. Verify connection status (should show green/connected)
3. Check battery settings again (may have reset)
4. Try toggling Airplane mode to reset network

### Issue: Frequent disconnections

**Check these settings:**
1. Battery optimization → Should be "Unrestricted" for both apps
2. Never sleeping apps → Both Tailscale and Termux should be listed
3. Device Care → Background restrictions should be off
4. Developer options → "Don't keep activities" should be OFF

### Issue: SSH works initially but stops after reboot

**Possible causes:**
1. Boot script not configured
2. Termux:Boot not installed
3. Battery restrictions re-enabled after update

**Solutions:**
```bash
# Verify boot script exists
ls -la ~/.termux/boot/start-sshd

# Check if executable
chmod +x ~/.termux/boot/start-sshd

# Reinstall Termux:Boot
pkg install termux-boot

# Manually grant battery permissions again after OS updates
```

### Issue: Monitor shows "Max retry attempts reached"

The monitor will attempt to restart the SSH service automatically. Check:

1. Can you SSH manually? `ssh -p 8022 user@fold7`
2. Is Tailscale connected? `tailscale status`
3. Is phone awake? (Script can't wake a completely dead phone)

---

## Advanced Configuration

### Adjust Monitoring Frequency

In `fold7_config.json`:
```json
{
  "monitoring": {
    "check_interval_seconds": 60,      // Check every 60s instead of 30s
    "connection_timeout_seconds": 15,   // Allow 15s for slow networks
    "max_retry_attempts": 10           // More attempts before restart
  }
}
```

### Multiple Devices

Create separate config files:
```bash
# For Fold 7
python3 fold7_ssh_monitor.py fold7_config.json

# For another device
python3 fold7_ssh_monitor.py tablet_config.json
```

### Email Notifications on Failure

You can extend the script to send emails. Add to the `handle_connection_failure()` method:

```python
import smtplib
from email.message import EmailMessage

def send_email_alert(subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = 'monitor@yourdomain.com'
    msg['To'] = 'your@email.com'

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login('your@email.com', 'app-password')
        server.send_message(msg)
```

---

## Security Considerations

### 1. Use SSH Keys (Not Passwords)

SSH keys are more secure and enable automatic reconnection:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/fold7_key
ssh-copy-id -i ~/.ssh/fold7_key -p 8022 user@fold7
```

Update your `.ssh/config`:
```
Host fold7
    HostName fold7-tailscale-name
    Port 8022
    User u0_a123
    IdentityFile ~/.ssh/fold7_key
    StrictHostKeyChecking no
    ServerAliveInterval 60
```

### 2. Tailscale ACLs

Restrict SSH access in Tailscale ACLs:
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["your-pc"],
      "dst": ["fold7:22", "fold7:8022"]
    }
  ]
}
```

### 3. Termux Permissions

Limit SSH access:
```bash
# In Termux
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

## Performance Tips

### Reduce Battery Drain

1. **Disable wake lock when not needed:**
   ```bash
   termux-wake-unlock
   ```

2. **Use SSH ControlMaster** for faster reconnects:
   ```
   Host fold7
       ControlMaster auto
       ControlPath ~/.ssh/control-%r@%h:%p
       ControlPersist 10m
   ```

3. **Optimize monitor intervals** - Check every 60s instead of 30s

### Reduce Data Usage

Add to `~/.ssh/config`:
```
Host fold7
    Compression yes
    ServerAliveInterval 120
```

---

## Files in This Solution

```
development/
├── IDENTIFY_YOUR_SSH_APP.md       # START HERE - Identify which SSH app you have
├── fold7_ssh_monitor.py           # Universal monitoring script (works with any SSH app)
├── fold7_config.json              # Configuration file (customize this!)
├── FOLD7_SSH_SETUP.md             # This guide (for Termux users)
├── setup_termux_ssh_server.sh     # Termux-specific setup script
├── setup_xnano_ssh_server.md      # Guide for xnano SSH Server app users
└── fold7_ssh_monitor.log          # Log file (generated at runtime)
```

---

## Quick Reference

### Phone Commands (Termux)
```bash
sshd                    # Start SSH server
pkill sshd              # Stop SSH server
pgrep sshd              # Check if running
whoami                  # Get username
termux-wake-lock        # Prevent sleep
termux-wake-unlock      # Allow sleep
cat ~/sshd-boot.log     # View boot logs
```

### PC Commands
```bash
# Test connection
ssh -p 8022 user@fold7

# Start monitor
python3 fold7_ssh_monitor.py

# View logs
tail -f fold7_ssh_monitor.log

# Check Tailscale
tailscale status
```

### Samsung Settings Checklist
- ✓ Tailscale → Battery → Unrestricted
- ✓ Termux → Battery → Unrestricted
- ✓ Both apps in "Never sleeping apps"
- ✓ Tailscale → Always-on VPN enabled
- ✓ Device Care → "Put unused apps to sleep" OFF
- ✓ Device Care → "Auto-disable unused apps" OFF

---

## Support and Updates

For issues or improvements, check:
- Tailscale docs: https://tailscale.com/kb/1023/troubleshooting
- Termux wiki: https://wiki.termux.com
- This script location: `development/fold7_ssh_monitor.py`

Last updated: 2025-09-30