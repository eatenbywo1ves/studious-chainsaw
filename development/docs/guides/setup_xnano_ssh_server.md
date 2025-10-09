# SSH/SFTP Server - Terminal Setup Guide (xnano/Banana Studio)

Configuration guide for the **SSH/SFTP Server - Terminal** app by Banana Studio (xnano) on Samsung Fold 7 with Tailscale.

## Overview

This app is a **dedicated SSH server** with built-in auto-start features, making it easier to configure than Termux. It's specifically designed for hosting SSH/SFTP services on Android.

**App Details:**
- **Name**: SSH/SFTP Server - Terminal
- **Developer**: Banana Studio (xnano)
- **Package**: `net.xnano.android.sshserver`
- **Play Store**: https://play.google.com/store/apps/details?id=net.xnano.android.sshserver

---

## Advantages Over Termux

✓ Built-in auto-start on boot (no addons needed)
✓ Auto-start on WiFi connection detection
✓ Tasker integration for advanced automation
✓ Simple GUI configuration (no scripting required)
✓ Multiple user support
✓ Built-in SFTP file access
✓ Doesn't require separate terminal emulator

---

## Step 1: Install and Configure the App

### A. Install from Play Store

1. Open Google Play Store
2. Search for "SSH/SFTP Server - Terminal"
3. Install the app (developer: Banana Studio)

### B. Initial Configuration

1. **Launch the app**
2. **Set SSH port** (default is 2222, but you can change it):
   - Tap **Settings** (gear icon)
   - Tap **Port**
   - Enter: `8022` (to match standard Termux convention)
   - Or use any port you prefer

3. **Create user account**:
   - Tap **Users** tab
   - Tap **+** to add new user
   - Enter username (e.g., `fold7user`)
   - Set password or configure SSH key authentication
   - Select home directory (default is usually fine)
   - Tap **Save**

4. **Configure authentication** (recommended: SSH keys):
   - In user settings, tap **Authentication**
   - Enable **Public Key Authentication**
   - Add your public key from your PC:
     ```bash
     # On PC: Copy your public key
     cat ~/.ssh/id_ed25519.pub
     ```
   - Paste into the app's authorized keys field

---

## Step 2: Enable Auto-Start on Boot

This is the **easiest part** compared to Termux!

1. Open the app
2. Tap **Settings** (gear icon)
3. Find **Auto-start on boot**
4. Toggle it **ON**
5. If prompted, grant permission to start on boot

That's it! No scripts, no addon apps needed.

---

## Step 3: Enable Auto-Start on WiFi (Optional)

Automatically start SSH when connected to your home/work WiFi:

1. In **Settings**, find **Auto-start on WiFi**
2. Toggle it **ON**
3. Select which WiFi networks should trigger auto-start
4. The app will only start SSH when connected to these networks

**Note**: Requires location permission on Android P+

---

## Step 4: Configure Samsung Battery Settings

Even with auto-start enabled, Samsung's aggressive battery management can kill the app.

### A. Set Battery to Unrestricted

1. Open **Settings** → **Apps** → **SSH/SFTP Server - Terminal**
2. Tap **Battery**
3. Select **Unrestricted**
4. Enable **Allow background activity** (if available)

### B. Add to Never Sleeping Apps

1. Open **Settings** → **Device Care** → **Battery**
2. Tap **3-dot menu** (⋮) → **Settings**
3. Tap **Never sleeping apps**
4. Tap **+** and add **SSH/SFTP Server - Terminal**

### C. Disable Global Battery Restrictions

1. In **Device Care** → **Battery** → **Settings**
2. **Disable**:
   - ❌ Put unused apps to sleep
   - ❌ Auto-disable unused apps

---

## Step 5: Configure Tailscale

### A. Install Tailscale

1. Install Tailscale from Play Store
2. Sign in to your Tailscale account
3. Connect to your tailnet

### B. Set Tailscale Battery to Unrestricted

Repeat the battery optimization steps for **Tailscale**:
- Settings → Apps → Tailscale → Battery → **Unrestricted**
- Add to **Never sleeping apps**

### C. Enable Always-On VPN

1. Open **Settings** → **Connections** → **More connection settings** → **VPN**
2. Tap ⚙️ next to **Tailscale**
3. Enable **Always-on VPN**
4. Enable **Block connections without VPN** (optional)

### D. Find Your Tailscale Hostname

In the Tailscale app:
1. Tap your device name
2. Note the **Machine name** (e.g., `samsung-fold7`)
3. Your full hostname is: `samsung-fold7.tailnet-name.ts.net`

Or from terminal on another device:
```bash
tailscale status | grep fold
```

---

## Step 6: Start the SSH Server

1. Open **SSH/SFTP Server - Terminal**
2. Tap the **big START button**
3. Server status should show: **Running**
4. Note the displayed IP addresses and port

The server will now:
- ✓ Auto-start on device reboot
- ✓ Auto-start on WiFi connection (if configured)
- ✓ Stay running in background

---

## Step 7: Test SSH Connection

From your PC:

```bash
# Test connection
ssh -p 8022 fold7user@your-fold7-tailscale-hostname

# Example:
ssh -p 8022 fold7user@samsung-fold7.tailnet.ts.net
```

If successful, you should get a shell prompt on your Fold 7!

---

## Step 8: Setup SSH Keys (Recommended)

For automatic reconnection without passwords:

### On PC:

1. **Generate key** (if you don't have one):
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/fold7_key -C "fold7-access"
   ```

2. **Copy public key**:
   ```bash
   cat ~/.ssh/fold7_key.pub
   ```

### On Phone:

1. Open **SSH/SFTP Server - Terminal**
2. Go to **Users** tab
3. Tap your user
4. Tap **Authentication**
5. Paste your public key in **Authorized Keys**
6. Save

### Configure SSH Client:

Edit `~/.ssh/config`:
```
Host fold7
    HostName samsung-fold7.tailnet.ts.net
    Port 8022
    User fold7user
    IdentityFile ~/.ssh/fold7_key
    StrictHostKeyChecking no
    ServerAliveInterval 60
```

Now you can connect with just: `ssh fold7`

---

## Step 9: Configure Python Monitor

Edit `fold7_config.json`:

```json
{
  "device": {
    "name": "Samsung Fold 7 (xnano SSH Server)",
    "tailscale_hostname": "samsung-fold7.tailnet.ts.net",
    "ssh_port": 8022,
    "ssh_user": "fold7user"
  },
  "monitoring": {
    "check_interval_seconds": 30,
    "connection_timeout_seconds": 10,
    "max_retry_attempts": 5,
    "exponential_backoff": true
  },
  "reconnection": {
    "enabled": false,
    "restart_sshd_command": null,
    "notes": "xnano app manages SSH automatically, no restart command needed"
  }
}
```

**Note**: Set `reconnection.enabled` to `false` because the xnano app manages the SSH server automatically and you can't restart it via SSH commands.

### Run the monitor:

```bash
python3 fold7_ssh_monitor.py
```

---

## Advanced: Tasker Integration

For even more automation possibilities:

### Install Tasker

1. Install **Tasker** from Play Store
2. Grant necessary permissions

### Create SSH Auto-Start Task

1. Open Tasker
2. Create new **Task**: "Start Fold7 SSH"
3. Add **Action** → **System** → **Send Intent**
4. Configure:
   - **Action**: `net.xnano.android.sshserver.START_SERVER`
   - **Package**: `net.xnano.android.sshserver`
   - **Class**: `net.xnano.android.sshserver.receivers.CustomBroadcastReceiver`
5. Save

### Create Profile (Trigger)

Create profiles to automatically start SSH when:
- Connected to specific WiFi
- Bluetooth device connected
- Time-based schedule
- Location-based
- Battery above certain level

Example - Start on Home WiFi:
1. New **Profile** → **State** → **Net** → **Wifi Connected**
2. Select your WiFi SSID
3. Link to "Start Fold7 SSH" task

---

## Troubleshooting

### Server won't auto-start on boot

**Check:**
1. Auto-start toggle is enabled in app settings
2. Battery optimization is set to Unrestricted
3. App is in "Never sleeping apps" list
4. Device Care isn't putting app to sleep

**Solution:**
- Manually start once after reboot
- Check app notifications for error messages
- Verify app has boot permission: Settings → Apps → SSH Server → Permissions

### Can't connect via Tailscale

**Check:**
1. Tailscale is connected (green indicator)
2. Both devices are on same tailnet
3. Correct hostname/IP address
4. Correct port (8022 or your custom port)
5. Firewall rules in Tailscale ACLs

**Test:**
```bash
# From PC, check if Tailscale can reach phone
ping samsung-fold7.tailnet.ts.net

# Check if port is open
nc -zv samsung-fold7.tailnet.ts.net 8022
```

### Authentication failures

**Check:**
1. Username is correct (case-sensitive)
2. If using password: verify password is correct
3. If using keys: ensure public key is in authorized keys
4. Check app logs for authentication errors

### Connection drops after few minutes

**Likely cause**: Battery optimization killing app

**Solutions:**
1. Verify all battery settings are Unrestricted
2. Keep app open in background (swipe up from multitasking, don't close)
3. Enable SSH keep-alive in `~/.ssh/config`:
   ```
   Host fold7
       ServerAliveInterval 30
       ServerAliveCountMax 3
   ```

### App crashes or closes unexpectedly

**Check:**
1. App is up-to-date (Play Store → Updates)
2. Sufficient storage space on device
3. No conflicting apps using same port
4. Check logcat for crash logs

**Get logs:**
```bash
adb logcat | grep "xnano\|sshserver"
```

---

## Comparison: xnano SSH Server vs Termux

| Feature | xnano SSH Server | Termux |
|---------|-----------------|--------|
| **Setup Difficulty** | ⭐ Easy (GUI) | ⭐⭐⭐ Complex (CLI) |
| **Auto-start on Boot** | ✓ Built-in toggle | Requires addon app |
| **WiFi Trigger** | ✓ Built-in | Manual scripting |
| **Tasker Integration** | ✓ Native support | Possible but complex |
| **Terminal Access** | Basic built-in | Full Linux environment |
| **Package Management** | None | apt/pkg (1000+ packages) |
| **SFTP Support** | ✓ Built-in | Via openssh package |
| **Multiple Users** | ✓ Easy GUI | Manual configuration |
| **File Browser** | ✓ Built-in | Via packages |
| **Learning Curve** | Low | High |
| **Flexibility** | Limited to SSH/SFTP | Full Linux system |
| **Resource Usage** | Light | Heavier |

---

## Security Best Practices

### 1. Use SSH Keys (Not Passwords)

SSH keys are much more secure and enable passwordless auto-connection.

### 2. Change Default Port

Use a non-standard port (like 8022) instead of default 2222.

### 3. Disable Root Login

The app runs as a regular Android user, so this is already enforced.

### 4. Limit Access via Tailscale ACLs

Configure Tailscale to only allow SSH from specific devices:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:trusted-pc"],
      "dst": ["samsung-fold7:8022"]
    }
  ]
}
```

### 5. Enable Connection Logging

In app settings:
1. Enable **Connection Logging**
2. Review logs periodically for suspicious activity
3. Check **Users & Connections** tab for active sessions

### 6. Use Strong Passwords

If using password authentication:
- Minimum 16 characters
- Mix of letters, numbers, symbols
- Use password manager

---

## Performance Tips

### Reduce Battery Drain

1. **Don't use wake lock** unless absolutely necessary
2. **Disable WiFi trigger** when not needed
3. **Use SSH keep-alive** instead of continuous connections
4. **Close idle connections** in app settings

### Optimize for Low Data Usage

In `~/.ssh/config`:
```
Host fold7
    Compression yes
    ServerAliveInterval 120
```

### Multiple Concurrent Connections

The app supports multiple SSH connections simultaneously. Configure max connections in settings if needed.

---

## Quick Reference

### Essential Commands (on PC)

```bash
# Connect
ssh -p 8022 fold7user@samsung-fold7.tailnet.ts.net

# Copy file TO phone
scp -P 8022 file.txt fold7user@samsung-fold7.tailnet.ts.net:~/

# Copy file FROM phone
scp -P 8022 fold7user@samsung-fold7.tailnet.ts.net:~/file.txt ./

# SFTP session
sftp -P 8022 fold7user@samsung-fold7.tailnet.ts.net
```

### Tasker Intents

```
# Start server
Action: net.xnano.android.sshserver.START_SERVER
Package: net.xnano.android.sshserver
Class: net.xnano.android.sshserver.receivers.CustomBroadcastReceiver

# Stop server
Action: net.xnano.android.sshserver.STOP_SERVER
Package: net.xnano.android.sshserver
Class: net.xnano.android.sshserver.receivers.CustomBroadcastReceiver
```

### Samsung Settings Checklist

- ✓ SSH Server app → Battery → Unrestricted
- ✓ Tailscale app → Battery → Unrestricted
- ✓ Both apps in "Never sleeping apps" list
- ✓ Tailscale → Always-on VPN enabled
- ✓ Device Care → "Put unused apps to sleep" OFF
- ✓ Device Care → "Auto-disable unused apps" OFF
- ✓ SSH Server → Auto-start on boot enabled

---

## Support

- **App Support**: support@xnano.net
- **XDA Forum**: https://xdaforums.com/t/ssh-sftp-server-terminal.3740091/
- **Tailscale Docs**: https://tailscale.com/kb/

---

Last updated: 2025-09-30