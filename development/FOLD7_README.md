       # Samsung Fold 7 SSH Auto-Reconnection Solution

**Maintain persistent SSH connectivity to your Samsung Fold 7 via Tailscale with automatic reconnection.**

---

## 🚀 Quick Start (3 Steps)

### Step 1: Identify Your SSH Server App

**Do you know which SSH app you're using on your phone?**

- ❓ **Not sure** → Start here: [`IDENTIFY_YOUR_SSH_APP.md`](IDENTIFY_YOUR_SSH_APP.md)
- ✓ **I have Termux** → Go to Step 2A
- ✓ **I have SSH/SFTP Server (xnano)** → Go to Step 2B
- ✗ **I don't have either** → Choose one and install it:
  - **Termux**: Full Linux environment, complex setup
  - **xnano SSH Server**: Easier GUI-based setup

### Step 2A: Setup for Termux Users

1. **Configure phone**: Follow [`FOLD7_SSH_SETUP.md`](FOLD7_SSH_SETUP.md)
   - Configure battery settings
   - Setup Tailscale Always-On VPN
   - Run `setup_termux_ssh_server.sh` on phone

### Step 2B: Setup for xnano SSH Server Users

1. **Configure phone**: Follow [`setup_xnano_ssh_server.md`](setup_xnano_ssh_server.md)
   - Configure battery settings (simpler than Termux)
   - Enable auto-start in app (one toggle!)
   - Setup Tailscale Always-On VPN

### Step 3: Setup PC-Side Monitor (Both Apps)

1. **Edit config**: `fold7_config.json`
   - Set your Tailscale hostname
   - Set SSH port (8022 for Termux, 2222 for xnano by default)
   - Set your SSH username

2. **Run monitor**:
   ```bash
   python3 fold7_ssh_monitor.py
   ```

3. **Optional**: Setup as background service (see guides)

---

## 📁 Files in This Solution

| File | Purpose | Who Needs It |
|------|---------|--------------|
| **[IDENTIFY_YOUR_SSH_APP.md](IDENTIFY_YOUR_SSH_APP.md)** | Identify which SSH app you have | Everyone (start here if unsure) |
| **[fold7_ssh_monitor.py](fold7_ssh_monitor.py)** | Auto-reconnection monitor script | Everyone (runs on PC) |
| **[fold7_config.json](fold7_config.json)** | Configuration file | Everyone (edit before running) |
| **[FOLD7_SSH_SETUP.md](FOLD7_SSH_SETUP.md)** | Termux setup guide | Termux users only |
| **[setup_termux_ssh_server.sh](setup_termux_ssh_server.sh)** | Termux auto-setup script | Termux users only |
| **[setup_xnano_ssh_server.md](setup_xnano_ssh_server.md)** | xnano SSH Server guide | xnano users only |

---

## 🎯 What This Solution Does

### The Problem

Samsung Fold devices with One UI aggressively kill background apps, causing:
- Tailscale VPN to disconnect randomly
- SSH servers to stop running
- Connection drops during WiFi ↔ Cellular transitions
- Services killed during deep sleep

### The Solution

**Two-pronged approach:**

1. **Phone-side configuration**:
   - Disable battery optimization for Tailscale and SSH app
   - Configure auto-start mechanisms
   - Setup Tailscale Always-On VPN
   - Use wake locks to prevent deep sleep

2. **PC-side monitoring**:
   - Python script continuously monitors SSH connectivity
   - Automatically reconnects when connection drops
   - Uses exponential backoff for retry logic
   - Logs all connection events

### Why This Works

- **Battery settings** prevent Android from killing apps
- **PC-side monitoring** is more reliable than phone-side scripts
- **Universal monitor** works with any SSH server app
- **Tailscale** provides persistent VPN connectivity

---

## 🔧 Requirements

### On Your Phone (Samsung Fold 7)

- Android with One UI (Samsung)
- **Tailscale** installed and configured
- **SSH server app** (choose one):
  - **Termux** (free, complex, full Linux)
  - **SSH/SFTP Server - Terminal** by xnano (free, easier)

### On Your PC/Server

- Python 3.7 or higher (no additional packages needed!)
- Tailscale installed and connected to same tailnet
- SSH client (`ssh` command)

---

## 📊 Feature Comparison

### Termux vs xnano SSH Server

| Feature | Termux | xnano SSH Server |
|---------|--------|------------------|
| **Ease of Setup** | Complex (CLI) | Easy (GUI) |
| **Auto-start on Boot** | Requires addon | Built-in toggle |
| **WiFi Auto-start** | Manual scripting | Built-in setting |
| **Terminal Environment** | Full Linux | Basic |
| **Package Manager** | Yes (1000+ pkgs) | No |
| **SFTP** | Via openssh | Built-in |
| **Best For** | Developers, power users | Simple SSH hosting |

**Recommendation:**
- Want simplicity? → **xnano SSH Server**
- Want full Linux? → **Termux**
- Either works great with the monitor script!

---

## 🔍 Troubleshooting

### Common Issues

#### "Connection refused" errors
- SSH server not running on phone
- Wrong port in config
- Battery optimization killed the app

**Solution**: Check battery settings, manually start SSH, verify port number

#### Frequent disconnections
- Battery optimization not disabled properly
- App not in "Never sleeping apps" list
- Tailscale Always-On VPN not enabled

**Solution**: Verify ALL battery settings on phone (see guides)

#### Can't find Tailscale hostname
**On phone or PC:**
```bash
tailscale status
```
Look for your phone's machine name

#### Monitor shows "Max retry attempts reached"
- Phone might be completely off or out of network
- Tailscale disconnected on phone
- SSH daemon crashed

**Solution**: Check phone is on, Tailscale connected, SSH running

### Getting Help

1. Check the app-specific guide thoroughly
2. Review `IDENTIFY_YOUR_SSH_APP.md` to ensure you're using the right guide
3. Check monitor logs: `tail -f fold7_ssh_monitor.log`
4. Test manual SSH: `ssh -p PORT user@hostname`

---

## 🔒 Security Notes

### Best Practices

1. **Use SSH keys** (not passwords) for auto-reconnection
2. **Configure Tailscale ACLs** to limit which devices can SSH
3. **Use non-standard ports** (8022 instead of 22)
4. **Review connection logs** periodically
5. **Keep apps updated** (Tailscale, SSH server, monitor script)

### Why This Is Secure

- Tailscale uses WireGuard encryption
- SSH provides end-to-end encryption
- No ports exposed to public internet
- Keys-based authentication (recommended)
- Zero-trust network model via Tailscale

---

## ⚙️ Configuration Examples

### Minimal Config (`fold7_config.json`)

```json
{
  "device": {
    "name": "Samsung Fold 7",
    "tailscale_hostname": "your-phone-hostname",
    "ssh_port": 8022,
    "ssh_user": "your-username"
  }
}
```

### Advanced Config with Custom Monitoring

```json
{
  "device": {
    "name": "Samsung Fold 7",
    "tailscale_hostname": "samsung-fold7.tailnet.ts.net",
    "ssh_port": 8022,
    "ssh_user": "u0_a123"
  },
  "monitoring": {
    "check_interval_seconds": 60,
    "connection_timeout_seconds": 15,
    "max_retry_attempts": 10,
    "exponential_backoff": true,
    "backoff_multiplier": 2,
    "max_backoff_seconds": 300
  },
  "reconnection": {
    "enabled": true,
    "restart_sshd_command": "pkill sshd && sshd"
  },
  "notifications": {
    "log_to_file": true,
    "log_file": "fold7_ssh_monitor.log",
    "console_output": true
  }
}
```

---

## 📖 Documentation Structure

### For First-Time Users

1. **Start**: `IDENTIFY_YOUR_SSH_APP.md` - Figure out which app you have
2. **Setup Phone**: Follow your app-specific guide
3. **Setup PC**: Configure and run `fold7_ssh_monitor.py`
4. **Test**: SSH into your phone and verify monitoring

### For Termux Users

1. `FOLD7_SSH_SETUP.md` - Complete setup guide
2. `setup_termux_ssh_server.sh` - Auto-setup script for phone
3. `fold7_config.json` - Configure monitoring

### For xnano SSH Server Users

1. `setup_xnano_ssh_server.md` - Complete setup guide
2. App GUI - Configure directly in app
3. `fold7_config.json` - Configure monitoring

---

## 🎓 How It Works

### Architecture

```
┌─────────────┐         ┌──────────────┐         ┌──────────────┐
│             │         │              │         │              │
│  Your PC    │◄───────►│  Tailscale   │◄───────►│ Samsung      │
│             │  VPN    │  Network     │  VPN    │ Fold 7       │
│  Monitor    │         │              │         │  SSH Server  │
│  Script     │         └──────────────┘         │  (Termux or  │
│             │                                   │   xnano)     │
└─────────────┘                                   └──────────────┘
      │                                                  ▲
      │                                                  │
      └──────────── SSH Connection (port 8022) ─────────┘
                    Checks every 30s
                    Auto-reconnects on failure
```

### Monitor Script Flow

1. **Check connectivity** every N seconds (configurable)
2. **If connected**: Log status, continue monitoring
3. **If disconnected**:
   - Retry with exponential backoff
   - After max retries, attempt to restart SSH service
   - Log all failures and recovery attempts
4. **On recovery**: Log downtime and resume monitoring

---

## 💡 Tips & Tricks

### Reduce Battery Drain

- Use SSH keep-alive instead of continuous connections
- Disable wake lock when not actively SSHing
- Use WiFi-only auto-start with xnano

### Optimize Performance

- Increase check interval to 60s if battery is concern
- Enable SSH compression for slower networks
- Use SSH ControlMaster for faster reconnects

### Running Monitor as Service

**Linux (systemd)**:
See `FOLD7_SSH_SETUP.md` → "Run as Background Service"

**Windows (Task Scheduler)**:
See `FOLD7_SSH_SETUP.md` → "Run as Background Service"

**macOS (launchd)**:
See `FOLD7_SSH_SETUP.md` → "Run as Background Service"

---

## 📝 Quick Reference

### Essential Commands

```bash
# On Phone (Termux)
sshd                          # Start SSH
pkill sshd                    # Stop SSH
pgrep sshd                    # Check if running
termux-wake-lock              # Prevent sleep

# On PC
ssh -p 8022 user@fold7        # Connect
python3 fold7_ssh_monitor.py  # Run monitor
tail -f fold7_ssh_monitor.log # View logs

# Tailscale
tailscale status              # Check connection
tailscale ip -4               # Get device IP
```

### Battery Settings Checklist

On your Samsung Fold 7:

- ✓ Tailscale → Battery → **Unrestricted**
- ✓ SSH App → Battery → **Unrestricted**
- ✓ Both apps in **"Never sleeping apps"**
- ✓ Tailscale → **Always-on VPN** enabled
- ✓ Device Care → "Put unused apps to sleep" → **OFF**
- ✓ Device Care → "Auto-disable unused apps" → **OFF**

---

## 🤝 Contributing

Found a bug or have improvements? This is a personal project, but suggestions are welcome!

---

## 📄 License

This solution is provided as-is for personal use. The monitor script uses only Python standard library and has no external dependencies.

---

## 🔗 Useful Links

- **Tailscale Docs**: https://tailscale.com/kb/1023/troubleshooting
- **Termux Wiki**: https://wiki.termux.com
- **Samsung Battery Optimization**: https://dontkillmyapp.com/samsung
- **SSH Configuration**: `man ssh_config`

---

**Last Updated**: 2025-09-30

**Compatible With**:
- Samsung Fold 7 (and other Samsung One UI devices)
- Termux SSH server
- xnano SSH/SFTP Server - Terminal
- Any SSH server app (monitor is universal)