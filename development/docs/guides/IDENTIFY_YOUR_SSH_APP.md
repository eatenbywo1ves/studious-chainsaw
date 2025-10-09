# Which SSH Server App Are You Using?

Quick guide to identify which SSH/terminal app you have installed on your Samsung Fold 7.

---

## Method 1: Check Your Phone

Look at your app drawer or home screen and compare the app icons/names:

### Option A: **Termux**
- **Icon**: Black terminal window with ">" prompt
- **App Name**: "Termux"
- **Description**: "Terminal emulator with packages"
- **Play Store**: https://f-droid.org/en/packages/com.termux/
- **Best known for**: Full Linux environment on Android

**If this is your app → Use:** `setup_termux_ssh_server.sh` and `FOLD7_SSH_SETUP.md`

---

### Option B: **SSH/SFTP Server - Terminal**
- **Icon**: Orange/red server icon or terminal symbol
- **App Name**: "SSH/SFTP Server - Terminal" or "SSH Server"
- **Developer**: Banana Studio
- **Play Store**: https://play.google.com/store/apps/details?id=net.xnano.android.sshserver
- **Best known for**: Dedicated SSH server with GUI configuration

**If this is your app → Use:** `setup_xnano_ssh_server.md`

---

### Option C: **Termius**
- **Icon**: Blue terminal window
- **App Name**: "Termius"
- **Description**: "SSH client"
- **Play Store**: https://play.google.com/store/apps/details?id=com.server.auditor.ssh.client

**Important**: Termius is an SSH **CLIENT** (for connecting TO servers), not a server. It cannot host SSH on your phone. If you need to SSH INTO your phone, you need Option A or B instead.

---

### Option D: **Something Else?**

If your app doesn't match any above, check:

1. **App name** in your launcher
2. **Package name**:
   - Settings → Apps → Your SSH app → Advanced → Package name
3. **Developer** listed in Play Store

Common alternatives:
- **ConnectBot** (SSH client, not server)
- **JuiceSSH** (SSH client, not server)
- **Linux Deploy** (Can run SSH, uses chroot/proot)
- **UserLAnd** (Linux distros on Android with SSH)

---

## Method 2: Test What Port Your SSH Server Uses

If you have SSH already running but don't know which app:

### Check Running SSH Servers

If you have `adb` access:
```bash
adb shell netstat -tlnp | grep -E ':(22|2222|8022)'
```

Or from Termux/terminal on phone:
```bash
netstat -tlnp | grep -E ':(22|2222|8022)'
# or
ss -tlnp | grep -E ':(22|2222|8022)'
```

**Port identification:**
- **Port 8022** → Usually **Termux**
- **Port 2222** → Usually **xnano SSH Server** (default)
- **Port 22** → Custom setup or Linux Deploy/UserLAnd

---

## Method 3: Check by Features

Ask yourself these questions:

### Question 1: Do you have a full Linux command line?

**YES** → Likely Termux, Linux Deploy, or UserLAnd
**NO** → Likely xnano SSH Server

### Question 2: Can you run `apt` or `pkg` commands?

```bash
pkg list-installed
```

**YES** → You have **Termux**
**NO** → You have xnano SSH Server or similar

### Question 3: Does your app have a GUI with a START/STOP button?

**YES** → Likely **xnano SSH Server**
**NO** → Likely **Termux** (command-line based)

### Question 4: Can you browse files in your app?

**YES, built-in file browser** → Likely **xnano SSH Server**
**NO** → Likely **Termux** (use `ls` commands)

---

## What If You're Not Sure?

### Take a Screenshot

1. Open your SSH/terminal app
2. Take a screenshot of the main screen
3. Compare with these examples:

**Termux looks like:**
```
~ $ ls
~ $ pkg install openssh
~ $ sshd
```
Black/dark terminal with command prompt. No GUI buttons.

**xnano SSH Server looks like:**
```
┌─────────────────────────┐
│   [START SERVER]        │
│                         │
│ Status: Running         │
│ Port: 2222              │
│ Users: 1                │
└─────────────────────────┘
```
GUI interface with big start button, status indicators, tabs.

---

## Decision Tree

```
START HERE
    ↓
Do you see a command prompt ($) when you open the app?
    ↓                           ↓
   YES                          NO
    ↓                           ↓
Can you type                 Do you see GUI
"pkg install"?               buttons/tabs?
    ↓                           ↓
   YES          NO              YES
    ↓            ↓               ↓
 TERMUX    Something      XNANO SSH
                else          SERVER
```

---

## Quick Setup Selector

Once you've identified your app:

### ✓ I have **Termux**

**Setup files:**
- Main guide: `FOLD7_SSH_SETUP.md` (Part 1: Termux Setup)
- Setup script: `setup_termux_ssh_server.sh`
- Monitor: `fold7_ssh_monitor.py` (works with all)

**Quick start:**
1. Read `FOLD7_SSH_SETUP.md` → "Part 1: Samsung Fold 7 Configuration" → "Step 4: Setup Termux Auto-Start SSH"
2. Run `setup_termux_ssh_server.sh` in Termux
3. Configure `fold7_config.json` on your PC
4. Run `python3 fold7_ssh_monitor.py`

---

### ✓ I have **SSH/SFTP Server - Terminal** (xnano)

**Setup files:**
- Main guide: `setup_xnano_ssh_server.md`
- Monitor: `fold7_ssh_monitor.py` (works with all)

**Quick start:**
1. Read `setup_xnano_ssh_server.md`
2. Configure via app GUI (much easier than Termux!)
3. Enable auto-start on boot in app settings
4. Configure `fold7_config.json` on your PC
5. Run `python3 fold7_ssh_monitor.py`

---

### ✓ I have **Termius** (or other SSH client)

**Problem**: SSH clients connect TO servers, they don't HOST servers.

**Solution**: You need to install an SSH **server** app:

**Option 1**: Install **Termux** (free, open-source, full Linux)
- Download: https://f-droid.org/en/packages/com.termux/
- Follow: `FOLD7_SSH_SETUP.md`

**Option 2**: Install **SSH/SFTP Server - Terminal** (free, easier GUI)
- Download: Play Store → "SSH/SFTP Server - Terminal"
- Follow: `setup_xnano_ssh_server.md`

---

### ✓ I have something else

**Check if it can host SSH:**
1. Look for "SSH Server" or "SSHD" in the app description
2. Check if you can set a port and user
3. Try connecting from another device: `ssh -p PORT user@phone-ip`

**If it works:**
- The Python monitor (`fold7_ssh_monitor.py`) will work with ANY SSH server
- Just configure the port and user in `fold7_config.json`
- Battery optimization steps are the same regardless of app

**If it doesn't work:**
- Install Termux or xnano SSH Server instead

---

## Still Need Help?

### Information to Gather

1. **App name** (from your app drawer)
2. **Package name** (Settings → Apps → Your app → Package name)
3. **What you see** when you open the app
4. **What port** your SSH server uses
5. **Screenshot** of the app's main screen

### Common Mistakes

❌ **Installing Termius thinking it's Termux**
- Termius = SSH client (connects TO servers)
- Termux = Terminal emulator (CAN host SSH servers)

❌ **Thinking ConnectBot/JuiceSSH host SSH**
- These are SSH clients, not servers
- You need Termux or xnano to host SSH

❌ **Expecting apps to auto-start without configuration**
- ALL apps need battery optimization disabled
- ALL apps need to be in "Never sleeping apps"
- Some apps need additional auto-start setup

---

## Comparison Chart

| Feature | Termux | xnano SSH Server | Termius |
|---------|--------|-----------------|---------|
| **Type** | Terminal + SSH Server | Dedicated SSH Server | SSH Client |
| **Host SSH?** | ✓ Yes | ✓ Yes | ✗ No |
| **GUI Config** | ✗ No (CLI) | ✓ Yes | ✓ Yes |
| **Auto-start** | Complex | Easy (built-in) | N/A |
| **Linux Env** | ✓ Full | ✗ None | ✗ None |
| **Learning Curve** | High | Low | Low |
| **Best For** | Power users, dev | Simple SSH hosting | Connecting to servers |

---

## My Recommendation

### If you want **easiest setup**:
→ **Use xnano SSH Server** + `setup_xnano_ssh_server.md`

### If you want **full Linux environment**:
→ **Use Termux** + `FOLD7_SSH_SETUP.md`

### If you want **to connect to other servers**:
→ **Use Termius** (but you still need Termux/xnano to host SSH on your phone)

---

## Next Steps

1. **Identify your app** using methods above
2. **Choose your setup guide**:
   - Termux → `FOLD7_SSH_SETUP.md`
   - xnano → `setup_xnano_ssh_server.md`
   - Don't have either → Install one and follow its guide
3. **Configure Samsung battery settings** (required for ALL apps)
4. **Setup Tailscale** with Always-On VPN
5. **Configure and run** `fold7_ssh_monitor.py` on your PC

The Python monitor works with **any SSH server** regardless of which app you choose!

---

Last updated: 2025-09-30