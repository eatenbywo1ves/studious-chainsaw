# SSH Scripts Deployment Summary

**Deployment Date:** 2025-09-30
**Desktop:** stoopidpc (100.108.218.15)
**Phone:** samsung-sm-f966u (100.105.224.93)

---

## ✓ Desktop Setup (COMPLETE)

### Prerequisites ✓
- **Python:** 3.13.5 ✓
- **OpenSSH:** 10.0p2 ✓ (Running, Automatic startup)
- **Tailscale:** 1.86.2 ✓ (Connected)

### Configuration ✓
- **fold7_config.json** updated with actual Tailscale hostname: `samsung-sm-f966u`
- **SSH Server** running on port 22
- **Desktop Tailscale IP:** 100.108.218.15

### Scripts Ready ✓
- **fold7_ssh_monitor.py** - Ready to run (monitors phone connection)
- **Configuration file** - Updated and ready

---

## ⏳ Phone Setup (MANUAL STEPS REQUIRED)

### Files Prepared for Transfer

The following scripts are ready in `C:\Users\Corbin\Downloads\`:

1. **setup_termux_ssh_server.sh** (4.4K)
   - Auto-configures SSH server on phone
   - Sets up boot scripts and wake lock

2. **termux_ssh_to_desktop.sh** (12K)
   - Connects from phone TO desktop
   - Auto-reconnection with monitoring

---

## 📱 Phone Deployment Steps

### Step 1: Install Termux on Phone

**Download APK:**
```
https://github.com/termux/termux-app/releases/download/v0.118.3/termux-app_v0.118.3+apt-android-7-github-debug_universal.apk
```

**On your Samsung Fold 7:**
1. Open browser on phone
2. Download the APK from link above
3. Enable "Install from unknown sources" when prompted
4. Install and open Termux

### Step 2: Initial Termux Setup

**In Termux on phone, run:**
```bash
# Update packages
pkg update && pkg upgrade

# Install required packages
pkg install openssh termux-api termux-boot termux-services curl

# Start SSH server
sshd

# Get your username (you'll need this!)
whoami

# Enable wake lock
termux-wake-lock
```

**Important:** Note the username from `whoami` command!

### Step 3: Transfer Scripts to Phone

**Option A: USB Transfer**
1. Connect phone to PC via USB
2. Copy from `C:\Users\Corbin\Downloads\` to phone's Download folder:
   - `setup_termux_ssh_server.sh`
   - `termux_ssh_to_desktop.sh`

**Option B: Cloud Transfer**
1. Upload scripts to Google Drive/OneDrive/Dropbox
2. Download on phone
3. Files will be in phone's Downloads folder

**Option C: Via Termux Storage (if USB connected)**
```bash
# In Termux:
termux-setup-storage
# Grant permission when prompted

# Copy from phone Downloads:
cp ~/storage/downloads/setup_termux_ssh_server.sh ~/
cp ~/storage/downloads/termux_ssh_to_desktop.sh ~/
chmod +x *.sh
```

### Step 4: Run Setup Script on Phone

**In Termux:**
```bash
cd ~
chmod +x setup_termux_ssh_server.sh
./setup_termux_ssh_server.sh
```

This will configure:
- SSH auto-start on boot
- Wake lock to prevent sleep
- Boot scripts
- Display your connection info

### Step 5: Update Desktop Config with Phone Username

**After running `whoami` in Termux on phone:**

On desktop, edit `C:\Users\Corbin\development\fold7_config.json`:
```json
"ssh_user": "u0_aXXX"  // Replace with actual username from whoami
```

### Step 6: Configure Samsung Battery Settings

**Critical - do not skip!**

On Samsung Fold 7:

1. **Termux Battery:**
   - Settings → Apps → Termux → Battery → **Unrestricted**
   - Settings → Device Care → Battery → Never sleeping apps → Add **Termux**

2. **Tailscale Battery:**
   - Settings → Apps → Tailscale → Battery → **Unrestricted**
   - Settings → Device Care → Battery → Never sleeping apps → Add **Tailscale**
   - Settings → VPN → Tailscale → Enable **Always-on VPN**

3. **Global Settings:**
   - Settings → Device Care → Battery → Settings
   - Disable: "Put unused apps to sleep"
   - Disable: "Auto-disable unused apps"

---

## 🚀 Testing the Connection

### Test 1: Desktop → Phone (SSH INTO phone)

**On desktop:**
```bash
cd C:\Users\Corbin\development

# Test manual SSH first
ssh -p 8022 u0_aXXX@samsung-sm-f966u

# If successful, run monitor
python fold7_ssh_monitor.py
```

**Expected output:**
```
============================================================
Samsung Fold 7 SSH Monitor - Auto-Reconnection Service
============================================================

2025-09-30 21:30:15 - INFO - Starting SSH monitor for Samsung Fold 7
2025-09-30 21:30:15 - INFO - Target: samsung-sm-f966u
2025-09-30 21:30:45 - INFO - Status: Connected | Uptime: 30s | Total reconnects: 0
```

### Test 2: Phone → Desktop (SSH FROM phone)

**On phone in Termux:**
```bash
cd ~
chmod +x termux_ssh_to_desktop.sh

# Create config
./termux_ssh_to_desktop.sh --create-config

# Edit config
nano ~/.ssh/desktop_connection.conf
```

**Update these values:**
```bash
DESKTOP_HOST="stoopidpc"  # or "100.108.218.15"
DESKTOP_USER="Corbin"
DESKTOP_PORT="22"
SSH_KEY="$HOME/.ssh/id_ed25519"
```

**Test connection:**
```bash
./termux_ssh_to_desktop.sh --test
```

**If successful, run monitor:**
```bash
./termux_ssh_to_desktop.sh
```

---

## 📊 Deployment Status

### Desktop Side
- [x] Python installed and verified
- [x] SSH server running
- [x] Tailscale connected
- [x] Configuration file updated
- [x] Scripts ready to run
- [x] Files copied to Downloads for transfer

### Phone Side (Manual Steps Remaining)
- [ ] Install Termux from GitHub
- [ ] Run initial Termux setup
- [ ] Transfer scripts to phone
- [ ] Run setup_termux_ssh_server.sh
- [ ] Update fold7_config.json with actual username
- [ ] Configure battery optimization settings
- [ ] Test SSH connection
- [ ] Run monitoring scripts

---

## 🔧 Tailscale Network Info

**Desktop (stoopidpc):**
- Tailscale IP: 100.108.218.15
- SSH Port: 22
- Username: Corbin
- Status: Online ✓

**Phone (samsung-sm-f966u):**
- Tailscale IP: 100.105.224.93
- SSH Port: 8022 (Termux default)
- Username: TBD (run `whoami` in Termux)
- Status: Online ✓
- Direct connection: 192.168.1.154:36753

**Connection:** Both devices can see each other via Tailscale ✓

---

## 📁 File Locations

### On Desktop PC

**Development Directory:** `C:\Users\Corbin\development\`
- fold7_ssh_monitor.py - Monitor script (desktop → phone)
- fold7_config.json - Configuration (updated)
- FOLD7_README.md - Master guide
- FOLD7_SSH_SETUP.md - Termux setup guide
- TERMUX_DESKTOP_SSH.md - Phone→desktop guide
- IDENTIFY_YOUR_SSH_APP.md - App identification help

**Downloads Directory:** `C:\Users\Corbin\Downloads\`
- setup_termux_ssh_server.sh - Copy this to phone
- termux_ssh_to_desktop.sh - Copy this to phone

### On Phone (After Transfer)

**Target location:** `/data/data/com.termux/files/home/`
- setup_termux_ssh_server.sh
- termux_ssh_to_desktop.sh
- .ssh/desktop_connection.conf (created by script)

---

## 🎯 Quick Start Commands

### On Desktop (Now)

```bash
# Navigate to development folder
cd C:\Users\Corbin\development

# View deployment status
cat DEPLOYMENT_COMPLETE.md

# When phone is ready, test connection
ssh -p 8022 USERNAME@samsung-sm-f966u

# Run monitor
python fold7_ssh_monitor.py
```

### On Phone (After Setup)

```bash
# In Termux:
cd ~

# Get username for desktop config
whoami

# Run setup
./setup_termux_ssh_server.sh

# Configure desktop connection
./termux_ssh_to_desktop.sh --create-config
nano ~/.ssh/desktop_connection.conf

# Test connections
./termux_ssh_to_desktop.sh --test
```

---

## 🔐 SSH Key Setup (Recommended)

### Desktop → Phone

**Generate key on desktop:**
```bash
ssh-keygen -t ed25519 -f ~/.ssh/fold7_key -C "desktop-to-fold7"
```

**Copy to phone:**
```bash
ssh-copy-id -i ~/.ssh/fold7_key.pub -p 8022 USERNAME@samsung-sm-f966u
```

### Phone → Desktop

**Generate key on phone (in Termux):**
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "fold7-to-desktop"
cat ~/.ssh/id_ed25519.pub
```

**Add to desktop authorized_keys:**
```powershell
# On desktop in PowerShell:
cd ~\.ssh
# Edit authorized_keys and paste the public key from phone
notepad authorized_keys
```

---

## 📞 Next Actions

### Immediate (You Need To Do)

1. **Transfer scripts** from `C:\Users\Corbin\Downloads\` to phone
2. **Install Termux** from GitHub on phone
3. **Run setup script** on phone
4. **Get username** from `whoami` in Termux
5. **Update** `fold7_config.json` with actual username
6. **Configure battery** settings on phone

### After Phone Setup

1. **Test SSH** from desktop to phone
2. **Run monitor** on desktop: `python fold7_ssh_monitor.py`
3. **Configure** phone→desktop SSH
4. **Test both** directions
5. **Setup auto-start** for persistence

---

## 📚 Documentation References

- **Complete setup:** `FOLD7_README.md`
- **Termux guide:** `FOLD7_SSH_SETUP.md`
- **Phone→Desktop:** `TERMUX_DESKTOP_SSH.md`
- **App identification:** `IDENTIFY_YOUR_SSH_APP.md`

---

## ✅ Deployment Checklist

### Desktop Preparation
- [x] Python 3.13.5 installed
- [x] OpenSSH Server running
- [x] Tailscale connected
- [x] Configuration file updated
- [x] Scripts ready
- [x] Files in Downloads for transfer

### Phone Setup
- [ ] Termux installed from GitHub
- [ ] Initial packages installed
- [ ] Scripts transferred to phone
- [ ] Setup script executed
- [ ] Username added to desktop config
- [ ] Battery optimization disabled
- [ ] Tailscale Always-On VPN enabled
- [ ] SSH connection tested
- [ ] Auto-start configured

### Testing
- [ ] Desktop → Phone SSH works
- [ ] fold7_ssh_monitor.py runs successfully
- [ ] Phone → Desktop SSH works
- [ ] termux_ssh_to_desktop.sh runs successfully
- [ ] Auto-reconnection tested
- [ ] Battery optimization verified

---

**Status:** Desktop side COMPLETE. Phone side requires manual deployment.

**Next Step:** Transfer scripts to phone and follow phone deployment steps above.

---

Last updated: 2025-09-30 21:16