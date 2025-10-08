# WSL2 DNS Fix - Step-by-Step Guide

**Issue:** WSL2 cannot resolve DNS (ping fails with "Temporary failure in name resolution")
**Solution:** Manually configure DNS servers
**Time Required:** 5 minutes

---

## 🔧 Method 1: Quick DNS Fix (Recommended)

### Step 1: Open Ubuntu WSL2 Terminal

```powershell
# In Windows Terminal or PowerShell
wsl -d Ubuntu
```

### Step 2: Fix DNS Configuration

```bash
# Remove existing resolv.conf
sudo rm /etc/resolv.conf

# Add Google DNS servers
sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
sudo bash -c 'echo "nameserver 8.8.4.4" >> /etc/resolv.conf'

# Prevent WSL from overwriting (optional but recommended)
sudo chattr +i /etc/resolv.conf
```

### Step 3: Verify DNS Works

```bash
# Test DNS resolution
ping -c 3 google.com

# You should see:
# PING google.com (142.250.x.x) ...
# 64 bytes from ...
```

### Step 4: Re-run Checkpoint Installation

```bash
cd /mnt/c/Users/Corbin/development/security/wiz-challenge
./checkpoint-install.sh
```

**Expected Result:** Installation should now proceed past checkpoint 2!

---

## 🔧 Method 2: WSL Configuration File (Permanent Fix)

If Method 1 doesn't persist after reboot, use this approach:

### Step 1: Create WSL Config File

In Windows, create or edit: `C:\Users\Corbin\.wslconfig`

```ini
[wsl2]
# Use mirrored networking (Windows 11)
networkingMode=mirrored
dnsTunneling=true
firewall=true
autoProxy=true

# Alternative: Specific DNS
# dns=8.8.8.8
```

### Step 2: Restart WSL

```powershell
# In PowerShell (as Administrator if possible)
wsl --shutdown

# Wait 5 seconds, then restart
wsl -d Ubuntu
```

### Step 3: Test and Verify

```bash
ping google.com
```

---

## 🔧 Method 3: Disable Auto-Generate resolv.conf

Make WSL stop overwriting your DNS settings:

### Step 1: Edit WSL Configuration

```bash
wsl -d Ubuntu

# Edit wsl.conf
sudo nano /etc/wsl.conf
```

### Step 2: Add This Content

```ini
[network]
generateResolvConf = false
```

Save (Ctrl+O, Enter) and exit (Ctrl+X)

### Step 3: Restart WSL

```powershell
# In PowerShell
wsl --shutdown
wsl -d Ubuntu
```

### Step 4: Manually Set DNS Again

```bash
sudo rm /etc/resolv.conf
sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
sudo bash -c 'echo "nameserver 8.8.4.4" >> /etc/resolv.conf'
sudo chattr +i /etc/resolv.conf
```

---

## 🔧 Method 4: Use Your Router's DNS

If Google DNS doesn't work (firewall/proxy):

```bash
# Find your router's DNS (usually 192.168.1.1)
# In PowerShell:
# ipconfig /all | findstr "DNS"

sudo rm /etc/resolv.conf
sudo bash -c 'echo "nameserver 192.168.1.1" > /etc/resolv.conf'
sudo bash -c 'echo "nameserver 8.8.8.8" >> /etc/resolv.conf'
```

---

## ✅ Verification Checklist

After applying fix, verify everything works:

```bash
# Test 1: DNS resolution
ping -c 3 google.com
# Should succeed

# Test 2: HTTPS access
curl -I https://google.com
# Should get HTTP response

# Test 3: Package manager
sudo apt update
# Should connect successfully

# Test 4: Docker installation (if checkpoint failed here)
curl -fsSL https://get.docker.com -o get-docker.sh
# Should download successfully
```

---

## 🚀 After DNS is Fixed

### Option A: Re-run Checkpoint Installation (Recommended)

```bash
cd /mnt/c/Users/Corbin/development/security/wiz-challenge
./checkpoint-install.sh
```

The checkpoint system will:
- ✅ Skip checkpoints 1-2 (already done)
- ✅ Continue from checkpoint 3
- ✅ Complete all remaining steps automatically

### Option B: Continue Manually from QUICK_START_GUIDE.md

If you prefer step-by-step control:

```bash
cd /mnt/c/Users/Corbin/development/security/wiz-challenge
cat QUICK_START_GUIDE.md
# Follow the manual installation steps
```

---

## 🐛 Troubleshooting

### Issue: "chattr: Operation not supported"

WSL2 filesystem might not support chattr. That's okay - just skip that command:

```bash
# Skip this line if it fails:
# sudo chattr +i /etc/resolv.conf

# DNS will still work, might just reset on reboot
# Use Method 2 (.wslconfig) for permanent fix
```

### Issue: Still Can't Resolve DNS

Try alternative DNS servers:

```bash
# Cloudflare DNS
sudo bash -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf'
sudo bash -c 'echo "nameserver 1.0.0.1" >> /etc/resolv.conf'

# Or Quad9 DNS
sudo bash -c 'echo "nameserver 9.9.9.9" > /etc/resolv.conf'
sudo bash -c 'echo "nameserver 149.112.112.112" >> /etc/resolv.conf'
```

### Issue: Permission Denied

Make sure you're using sudo:

```bash
# All resolv.conf operations need sudo
sudo rm /etc/resolv.conf
sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
```

### Issue: WSL Won't Start After Config Change

```powershell
# Reset WSL (in PowerShell)
wsl --shutdown
wsl --unregister Ubuntu  # WARNING: This deletes the distro!

# Or just remove the config:
# Delete C:\Users\Corbin\.wslconfig
# Then: wsl --shutdown
```

---

## 📊 Expected Timeline After Fix

**Once DNS is working:**

```
✅ Checkpoint 2: Internet - PASS (now works!)
⏳ Checkpoint 3: Sudo access - 10 seconds
⏳ Checkpoint 4-5: Docker install - 2-3 minutes
⏳ Checkpoint 6-7: NVIDIA toolkit - 3-5 minutes
⏳ Checkpoint 8: GPU test - 30 seconds
⏳ Checkpoint 9-10: Falco - 2-3 minutes
⏳ Checkpoint 11-13: Security tools - 2-3 minutes
⏳ Checkpoint 14: Baseline - 30 seconds

Total: 10-15 minutes to complete
```

---

## 🎯 Quick Copy-Paste Commands

**For fastest fix, copy and paste these exactly:**

```bash
# Open WSL
wsl -d Ubuntu

# Fix DNS (paste all at once)
sudo rm -f /etc/resolv.conf
sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
sudo bash -c 'echo "nameserver 8.8.4.4" >> /etc/resolv.conf'

# Test it works
ping -c 3 google.com

# If ping works, re-run installation
cd /mnt/c/Users/Corbin/development/security/wiz-challenge
./checkpoint-install.sh
```

---

## 💡 Why This Happens

WSL2 uses a virtualized network adapter that sometimes doesn't properly inherit DNS settings from Windows. This is a known issue with several solutions. The fix is simple and works for most users.

---

## ✅ Success Indicators

You'll know it's fixed when:

1. ✅ `ping google.com` works
2. ✅ `sudo apt update` works
3. ✅ `curl https://google.com` works
4. ✅ Checkpoint installation proceeds past step 2

---

**After fixing DNS, the automated installation should complete smoothly!**

Let me know once DNS is working and I'll monitor the checkpoint installation progress.
