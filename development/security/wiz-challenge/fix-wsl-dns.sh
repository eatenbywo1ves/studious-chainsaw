#!/bin/bash
set -e

echo "=== WSL2 DNS Fix Script ==="
echo ""

# Step 1: Create/update wsl.conf to disable auto-generation
echo "Step 1: Disabling WSL auto-generation of resolv.conf..."
sudo bash -c 'cat > /etc/wsl.conf << EOF
[boot]
systemd=true

[network]
generateResolvConf = false
EOF'

echo "Created /etc/wsl.conf:"
cat /etc/wsl.conf
echo ""

# Step 2: Remove old resolv.conf and create new one
echo "Step 2: Creating new resolv.conf with Google DNS..."
sudo rm -f /etc/resolv.conf
sudo bash -c 'cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF'

echo "Created /etc/resolv.conf:"
cat /etc/resolv.conf
echo ""

# Step 3: Test DNS resolution
echo "Step 3: Testing DNS resolution..."
echo "Attempting to ping google.com..."
if ping -c 3 google.com; then
    echo ""
    echo "SUCCESS: DNS is working!"
    echo ""
    echo "IMPORTANT: WSL needs to be restarted for wsl.conf changes to take effect."
    echo "After this script completes, exit WSL and run: wsl --shutdown"
    echo "Then restart WSL and run the checkpoint installation."
    exit 0
else
    echo ""
    echo "WARNING: DNS test failed, but configuration is in place."
    echo "Please restart WSL with: wsl --shutdown"
    echo "Then test again."
    exit 1
fi
