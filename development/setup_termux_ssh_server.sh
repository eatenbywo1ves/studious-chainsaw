#!/data/data/com.termux/files/usr/bin/bash
#
# Setup script for auto-starting SSH server in Termux on Samsung Fold 7
# This script configures Termux to automatically start SSH with wake lock
# when the device boots or when Termux is launched.
#

echo "=========================================="
echo "Termux SSH Auto-Start Setup"
echo "Samsung Fold 7 Configuration"
echo "=========================================="
echo

# Check if running in Termux
if [ ! -d "$HOME/../usr" ]; then
    echo "ERROR: This script must be run inside Termux!"
    exit 1
fi

# Update packages
echo "[1/6] Updating packages..."
pkg update -y

# Install required packages
echo "[2/6] Installing required packages..."
pkg install -y openssh termux-api termux-boot termux-services

# Configure SSH
echo "[3/6] Configuring SSH server..."

# Create .ssh directory if it doesn't exist
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Set password if not already set
if [ ! -f ~/.ssh/authorized_keys ]; then
    echo
    echo "IMPORTANT: You need to either:"
    echo "  1. Set a password with 'passwd' command"
    echo "  2. Add SSH public keys to ~/.ssh/authorized_keys"
    echo
    read -p "Do you want to set a password now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        passwd
    fi
fi

# Create boot script directory
echo "[4/6] Setting up boot script..."
mkdir -p ~/.termux/boot

# Create boot startup script
cat > ~/.termux/boot/start-sshd << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

# Acquire wake lock to prevent deep sleep
termux-wake-lock

# Wait a bit for network
sleep 5

# Start SSH daemon
sshd

# Log startup
echo "[$(date)] SSH server started on boot" >> ~/sshd-boot.log
EOF

chmod +x ~/.termux/boot/start-sshd

# Create .bashrc for manual Termux launches
echo "[5/6] Configuring auto-start on Termux launch..."

# Backup existing .bashrc if it exists
if [ -f ~/.bashrc ]; then
    cp ~/.bashrc ~/.bashrc.backup.$(date +%Y%m%d_%H%M%S)
fi

# Add SSH auto-start to .bashrc
cat >> ~/.bashrc << 'EOF'

# Auto-start SSH server if not already running
if ! pgrep -x sshd > /dev/null; then
    echo "Starting SSH server..."
    termux-wake-lock
    sshd
    echo "SSH server started. Wake lock acquired."
    echo "To release wake lock: termux-wake-unlock"
fi
EOF

# Show current configuration
echo "[6/6] Configuration complete!"
echo
echo "=========================================="
echo "Configuration Summary"
echo "=========================================="
echo
echo "SSH Port: 8022 (default Termux)"
echo "Your username: $(whoami)"
echo "Device hostname in Termux: $(hostname)"
echo
echo "To get your Tailscale hostname, run:"
echo "  tailscale ip -4"
echo
echo "=========================================="
echo "Next Steps"
echo "=========================================="
echo
echo "1. CONFIGURE BATTERY SETTINGS:"
echo "   - Go to: Settings → Apps → Termux → Battery"
echo "   - Set to: Unrestricted"
echo "   - Enable: Allow background activity"
echo
echo "2. ADD TO NEVER SLEEPING APPS:"
echo "   - Go to: Settings → Device Care → Battery"
echo "   - Tap: 3-dot menu → Settings"
echo "   - Add Termux to 'Never sleeping apps'"
echo
echo "3. DISABLE AGGRESSIVE POWER SAVING:"
echo "   - In Device Care → Battery → Settings"
echo "   - Disable: 'Put unused apps to sleep'"
echo "   - Disable: 'Auto-disable unused apps'"
echo
echo "4. SETUP SSH KEY (Recommended):"
echo "   - On your PC, copy public key to phone:"
echo "   - ssh-copy-id -p 8022 $(whoami)@<tailscale-hostname>"
echo
echo "5. TEST SSH CONNECTION:"
echo "   - From PC: ssh -p 8022 $(whoami)@<tailscale-hostname>"
echo
echo "6. REBOOT YOUR PHONE:"
echo "   - SSH should auto-start on boot"
echo "   - Check log: cat ~/sshd-boot.log"
echo
echo "=========================================="
echo
echo "Current SSH server status:"
if pgrep -x sshd > /dev/null; then
    echo "✓ SSH server is RUNNING"
else
    echo "✗ SSH server is NOT running"
    echo "  Starting now..."
    termux-wake-lock
    sshd
    echo "✓ Started"
fi
echo
echo "Wake lock status:"
if [ -f "$PREFIX/var/run/termux-wake-lock.pid" ]; then
    echo "✓ Wake lock is ACTIVE"
else
    echo "✗ Wake lock is NOT active"
    echo "  Run: termux-wake-lock"
fi
echo
echo "Setup complete! SSH should now auto-start."
echo "=========================================="