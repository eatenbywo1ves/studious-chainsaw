#!/data/data/com.termux/files/usr/bin/bash
#
# Enhanced Setup Script for Auto-Starting SSH Server in Termux on Samsung Fold 7
# Features: Auto-start SSH, Tailscale integration, health monitoring, wake lock
# Version: 2.0
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Termux SSH Auto-Start Setup (Enhanced)"
echo "Samsung Fold 7 Configuration v2.0"
echo "=========================================="
echo

# Check if running in Termux
if [ ! -d "$HOME/../usr" ]; then
    echo -e "${RED}ERROR: This script must be run inside Termux!${NC}"
    exit 1
fi

# Function to print status
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Update packages
print_status "[1/8] Updating packages..."
pkg update -y || print_warning "Package update had issues, continuing..."

# Install required packages
print_status "[2/8] Installing required packages..."
PACKAGES="openssh termux-api termux-boot termux-services curl jq"

# Check for Tailscale
if command -v tailscale &> /dev/null; then
    print_success "Tailscale already installed"
else
    print_status "Installing Tailscale..."
    PACKAGES="$PACKAGES tailscale"
fi

pkg install -y $PACKAGES

# Configure SSH
print_status "[3/8] Configuring SSH server..."

# Create .ssh directory if it doesn't exist
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Generate host keys if they don't exist
if [ ! -f "$PREFIX/etc/ssh/ssh_host_rsa_key" ]; then
    print_status "Generating SSH host keys..."
    ssh-keygen -A
fi

# Configure sshd_config for better security
SSHD_CONFIG="$PREFIX/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    print_status "Securing SSH configuration..."

    # Backup original config
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"

    # Apply security hardening
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"

    # Add if not present
    grep -q "^Port 8022" "$SSHD_CONFIG" || echo "Port 8022" >> "$SSHD_CONFIG"
    grep -q "^PrintMotd yes" "$SSHD_CONFIG" || echo "PrintMotd yes" >> "$SSHD_CONFIG"
fi

# Set password if not already configured
if [ ! -f ~/.ssh/authorized_keys ]; then
    echo
    print_warning "IMPORTANT: You need to either:"
    echo "  1. Set a password with 'passwd' command"
    echo "  2. Add SSH public keys to ~/.ssh/authorized_keys"
    echo
    read -p "Do you want to set a password now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        passwd
    fi
fi

# Configure Tailscale
print_status "[4/8] Configuring Tailscale..."

if command -v tailscale &> /dev/null; then
    if tailscale status &> /dev/null; then
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "Not connected")
        TAILSCALE_HOSTNAME=$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // "unknown"' | sed 's/\.$//')

        if [ "$TAILSCALE_IP" != "Not connected" ]; then
            print_success "Tailscale is connected"
            echo "  IP: $TAILSCALE_IP"
            echo "  Hostname: $TAILSCALE_HOSTNAME"
        else
            print_warning "Tailscale is installed but not connected"
            echo "  Run: tailscale up"
        fi
    else
        print_warning "Tailscale daemon not running"
        echo "  Start with: sv-enable tailscaled && sv up tailscaled"
    fi
else
    print_warning "Tailscale not installed (optional)"
fi

# Create boot script directory
print_status "[5/8] Setting up boot scripts..."
mkdir -p ~/.termux/boot

# Create enhanced boot startup script
cat > ~/.termux/boot/start-services << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

LOG_FILE=~/services-boot.log
echo "========================================" >> $LOG_FILE
echo "[$(date)] Boot sequence started" >> $LOG_FILE

# Acquire wake lock to prevent deep sleep
termux-wake-lock
echo "[$(date)] Wake lock acquired" >> $LOG_FILE

# Wait for network
echo "[$(date)] Waiting for network..." >> $LOG_FILE
for i in {1..30}; do
    if ping -c 1 8.8.8.8 &> /dev/null; then
        echo "[$(date)] Network is up" >> $LOG_FILE
        break
    fi
    sleep 1
done

# Start Tailscale if installed
if command -v tailscale &> /dev/null; then
    echo "[$(date)] Starting Tailscale..." >> $LOG_FILE
    sv-enable tailscaled 2>> $LOG_FILE
    sv up tailscaled 2>> $LOG_FILE
    sleep 3

    # Auto-connect if not connected
    if ! tailscale status &> /dev/null; then
        echo "[$(date)] Connecting to Tailscale..." >> $LOG_FILE
        tailscale up 2>> $LOG_FILE
    fi
fi

# Start SSH daemon
echo "[$(date)] Starting SSH server..." >> $LOG_FILE
sshd
if pgrep -x sshd > /dev/null; then
    echo "[$(date)] SSH server started successfully" >> $LOG_FILE
else
    echo "[$(date)] ERROR: SSH server failed to start" >> $LOG_FILE
fi

# Log system info
echo "[$(date)] System ready" >> $LOG_FILE
echo "  IP: $(hostname -I)" >> $LOG_FILE
if command -v tailscale &> /dev/null; then
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "Not connected")
    echo "  Tailscale IP: $TAILSCALE_IP" >> $LOG_FILE
fi
echo "========================================" >> $LOG_FILE
EOF

chmod +x ~/.termux/boot/start-services

# Create health check script
print_status "[6/8] Creating health monitoring script..."

cat > ~/check-ssh-health.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

# SSH Health Check Script
# Monitors SSH daemon and automatically restarts if down

LOG_FILE=~/ssh-health.log

check_and_restart() {
    if ! pgrep -x sshd > /dev/null; then
        echo "[$(date)] SSH daemon is DOWN - restarting" >> $LOG_FILE

        # Ensure wake lock is active
        termux-wake-lock

        # Start SSH
        sshd

        if pgrep -x sshd > /dev/null; then
            echo "[$(date)] SSH daemon restarted successfully" >> $LOG_FILE

            # Send notification if termux-api is available
            if command -v termux-notification &> /dev/null; then
                termux-notification --title "SSH Restored" --content "SSH daemon was down and has been restarted"
            fi
        else
            echo "[$(date)] ERROR: Failed to restart SSH daemon" >> $LOG_FILE

            if command -v termux-notification &> /dev/null; then
                termux-notification --title "SSH Error" --content "Failed to restart SSH daemon" --priority high
            fi
        fi
    fi
}

check_and_restart
EOF

chmod +x ~/check-ssh-health.sh

# Create cron-like health check using termux-job-scheduler (if available)
if command -v termux-job-scheduler &> /dev/null; then
    print_status "Setting up automatic health checks (every 5 minutes)..."

    # Schedule health check
    termux-job-scheduler --script ~/check-ssh-health.sh --period-ms 300000 --persisted true 2>/dev/null || \
        print_warning "Could not schedule automatic health checks"
fi

# Create .bashrc for manual Termux launches
print_status "[7/8] Configuring auto-start on Termux launch..."

# Backup existing .bashrc if it exists
if [ -f ~/.bashrc ]; then
    cp ~/.bashrc ~/.bashrc.backup.$(date +%Y%m%d_%H%M%S)
fi

# Add enhanced SSH auto-start to .bashrc
cat >> ~/.bashrc << 'EOF'

# ============================================
# Auto-start SSH server and services
# ============================================

start_services() {
    local services_started=false

    # Start SSH if not running
    if ! pgrep -x sshd > /dev/null; then
        echo "Starting SSH server..."
        termux-wake-lock
        sshd
        services_started=true

        if pgrep -x sshd > /dev/null; then
            echo "✓ SSH server started (port 8022)"
        else
            echo "✗ SSH server failed to start"
        fi
    fi

    # Start Tailscale if installed and not running
    if command -v tailscale &> /dev/null; then
        if ! tailscale status &> /dev/null 2>&1; then
            echo "Starting Tailscale..."
            sv-enable tailscaled 2>/dev/null
            sv up tailscaled 2>/dev/null
            sleep 2
            services_started=true
        fi

        # Show Tailscale status
        if tailscale status &> /dev/null 2>&1; then
            TAILSCALE_IP=$(tailscale ip -4 2>/dev/null)
            if [ -n "$TAILSCALE_IP" ]; then
                echo "✓ Tailscale connected: $TAILSCALE_IP"
            fi
        fi
    fi

    # Show wake lock status
    if [ -f "$PREFIX/var/run/termux-wake-lock.pid" ]; then
        $services_started && echo "✓ Wake lock active"
    else
        echo "⚠ Wake lock not active - run: termux-wake-lock"
    fi

    $services_started && echo "To release wake lock: termux-wake-unlock"
}

# Auto-start services
start_services

# Helpful aliases
alias ssh-status='pgrep -x sshd > /dev/null && echo "SSH: Running" || echo "SSH: Stopped"'
alias ssh-restart='pkill sshd; sshd; echo "SSH restarted"'
alias ts-status='tailscale status 2>/dev/null || echo "Tailscale not running"'
alias ts-ip='tailscale ip -4 2>/dev/null || echo "Not connected"'
alias check-services='ssh-status; ts-status'
EOF

# Create quick status script
cat > ~/status.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

echo "=========================================="
echo "Termux Services Status"
echo "=========================================="
echo

# SSH Status
if pgrep -x sshd > /dev/null; then
    echo "✓ SSH Server: RUNNING (port 8022)"
    echo "  Username: $(whoami)"
else
    echo "✗ SSH Server: STOPPED"
fi
echo

# Tailscale Status
if command -v tailscale &> /dev/null; then
    if tailscale status &> /dev/null 2>&1; then
        TS_IP=$(tailscale ip -4 2>/dev/null)
        TS_HOSTNAME=$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // "unknown"' | sed 's/\.$//')
        echo "✓ Tailscale: CONNECTED"
        echo "  IP: $TS_IP"
        echo "  Hostname: $TS_HOSTNAME"
        echo "  Connect: ssh -p 8022 $(whoami)@$TS_HOSTNAME"
    else
        echo "✗ Tailscale: DISCONNECTED"
        echo "  Start: sv-enable tailscaled && sv up tailscaled"
    fi
else
    echo "⚠ Tailscale: NOT INSTALLED"
fi
echo

# Wake Lock Status
if [ -f "$PREFIX/var/run/termux-wake-lock.pid" ]; then
    echo "✓ Wake Lock: ACTIVE"
else
    echo "⚠ Wake Lock: INACTIVE"
    echo "  Activate: termux-wake-lock"
fi
echo

# Network Status
echo "Network Interfaces:"
ip addr show | grep 'inet ' | awk '{print "  " $NF ": " $2}'
echo

echo "=========================================="
EOF

chmod +x ~/status.sh

# Create connection test script
cat > ~/test-ssh.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

echo "Testing SSH connectivity..."
echo

# Test local SSH
if nc -z localhost 8022 2>/dev/null; then
    echo "✓ SSH port 8022 is open locally"
else
    echo "✗ SSH port 8022 is not accessible"
    exit 1
fi

# Test Tailscale connection
if command -v tailscale &> /dev/null; then
    TS_IP=$(tailscale ip -4 2>/dev/null)
    if [ -n "$TS_IP" ]; then
        echo "✓ Tailscale IP: $TS_IP"
        echo
        echo "Test from remote machine:"
        echo "  ssh -p 8022 $(whoami)@$TS_IP"
    fi
fi
EOF

chmod +x ~/test-ssh.sh

# Show configuration summary
print_status "[8/8] Configuration complete!"
echo
echo "=========================================="
echo "Configuration Summary"
echo "=========================================="
echo

# SSH Info
echo "SSH Configuration:"
echo "  Port: 8022 (Termux default)"
echo "  Username: $(whoami)"
echo "  Device hostname: $(hostname)"
echo

# Tailscale Info
if command -v tailscale &> /dev/null; then
    if tailscale status &> /dev/null 2>&1; then
        TS_IP=$(tailscale ip -4 2>/dev/null)
        TS_HOSTNAME=$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // "unknown"' | sed 's/\.$//')
        echo "Tailscale Configuration:"
        echo "  IP: $TS_IP"
        echo "  Hostname: $TS_HOSTNAME"
        echo "  SSH Command: ssh -p 8022 $(whoami)@$TS_HOSTNAME"
    else
        echo "Tailscale: Not connected yet"
        echo "  Connect: tailscale up"
    fi
else
    echo "Tailscale: Not installed"
fi
echo

echo "=========================================="
echo "Quick Commands"
echo "=========================================="
echo
echo "~/status.sh           - Show all service status"
echo "~/test-ssh.sh         - Test SSH connectivity"
echo "~/check-ssh-health.sh - Manual health check"
echo
echo "Aliases added to .bashrc:"
echo "  ssh-status    - Check SSH status"
echo "  ssh-restart   - Restart SSH server"
echo "  ts-status     - Check Tailscale status"
echo "  ts-ip         - Show Tailscale IP"
echo "  check-services - Check all services"
echo

echo "=========================================="
echo "Next Steps"
echo "=========================================="
echo
echo "1. CONFIGURE BATTERY SETTINGS:"
echo "   Settings → Apps → Termux → Battery"
echo "   - Set: Unrestricted"
echo "   - Enable: Allow background activity"
echo
echo "2. ADD TO NEVER SLEEPING APPS:"
echo "   Settings → Device Care → Battery → 3-dot menu"
echo "   - Add Termux to 'Never sleeping apps'"
echo
echo "3. DISABLE AGGRESSIVE POWER SAVING:"
echo "   Device Care → Battery → Settings"
echo "   - Disable: 'Put unused apps to sleep'"
echo "   - Disable: 'Auto-disable unused apps'"
echo
echo "4. SETUP SSH KEY (Recommended):"
echo "   From your PC:"
if command -v tailscale &> /dev/null && tailscale status &> /dev/null 2>&1; then
    TS_HOSTNAME=$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // "unknown"' | sed 's/\.$//')
    echo "   ssh-copy-id -p 8022 $(whoami)@$TS_HOSTNAME"
else
    echo "   ssh-copy-id -p 8022 $(whoami)@<tailscale-hostname>"
fi
echo
echo "5. TEST CONNECTION:"
echo "   From PC: ssh -p 8022 $(whoami)@<tailscale-hostname>"
echo
echo "6. REBOOT YOUR PHONE:"
echo "   SSH should auto-start on boot"
echo "   Check log: cat ~/services-boot.log"
echo

echo "=========================================="
echo "Current Status"
echo "=========================================="
echo

# SSH Status
if pgrep -x sshd > /dev/null; then
    print_success "SSH server is RUNNING"
else
    print_warning "SSH server is NOT running"
    echo "  Starting now..."
    termux-wake-lock
    sshd
    if pgrep -x sshd > /dev/null; then
        print_success "Started"
    else
        print_error "Failed to start"
    fi
fi

# Wake Lock Status
if [ -f "$PREFIX/var/run/termux-wake-lock.pid" ]; then
    print_success "Wake lock is ACTIVE"
else
    print_warning "Wake lock is NOT active"
    echo "  Activating..."
    termux-wake-lock
    print_success "Wake lock activated"
fi

# Tailscale Status
if command -v tailscale &> /dev/null; then
    if tailscale status &> /dev/null 2>&1; then
        print_success "Tailscale is CONNECTED"
    else
        print_warning "Tailscale is installed but not connected"
        echo "  Run: tailscale up"
    fi
fi

echo
echo "=========================================="
print_success "Setup complete! SSH configured with enhanced monitoring."
echo "Run: ~/status.sh to check all services"
echo "=========================================="
