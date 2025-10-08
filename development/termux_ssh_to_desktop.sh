#!/data/data/com.termux/files/usr/bin/bash
#
# Termux SSH Auto-Connect Script
# Maintains persistent SSH connection from Samsung Fold 7 to Desktop PC via Tailscale
#
# Usage: ./termux_ssh_to_desktop.sh [config_file]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration file
CONFIG_FILE="${1:-$HOME/.ssh/desktop_connection.conf}"

# Function to print colored messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to create default config
create_default_config() {
    log_info "Creating default configuration file at $CONFIG_FILE"

    mkdir -p "$(dirname "$CONFIG_FILE")"

    cat > "$CONFIG_FILE" << 'EOF'
# Desktop SSH Connection Configuration
# Edit this file with your desktop details

# Desktop Tailscale hostname or IP
DESKTOP_HOST="your-desktop-hostname.tailnet.ts.net"

# SSH port on desktop (usually 22)
DESKTOP_PORT="22"

# Username on desktop
DESKTOP_USER="Corbin"

# SSH key to use (optional, leave empty for password auth)
SSH_KEY="$HOME/.ssh/id_ed25519"

# Connection check interval (seconds)
CHECK_INTERVAL=30

# Connection timeout (seconds)
CONNECTION_TIMEOUT=10

# Max retry attempts before backing off
MAX_RETRIES=5

# Enable auto-reconnect
AUTO_RECONNECT=true

# Keep-alive interval (seconds)
KEEPALIVE_INTERVAL=60

# Log file location
LOG_FILE="$HOME/ssh_desktop_monitor.log"

# Enable verbose logging
VERBOSE=false

# Command to run on desktop after connecting (optional)
# Examples: "tmux attach" or "screen -r" or empty for normal shell
REMOTE_COMMAND=""

# Enable wake lock (prevents phone sleep)
USE_WAKELOCK=true

# Send notification on connection events (requires termux-api)
SEND_NOTIFICATIONS=true
EOF

    log_success "Configuration file created"
    log_warning "Please edit $CONFIG_FILE with your desktop details"
    echo
    echo "Required changes:"
    echo "  - DESKTOP_HOST: Your desktop's Tailscale hostname"
    echo "  - DESKTOP_USER: Your username on desktop"
    echo "  - SSH_KEY: Path to your SSH key (or leave empty for password)"
    echo
    exit 0
}

# Load configuration
load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        create_default_config
    fi

    # shellcheck source=/dev/null
    source "$CONFIG_FILE"

    # Validate required settings
    if [ "$DESKTOP_HOST" = "your-desktop-hostname.tailnet.ts.net" ]; then
        log_error "Please configure DESKTOP_HOST in $CONFIG_FILE"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()

    # Check for SSH
    if ! command -v ssh &> /dev/null; then
        missing_deps+=("openssh")
    fi

    # Check for termux-api if notifications enabled
    if [ "$SEND_NOTIFICATIONS" = "true" ] && ! command -v termux-notification &> /dev/null; then
        log_warning "termux-api not installed, notifications disabled"
        SEND_NOTIFICATIONS=false
    fi

    # Install missing dependencies
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_info "Installing missing dependencies: ${missing_deps[*]}"
        pkg install -y "${missing_deps[@]}"
    fi
}

# Acquire wake lock
acquire_wakelock() {
    if [ "$USE_WAKELOCK" = "true" ]; then
        if command -v termux-wake-lock &> /dev/null; then
            termux-wake-lock
            log_info "Wake lock acquired (prevents phone sleep)"
        else
            log_warning "termux-api not installed, wake lock unavailable"
        fi
    fi
}

# Release wake lock
release_wakelock() {
    if command -v termux-wake-unlock &> /dev/null; then
        termux-wake-unlock
        log_info "Wake lock released"
    fi
}

# Send notification
send_notification() {
    local title="$1"
    local content="$2"

    if [ "$SEND_NOTIFICATIONS" = "true" ]; then
        termux-notification --title "$title" --content "$content" --priority high
    fi
}

# Log message to file
log_to_file() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_FILE"
}

# Check if desktop is reachable
check_desktop_reachable() {
    if [ "$VERBOSE" = "true" ]; then
        log_info "Checking if desktop is reachable..."
    fi

    # Try to resolve hostname
    if ! getent hosts "$DESKTOP_HOST" &> /dev/null; then
        if [ "$VERBOSE" = "true" ]; then
            log_warning "Cannot resolve hostname: $DESKTOP_HOST"
        fi
        return 1
    fi

    return 0
}

# Test SSH connection
test_ssh_connection() {
    local ssh_opts=(
        "-o" "ConnectTimeout=$CONNECTION_TIMEOUT"
        "-o" "BatchMode=yes"
        "-o" "StrictHostKeyChecking=no"
        "-p" "$DESKTOP_PORT"
    )

    # Add SSH key if specified
    if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
        ssh_opts+=("-i" "$SSH_KEY")
    fi

    # Test connection with simple command
    if ssh "${ssh_opts[@]}" "${DESKTOP_USER}@${DESKTOP_HOST}" "echo connected" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Connect to desktop
connect_to_desktop() {
    local ssh_opts=(
        "-o" "ServerAliveInterval=$KEEPALIVE_INTERVAL"
        "-o" "ServerAliveCountMax=3"
        "-o" "StrictHostKeyChecking=no"
        "-p" "$DESKTOP_PORT"
    )

    # Add SSH key if specified
    if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
        ssh_opts+=("-i" "$SSH_KEY")
    fi

    log_info "Connecting to ${DESKTOP_USER}@${DESKTOP_HOST}:${DESKTOP_PORT}..."
    log_to_file "Attempting connection to desktop"

    # Build SSH command
    local ssh_cmd="ssh ${ssh_opts[*]} ${DESKTOP_USER}@${DESKTOP_HOST}"

    # Add remote command if specified
    if [ -n "$REMOTE_COMMAND" ]; then
        ssh_cmd="$ssh_cmd $REMOTE_COMMAND"
    fi

    # Execute SSH connection
    eval "$ssh_cmd"

    local exit_code=$?
    log_to_file "SSH connection exited with code: $exit_code"

    return $exit_code
}

# Monitor and auto-reconnect loop
monitor_connection() {
    local retry_count=0
    local last_success=$(date +%s)
    local total_reconnects=0

    log_info "Starting SSH connection monitor"
    log_info "Target: ${DESKTOP_USER}@${DESKTOP_HOST}:${DESKTOP_PORT}"
    log_info "Check interval: ${CHECK_INTERVAL}s"
    log_info "Auto-reconnect: $AUTO_RECONNECT"
    echo

    acquire_wakelock

    while true; do
        # Check if desktop is reachable
        if ! check_desktop_reachable; then
            log_warning "Desktop not reachable via Tailscale"
            log_to_file "Desktop unreachable"

            if [ "$AUTO_RECONNECT" = "true" ]; then
                retry_count=$((retry_count + 1))

                if [ $retry_count -ge $MAX_RETRIES ]; then
                    local backoff=$((CHECK_INTERVAL * retry_count))
                    [ $backoff -gt 300 ] && backoff=300  # Max 5 minutes

                    log_warning "Max retries reached, waiting ${backoff}s before retry..."
                    send_notification "SSH Monitor" "Desktop unreachable, retrying in ${backoff}s"
                    sleep "$backoff"
                    retry_count=0
                else
                    log_info "Retry $retry_count/$MAX_RETRIES in ${CHECK_INTERVAL}s..."
                    sleep "$CHECK_INTERVAL"
                fi
                continue
            else
                log_error "Desktop unreachable, auto-reconnect disabled"
                break
            fi
        fi

        # Test SSH connection
        if test_ssh_connection; then
            log_success "SSH connection test successful"
            retry_count=0

            # Calculate uptime
            local now=$(date +%s)
            local uptime=$((now - last_success))

            if [ $uptime -gt $CHECK_INTERVAL ]; then
                log_success "Connection recovered after ${uptime}s downtime"
                send_notification "SSH Connected" "Desktop connection restored"
                total_reconnects=$((total_reconnects + 1))
            fi

            last_success=$now

            # Connect to desktop (this will block until connection ends)
            connect_to_desktop

            log_warning "SSH connection closed"
            log_to_file "Connection closed, checking for reconnect"

            if [ "$AUTO_RECONNECT" = "true" ]; then
                log_info "Auto-reconnecting in ${CHECK_INTERVAL}s..."
                send_notification "SSH Disconnected" "Reconnecting to desktop..."
                sleep "$CHECK_INTERVAL"
            else
                log_info "Auto-reconnect disabled, exiting"
                break
            fi
        else
            log_warning "SSH connection test failed"
            retry_count=$((retry_count + 1))

            if [ $retry_count -ge $MAX_RETRIES ]; then
                log_error "Max retries reached, backing off..."
                send_notification "SSH Failed" "Cannot connect to desktop"
                sleep $((CHECK_INTERVAL * 3))
                retry_count=0
            else
                log_info "Retry $retry_count/$MAX_RETRIES in ${CHECK_INTERVAL}s..."
                sleep "$CHECK_INTERVAL"
            fi
        fi
    done

    release_wakelock
    log_info "Monitor stopped. Total reconnects: $total_reconnects"
    log_to_file "Monitor stopped after $total_reconnects reconnects"
}

# Simple connect mode (no monitoring)
simple_connect() {
    local ssh_opts=(
        "-o" "ServerAliveInterval=$KEEPALIVE_INTERVAL"
        "-o" "ServerAliveCountMax=3"
        "-p" "$DESKTOP_PORT"
    )

    if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
        ssh_opts+=("-i" "$SSH_KEY")
    fi

    if [ -n "$REMOTE_COMMAND" ]; then
        ssh "${ssh_opts[@]}" "${DESKTOP_USER}@${DESKTOP_HOST}" "$REMOTE_COMMAND"
    else
        ssh "${ssh_opts[@]}" "${DESKTOP_USER}@${DESKTOP_HOST}"
    fi
}

# Main function
main() {
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Termux SSH Auto-Connect to Desktop                   ║"
    echo "║  Maintains persistent connection via Tailscale        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo

    # Handle command line arguments
    case "${2:-}" in
        --once)
            load_config
            check_dependencies
            log_info "Single connection mode"
            simple_connect
            exit $?
            ;;
        --test)
            load_config
            check_dependencies
            log_info "Testing connection..."
            if test_ssh_connection; then
                log_success "Connection test successful!"
                exit 0
            else
                log_error "Connection test failed"
                exit 1
            fi
            ;;
        --create-config)
            create_default_config
            exit 0
            ;;
    esac

    # Normal operation: load config and start monitoring
    load_config
    check_dependencies

    # Start monitoring loop
    monitor_connection
}

# Trap Ctrl+C
trap 'echo; log_warning "Interrupted by user"; release_wakelock; exit 130' INT TERM

# Run main function
main "$@"