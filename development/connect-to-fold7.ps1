# Connect to Samsung Fold 7 via SSH (Tailscale)
# Companion script for enhanced Termux SSH setup
# Version: 1.0

param(
    [switch]$Status,
    [switch]$Copy,
    [switch]$SetupKeys,
    [switch]$Monitor,
    [string]$Command = ""
)

# Configuration
$FOLD7_USER = "u0_a397"  # Update this with your Termux username
$FOLD7_TAILSCALE = "fold7"  # Update with your Tailscale hostname
$SSH_PORT = 8022
$SSH_KEY_PATH = "$env:USERPROFILE\.ssh\id_fold7"

# Colors
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Info($message) {
    Write-ColorOutput Cyan "[INFO] $message"
}

function Write-Success($message) {
    Write-ColorOutput Green "[SUCCESS] $message"
}

function Write-Warning($message) {
    Write-ColorOutput Yellow "[WARNING] $message"
}

function Write-Error($message) {
    Write-ColorOutput Red "[ERROR] $message"
}

# Banner
function Show-Banner {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Samsung Fold 7 SSH Connection Manager" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

# Test Tailscale connectivity
function Test-TailscaleConnection {
    Write-Info "Testing Tailscale connectivity..."

    if (!(Get-Command tailscale -ErrorAction SilentlyContinue)) {
        Write-Error "Tailscale is not installed or not in PATH"
        Write-Host "Download from: https://tailscale.com/download/windows"
        return $false
    }

    $status = tailscale status 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tailscale is not running"
        Write-Host "Start Tailscale from system tray or run: tailscale up"
        return $false
    }

    # Get Fold 7 IP from Tailscale
    $fold7IP = tailscale ip -4 $FOLD7_TAILSCALE 2>$null
    if ($fold7IP) {
        Write-Success "Tailscale connected"
        Write-Host "  Fold 7 IP: $fold7IP"
        return $true
    } else {
        Write-Warning "Cannot resolve Fold 7 hostname: $FOLD7_TAILSCALE"
        Write-Host "  Run 'tailscale status' to see available devices"
        return $false
    }
}

# Test SSH connectivity to Fold 7
function Test-SSHConnection {
    Write-Info "Testing SSH connection to Fold 7..."

    $testConnection = Test-NetConnection -ComputerName $FOLD7_TAILSCALE -Port $SSH_PORT -InformationLevel Quiet -WarningAction SilentlyContinue

    if ($testConnection) {
        Write-Success "SSH port $SSH_PORT is reachable"

        # Try to connect
        $result = ssh -p $SSH_PORT -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$FOLD7_USER@$FOLD7_TAILSCALE" "echo 'SSH OK'" 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "SSH authentication successful"
            return $true
        } else {
            Write-Warning "SSH port is open but authentication failed"
            Write-Host "  You may need to setup SSH keys or enter password"
            return $false
        }
    } else {
        Write-Error "Cannot reach SSH port $SSH_PORT on Fold 7"
        Write-Host ""
        Write-Host "Troubleshooting steps:"
        Write-Host "  1. Ensure Termux is running on Fold 7"
        Write-Host "  2. Check if SSH daemon is running: ~/status.sh"
        Write-Host "  3. Verify Tailscale is connected on both devices"
        return $false
    }
}

# Show status of Fold 7 services
function Show-Fold7Status {
    Show-Banner

    if (!(Test-TailscaleConnection)) {
        return
    }

    Write-Info "Fetching Fold 7 status..."
    Write-Host ""

    ssh -p $SSH_PORT "$FOLD7_USER@$FOLD7_TAILSCALE" "bash ~/status.sh"

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Success "Status retrieved successfully"
    } else {
        Write-Error "Failed to retrieve status"
    }
}

# Setup SSH keys
function Setup-SSHKeys {
    Show-Banner

    Write-Info "Setting up SSH key-based authentication..."
    Write-Host ""

    # Check if key already exists
    if (Test-Path $SSH_KEY_PATH) {
        Write-Warning "SSH key already exists: $SSH_KEY_PATH"
        $response = Read-Host "Do you want to create a new key? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Info "Using existing key"
        } else {
            Write-Info "Generating new SSH key..."
            ssh-keygen -t ed25519 -f $SSH_KEY_PATH -C "fold7-access-key"
        }
    } else {
        Write-Info "Generating new SSH key..."
        ssh-keygen -t ed25519 -f $SSH_KEY_PATH -C "fold7-access-key"
    }

    if (Test-Path $SSH_KEY_PATH) {
        Write-Success "SSH key ready: $SSH_KEY_PATH"
        Write-Host ""
        Write-Info "Copying public key to Fold 7..."

        # Copy public key to Fold 7
        $result = Get-Content "$SSH_KEY_PATH.pub" | ssh -p $SSH_PORT "$FOLD7_USER@$FOLD7_TAILSCALE" `
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'Key installed successfully'"

        if ($LASTEXITCODE -eq 0) {
            Write-Success "SSH key installed on Fold 7"
            Write-Host ""
            Write-Info "Testing key-based authentication..."

            ssh -p $SSH_PORT -i $SSH_KEY_PATH "$FOLD7_USER@$FOLD7_TAILSCALE" "echo 'Authentication test successful'"

            if ($LASTEXITCODE -eq 0) {
                Write-Success "SSH key authentication is working!"
                Write-Host ""
                Write-Host "Add to your ~/.ssh/config for easier access:"
                Write-Host ""
                Write-Host "Host fold7" -ForegroundColor Yellow
                Write-Host "    HostName $FOLD7_TAILSCALE" -ForegroundColor Yellow
                Write-Host "    User $FOLD7_USER" -ForegroundColor Yellow
                Write-Host "    Port $SSH_PORT" -ForegroundColor Yellow
                Write-Host "    IdentityFile $SSH_KEY_PATH" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Then connect with: ssh fold7" -ForegroundColor Green
            }
        } else {
            Write-Error "Failed to install SSH key"
        }
    }
}

# Copy file to/from Fold 7
function Copy-Files {
    Show-Banner

    Write-Host "SCP File Transfer to/from Fold 7"
    Write-Host ""

    $direction = Read-Host "Transfer direction? (1=To Fold7, 2=From Fold7)"

    if ($direction -eq "1") {
        $localFile = Read-Host "Enter local file path"
        $remotePath = Read-Host "Enter remote path (e.g., ~/Downloads/)"

        Write-Info "Copying $localFile to Fold 7:$remotePath"
        scp -P $SSH_PORT "$localFile" "${FOLD7_USER}@${FOLD7_TAILSCALE}:$remotePath"

        if ($LASTEXITCODE -eq 0) {
            Write-Success "File copied successfully"
        }
    } elseif ($direction -eq "2") {
        $remotePath = Read-Host "Enter remote file path (e.g., ~/file.txt)"
        $localPath = Read-Host "Enter local destination"

        Write-Info "Copying Fold 7:$remotePath to $localPath"
        scp -P $SSH_PORT "${FOLD7_USER}@${FOLD7_TAILSCALE}:$remotePath" "$localPath"

        if ($LASTEXITCODE -eq 0) {
            Write-Success "File copied successfully"
        }
    } else {
        Write-Error "Invalid selection"
    }
}

# Monitor Fold 7 services
function Start-Monitoring {
    Show-Banner

    Write-Info "Starting Fold 7 service monitor (Ctrl+C to stop)..."
    Write-Host ""

    while ($true) {
        Clear-Host
        Write-Host "Fold 7 Service Monitor - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""

        # Test Tailscale
        if (Get-Command tailscale -ErrorAction SilentlyContinue) {
            $tailscaleStatus = tailscale status 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[✓] Tailscale: Connected" -ForegroundColor Green
            } else {
                Write-Host "[✗] Tailscale: Disconnected" -ForegroundColor Red
            }
        } else {
            Write-Host "[✗] Tailscale: Not installed" -ForegroundColor Red
        }

        # Test SSH connectivity
        $sshTest = Test-NetConnection -ComputerName $FOLD7_TAILSCALE -Port $SSH_PORT -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($sshTest) {
            Write-Host "[✓] SSH Port $SSH_PORT : Reachable" -ForegroundColor Green

            # Get service status from Fold 7
            $serviceStatus = ssh -p $SSH_PORT -o ConnectTimeout=3 "$FOLD7_USER@$FOLD7_TAILSCALE" `
                "pgrep -x sshd > /dev/null && echo 'SSH:Running' || echo 'SSH:Stopped'; tailscale status &>/dev/null && echo 'TS:Connected' || echo 'TS:Disconnected'" 2>$null

            if ($serviceStatus) {
                $serviceStatus -split "`n" | ForEach-Object {
                    if ($_ -match "Running|Connected") {
                        Write-Host "[✓] $_" -ForegroundColor Green
                    } else {
                        Write-Host "[✗] $_" -ForegroundColor Yellow
                    }
                }
            }
        } else {
            Write-Host "[✗] SSH Port $SSH_PORT : Unreachable" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "Refreshing in 5 seconds..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
    }
}

# Execute command on Fold 7
function Invoke-RemoteCommand {
    param([string]$cmd)

    Show-Banner
    Write-Info "Executing command on Fold 7: $cmd"
    Write-Host ""

    ssh -p $SSH_PORT "$FOLD7_USER@$FOLD7_TAILSCALE" $cmd
}

# Main connection function
function Connect-Fold7 {
    Show-Banner

    Write-Info "Connecting to Samsung Fold 7..."
    Write-Host ""

    # Check Tailscale
    if (!(Test-TailscaleConnection)) {
        return
    }

    Write-Host ""
    Write-Info "Opening SSH session..."
    Write-Host "  Host: $FOLD7_TAILSCALE"
    Write-Host "  User: $FOLD7_USER"
    Write-Host "  Port: $SSH_PORT"
    Write-Host ""

    # Use SSH key if available
    if (Test-Path $SSH_KEY_PATH) {
        ssh -p $SSH_PORT -i $SSH_KEY_PATH "$FOLD7_USER@$FOLD7_TAILSCALE"
    } else {
        ssh -p $SSH_PORT "$FOLD7_USER@$FOLD7_TAILSCALE"
    }
}

# Main execution
if ($Status) {
    Show-Fold7Status
} elseif ($SetupKeys) {
    Setup-SSHKeys
} elseif ($Copy) {
    Copy-Files
} elseif ($Monitor) {
    Start-Monitoring
} elseif ($Command) {
    Invoke-RemoteCommand -cmd $Command
} else {
    # Default: Connect
    Connect-Fold7
}
