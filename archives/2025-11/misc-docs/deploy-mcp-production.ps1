# MCP Servers Production Deployment Script
# PowerShell script for deploying MCP servers in production mode

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("start", "stop", "restart", "status", "logs", "install")]
    [string]$Action = "status",

    [Parameter(Mandatory=$false)]
    [string]$Server = "all",

    [Parameter(Mandatory=$false)]
    [ValidateSet("development", "staging", "production")]
    [string]$Environment = "production"
)

$ErrorActionPreference = "Stop"

# Configuration
$CONFIG_FILE = "mcp-production-config.yaml"
$LOG_DIR = "C:\Users\Corbin\logs"
$PID_DIR = "C:\Users\Corbin\mcp-pids"
$BACKUP_DIR = "C:\Users\Corbin\mcp-backups"

# Colors for output
function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Info { Write-Host $args -ForegroundColor Cyan }
function Write-Warning { Write-Host $args -ForegroundColor Yellow }
function Write-Error { Write-Host $args -ForegroundColor Red }

# Ensure directories exist
function Ensure-Directories {
    @($LOG_DIR, $PID_DIR, $BACKUP_DIR) | ForEach-Object {
        if (!(Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Info "Created directory: $_"
        }
    }
}

# Install dependencies
function Install-Dependencies {
    Write-Info "Installing production dependencies..."

    # Check for PM2
    $pm2 = Get-Command pm2 -ErrorAction SilentlyContinue
    if (!$pm2) {
        Write-Info "Installing PM2 process manager..."
        npm install -g pm2
        npm install -g pm2-windows-startup
        pm2-startup install
    }

    # Check for required npm packages
    Write-Info "Installing MCP server dependencies..."
    Push-Location "C:\Users\Corbin\development\mcp-servers"

    # Install dependencies for each server
    $servers = @(
        "financial\localization",
        "financial\stochastic",
        "financial\multidimensional",
        "utilities\random-walk",
        "utilities\adaptive-control"
    )

    foreach ($serverPath in $servers) {
        if (Test-Path $serverPath) {
            Write-Info "  - Installing dependencies for $serverPath"
            Push-Location $serverPath
            npm install --production

            # Build if TypeScript
            if (Test-Path "tsconfig.json") {
                Write-Info "    Building TypeScript..."
                npm run build 2>$null || npx tsc
            }
            Pop-Location
        }
    }

    Pop-Location
    Write-Success "Dependencies installed successfully!"
}

# Start servers
function Start-Servers {
    param([string]$ServerName = "all")

    Write-Info "Starting MCP servers in $Environment mode..."

    # Create PM2 ecosystem file
    $ecosystem = @"
module.exports = {
  apps: [
    {
      name: 'mcp-filesystem',
      script: 'npx',
      args: '-y @modelcontextprotocol/server-filesystem C:/Users/Corbin/development',
      env: {
        NODE_ENV: '$Environment'
      },
      max_memory_restart: '512M',
      autorestart: true,
      watch: false,
      max_restarts: 5,
      min_uptime: '10s',
      error_file: '$LOG_DIR/mcp-filesystem-error.log',
      out_file: '$LOG_DIR/mcp-filesystem-out.log',
      log_file: '$LOG_DIR/mcp-filesystem-combined.log',
      time: true
    },
    {
      name: 'mcp-financial-localization',
      script: 'C:/Users/Corbin/development/mcp-servers/financial/localization/dist/index.js',
      env: {
        NODE_ENV: '$Environment',
        PORT: 3001
      },
      max_memory_restart: '256M',
      autorestart: true,
      watch: false,
      max_restarts: 5,
      error_file: '$LOG_DIR/mcp-financial-loc-error.log',
      out_file: '$LOG_DIR/mcp-financial-loc-out.log',
      time: true
    },
    {
      name: 'mcp-financial-stochastic',
      script: 'C:/Users/Corbin/development/mcp-servers/financial/stochastic/dist/index.js',
      env: {
        NODE_ENV: '$Environment',
        PORT: 3002,
        MAX_SIMULATIONS: 10000
      },
      max_memory_restart: '1G',
      autorestart: true,
      watch: false,
      max_restarts: 5,
      error_file: '$LOG_DIR/mcp-financial-stoch-error.log',
      out_file: '$LOG_DIR/mcp-financial-stoch-out.log',
      time: true
    },
    {
      name: 'mcp-multidimensional',
      script: 'C:/Users/Corbin/development/mcp-servers/financial/multidimensional/dist/index.js',
      env: {
        NODE_ENV: '$Environment',
        PORT: 3003,
        MAX_DIMENSIONS: 100
      },
      max_memory_restart: '2G',
      autorestart: true,
      watch: false,
      max_restarts: 5,
      error_file: '$LOG_DIR/mcp-multidim-error.log',
      out_file: '$LOG_DIR/mcp-multidim-out.log',
      time: true
    },
    {
      name: 'mcp-random-walk',
      script: 'C:/Users/Corbin/development/mcp-servers/utilities/random-walk/dist/index.js',
      env: {
        NODE_ENV: '$Environment',
        PORT: 3004
      },
      max_memory_restart: '512M',
      autorestart: true,
      watch: false,
      max_restarts: 5,
      error_file: '$LOG_DIR/mcp-random-walk-error.log',
      out_file: '$LOG_DIR/mcp-random-walk-out.log',
      time: true
    },
    {
      name: 'mcp-adaptive-control',
      script: 'C:/Users/Corbin/development/mcp-servers/utilities/adaptive-control/dist/index.js',
      env: {
        NODE_ENV: '$Environment',
        PORT: 3005,
        LEARNING_RATE: 0.01
      },
      max_memory_restart: '1G',
      autorestart: true,
      watch: false,
      max_restarts: 5,
      error_file: '$LOG_DIR/mcp-adaptive-error.log',
      out_file: '$LOG_DIR/mcp-adaptive-out.log',
      time: true
    }
  ]
};
"@

    $ecosystem | Out-File -FilePath "ecosystem.config.js" -Encoding UTF8

    # Start with PM2
    if ($ServerName -eq "all") {
        pm2 start ecosystem.config.js
    } else {
        pm2 start ecosystem.config.js --only $ServerName
    }

    Write-Success "MCP servers started successfully!"
}

# Stop servers
function Stop-Servers {
    param([string]$ServerName = "all")

    Write-Info "Stopping MCP servers..."

    if ($ServerName -eq "all") {
        pm2 stop all
    } else {
        pm2 stop $ServerName
    }

    Write-Success "MCP servers stopped!"
}

# Restart servers
function Restart-Servers {
    param([string]$ServerName = "all")

    Write-Info "Restarting MCP servers..."

    if ($ServerName -eq "all") {
        pm2 restart all
    } else {
        pm2 restart $ServerName
    }

    Write-Success "MCP servers restarted!"
}

# Get server status
function Get-ServerStatus {
    Write-Info "MCP Server Status:"
    pm2 list

    Write-Info "`nResource Usage:"
    pm2 monit
}

# View logs
function View-Logs {
    param([string]$ServerName = "all")

    if ($ServerName -eq "all") {
        pm2 logs
    } else {
        pm2 logs $ServerName
    }
}

# Create Windows Service
function Install-WindowsService {
    Write-Info "Installing MCP servers as Windows service..."

    # Save PM2 configuration
    pm2 save

    # Install as Windows service
    pm2-installer

    Write-Success "Windows service installed!"
    Write-Info "The MCP servers will now start automatically on system boot"
}

# Main execution
Write-Info "================================="
Write-Info "  MCP Production Deployment Tool"
Write-Info "================================="
Write-Info "Environment: $Environment"
Write-Info "Action: $Action"
Write-Info ""

Ensure-Directories

switch ($Action) {
    "install" {
        Install-Dependencies
        Install-WindowsService
    }
    "start" {
        Start-Servers -ServerName $Server
    }
    "stop" {
        Stop-Servers -ServerName $Server
    }
    "restart" {
        Restart-Servers -ServerName $Server
    }
    "status" {
        Get-ServerStatus
    }
    "logs" {
        View-Logs -ServerName $Server
    }
    default {
        Write-Error "Unknown action: $Action"
        exit 1
    }
}

Write-Info ""
Write-Info "Operation completed!"