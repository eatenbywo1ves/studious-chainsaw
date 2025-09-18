# MCP Server Orchestrator

Centralized management and monitoring system for Model Context Protocol (MCP) servers.

## Features

- **Unified Management**: Start, stop, and restart all MCP servers from one place
- **Health Monitoring**: Automatic health checks with configurable thresholds
- **Auto-Restart**: Automatically restart crashed or unhealthy servers
- **Resource Tracking**: Monitor CPU and memory usage per server
- **Web Dashboard**: Real-time monitoring dashboard with server controls
- **Logging**: Comprehensive logging for debugging and audit trails
- **CLI Interface**: Command-line tool for server management

## Components

### 1. `mcp_orchestrator.py`
Core orchestration engine with:
- Process management
- Health checking
- Resource monitoring
- Auto-restart logic
- Signal handling for graceful shutdown

### 2. `dashboard.py`
Flask-based web dashboard providing:
- Real-time server status
- Start/stop/restart controls
- Resource usage metrics
- Log viewing
- Auto-refresh every 5 seconds

### 3. Startup Scripts
- `start-services.bat`: Windows batch script
- `start-services.sh`: Unix/Linux/WSL script

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

### Command Line Interface

```bash
# Start all servers
python Tools/mcp-orchestrator/mcp_orchestrator.py start

# Start specific server
python Tools/mcp-orchestrator/mcp_orchestrator.py start --server financial-localization

# Stop all servers
python Tools/mcp-orchestrator/mcp_orchestrator.py stop

# Restart a server
python Tools/mcp-orchestrator/mcp_orchestrator.py restart --server random-walk

# View status
python Tools/mcp-orchestrator/mcp_orchestrator.py status

# Monitor mode (continuous monitoring with auto-restart)
python Tools/mcp-orchestrator/mcp_orchestrator.py monitor
```

### Quick Start (Windows)

Double-click `start-services.bat` or run:
```cmd
Tools\mcp-orchestrator\start-services.bat
```

### Quick Start (Unix/Linux/WSL)

```bash
chmod +x Tools/mcp-orchestrator/start-services.sh
./Tools/mcp-orchestrator/start-services.sh
```

### Web Dashboard

1. Start the dashboard:
```bash
python Tools/mcp-orchestrator/dashboard.py
```

2. Open browser to: http://localhost:5000

## Configuration

The orchestrator reads MCP server configuration from `.mcp.json` in the user's home directory.

Example configuration:
```json
{
  "mcpServers": {
    "server-name": {
      "command": "node",
      "args": ["path/to/server.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

## Health Check Configuration

Health checks are performed every 10 seconds with the following thresholds:
- CPU Usage: Warning at >90%
- Memory Usage: Warning at >1GB
- Failed Checks: Auto-restart after 3 consecutive failures
- Max Restarts: 3 attempts before marking as crashed

## Dashboard Features

- **Server Cards**: Visual representation of each server
- **Status Indicators**:
  - 🟢 Running
  - ⏹️ Stopped
  - ❌ Crashed
  - ⚠️ Unhealthy
  - 🔄 Starting/Stopping
- **Metrics**: Real-time CPU and memory usage
- **Actions**: One-click start/stop/restart
- **Logs**: View recent orchestrator logs

## Troubleshooting

### Server won't start
- Check if the server path exists
- Verify Node.js is installed (for Node-based servers)
- Check orchestrator.log for errors

### Dashboard not loading
- Ensure Flask is installed: `pip install flask flask-cors`
- Check if port 5000 is available
- Try a different port: `python dashboard.py --port 5001`

### High resource usage
- Adjust health check intervals in mcp_orchestrator.py
- Reduce monitoring frequency
- Check individual server logs for issues

## Architecture

```
┌─────────────────┐
│  Web Dashboard  │
│   (Flask App)   │
└────────┬────────┘
         │ REST API
┌────────▼────────┐
│  Orchestrator   │
│     Engine      │
├─────────────────┤
│ Health Monitor  │
│ Process Manager │
│ Resource Track  │
└────────┬────────┘
         │ Manages
┌────────▼────────┐
│  MCP Servers    │
│ - filesystem    │
│ - financial-*   │
│ - utilities-*   │
└─────────────────┘
```

## Future Enhancements

- [ ] Server grouping and bulk operations
- [ ] Performance metrics history/graphs
- [ ] Email/webhook alerts for failures
- [ ] Server dependency management
- [ ] Configuration hot-reload
- [ ] Docker container support
- [ ] Distributed orchestration
- [ ] Backup and restore functionality