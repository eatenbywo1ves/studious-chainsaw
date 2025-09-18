# Workspace Launcher System

Complete workspace management system for your development environment.

## Quick Start

**Launch your workspace with one command:**
```cmd
C:\Users\Corbin\launch-workspace.bat
```

## Features

- **Profile-Based Launch**: Pre-configured workspace profiles for different tasks
- **Service Orchestration**: Manages MCP servers, development tools, and projects
- **Health Monitoring**: Tracks service status and resource usage
- **Quick Launchers**: Single-command shortcuts for common tasks
- **Environment Validation**: Checks and installs dependencies
- **Windows Terminal Integration**: Multi-tab layouts for better organization

## Available Profiles

### 1. Full Development
Everything you need for comprehensive development:
- MCP Orchestrator & Dashboard
- Ghidra-Claude Bridge
- API Gateway
- Financial Simulator
- Development environment

### 2. MCP Services
Focused on MCP server management:
- MCP Orchestrator
- MCP Dashboard (http://localhost:5000)
- Service monitoring

### 3. Financial Development
Financial application development:
- MCP services
- Financial simulator (http://localhost:5173)
- Required Node.js environment

### 4. Reverse Engineering
Binary analysis and reverse engineering:
- Ghidra-Claude Bridge
- Analysis tools
- RE-specific environment

### 5. Minimal
Basic development environment:
- Code editor
- Essential tools only

### 6. Custom
Interactive selection of services to launch

## File Structure

```
Tools/workspace-launcher/
├── workspace_manager.py      # Core workspace management
├── wt-profiles.json          # Windows Terminal configurations
├── quick-launchers.bat       # Quick launch shortcuts
├── setup-environment.bat     # Environment setup script
└── logs/                     # Workspace logs

C:\Users\Corbin\
└── launch-workspace.bat      # Main launcher script
```

## Quick Commands

### Using Quick Launchers

```cmd
# Start MCP services
Tools\workspace-launcher\quick-launchers mcp

# Start Ghidra bridge
Tools\workspace-launcher\quick-launchers ghidra

# Start financial apps
Tools\workspace-launcher\quick-launchers financial

# Open dashboard
Tools\workspace-launcher\quick-launchers dashboard

# Stop all services
Tools\workspace-launcher\quick-launchers stop

# Check status
Tools\workspace-launcher\quick-launchers status
```

### Using Python Manager

```bash
# Launch specific profile
python Tools/workspace-launcher/workspace_manager.py launch --profile full

# Interactive mode
python Tools/workspace-launcher/workspace_manager.py launch --interactive

# Check status
python Tools/workspace-launcher/workspace_manager.py status

# List all profiles
python Tools/workspace-launcher/workspace_manager.py list

# Stop all services
python Tools/workspace-launcher/workspace_manager.py stop
```

## Environment Setup

Run the setup script to validate your environment:
```cmd
Tools\workspace-launcher\setup-environment.bat
```

This will check for:
- Python installation
- Node.js and npm
- Git
- Required Python packages (Flask, psutil)
- Project dependencies

## Service Details

### MCP Orchestrator
- **Port**: N/A (backend service)
- **Purpose**: Manages all MCP servers
- **Health checks**: Every 10 seconds
- **Auto-restart**: Up to 3 attempts

### MCP Dashboard
- **Port**: 5000
- **URL**: http://localhost:5000
- **Purpose**: Visual monitoring interface
- **Features**: Real-time updates, server controls

### Financial Simulator
- **Port**: 5173
- **URL**: http://localhost:5173
- **Purpose**: Financial application development
- **Framework**: Vite + React

### Ghidra-Claude Bridge
- **Port**: Various
- **Purpose**: RE tool integration
- **Requirements**: Ghidra installation

## Customization

### Adding New Services

Edit `workspace_manager.py` and add to `_define_services()`:

```python
"my-service": Service(
    name="My Service",
    command="python my_service.py",
    directory=str(self.base_dir / "path"),
    port=8080,
    url="http://localhost:8080",
    wait_for_port=True,
    auto_open_browser=True
)
```

### Creating New Profiles

Edit `workspace_manager.py` and add to `_define_profiles()`:

```python
"my-profile": WorkspaceProfile(
    name="My Custom Profile",
    description="Description here",
    services=["mcp-orchestrator", "my-service"],
    projects=["my-project"],
    environment={"MY_VAR": "value"}
)
```

## Troubleshooting

### Services won't start
1. Run `setup-environment.bat` to check dependencies
2. Check logs in `Tools\workspace-launcher\logs\`
3. Verify paths in `workspace_manager.py`

### Port conflicts
- MCP Dashboard: Change port in `dashboard.py`
- Financial apps: Update port in `vite.config.js`

### Python package issues
```cmd
pip install --upgrade pip
pip install flask flask-cors psutil
```

### Node.js issues
```cmd
npm cache clean --force
npm install
```

## Tips

1. **First Time Setup**: Run `setup-environment.bat` first
2. **Daily Use**: Use `launch-workspace.bat` for quick starts
3. **Quick Access**: Pin `launch-workspace.bat` to taskbar
4. **Multiple Profiles**: You can run different profiles in separate sessions
5. **Resource Management**: Monitor CPU/RAM usage in MCP dashboard

## Integration with Other Tools

### VS Code
The workspace launcher can open VS Code automatically:
- Configured in the "code-server" service
- Opens in `projects/active/` directory

### Windows Terminal
For better terminal management:
- Profiles defined in `wt-profiles.json`
- Use `--use-wt` flag for Windows Terminal layout

### Git Integration
- Git status shown in some profiles
- Auto-detection of repository status

## Future Enhancements

- [ ] Docker container support
- [ ] Remote service management
- [ ] Profile import/export
- [ ] Service dependency resolution
- [ ] Automated backups
- [ ] Performance profiling
- [ ] Integration with CI/CD