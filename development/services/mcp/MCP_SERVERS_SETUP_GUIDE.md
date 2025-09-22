# MCP Servers Setup Guide

## Successfully Installed MCP Servers

This guide documents the MCP (Model Context Protocol) servers that have been installed and configured for your development environment.

### 1. PRIMS - Python Runtime Interpreter
**Location**: `C:\Users\Corbin\development\mcp-servers\PRIMS`
**Purpose**: Execute Python code in a secure, isolated sandbox environment
**Features**:
- Fresh virtual environment for each execution
- Automatic pip package installation
- File mounting capabilities
- Workspace persistence within sessions

**Usage in Claude**:
- Ask Claude to run Python code for data analysis
- Test algorithms and scripts safely
- Process data without affecting your local environment

### 2. JSExecutor - Local JavaScript Executor
**Location**: `C:\Users\Corbin\development\mcp-servers\js-executor`
**Purpose**: Execute JavaScript code safely using Node.js worker threads
**Features**:
- Process-level isolation using worker threads
- Console output capture
- Execution timeout protection
- No external dependencies or cloud services needed

**Usage in Claude**:
- Run JavaScript code snippets
- Test algorithms and functions
- Process data with JavaScript
- No API keys or external services required

### 3. RepoMapper - Repository Navigator
**Location**: `C:\Users\Corbin\development\mcp-servers\RepoMapper`
**Purpose**: Generate intelligent maps of codebases for better navigation
**Features**:
- Uses PageRank to identify important code
- Tree-sitter for language-agnostic parsing
- Token-aware output for LLM contexts
- Supports multiple programming languages

**Usage in Claude**:
- "Map this repository to understand its structure"
- "Show me the most important files in this project"
- "Generate a code map focusing on the authentication module"

### 4. Desktop Notification Server
**Location**: Installed as Python package
**Purpose**: Send desktop notifications when long-running tasks complete
**Features**:
- Cross-platform notification support
- Sound alerts for important events
- Integration with Windows notification center

**Usage in Claude**:
- Automatically notifies when builds complete
- Alerts for finished analysis tasks
- Confirmation when deployments are done

### 5. Filesystem Server (Existing)
**Location**: Runs via NPX
**Purpose**: Safe file system access within allowed directories
**Features**:
- Read/write file operations
- Directory navigation
- Access control for security

## Configuration File Location

The MCP configuration has been saved to:
```
C:\Users\Corbin\development\mcp-configs\claude_desktop_config.json
```

## To Use These Servers with Claude Desktop:

1. **Copy the configuration**:
   - Navigate to `%APPDATA%\Claude`
   - Back up any existing `claude_desktop_config.json`
   - Copy our new configuration file there

2. **For Yepcode** (if you want to use it):
   - Get your API token from https://cloud.yepcode.io
   - Edit the configuration file
   - Replace `YOUR_YEPCODE_API_TOKEN_HERE` with your actual token

3. **Restart Claude Desktop**:
   - Completely quit Claude Desktop
   - Start it again to load the new MCP servers

## Testing the Servers

You can verify each server is working:

### Test PRIMS:
```bash
cd C:\Users\Corbin\development\mcp-servers\PRIMS
python -m server.main
```

### Test RepoMapper:
```bash
cd C:\Users\Corbin\development\mcp-servers\RepoMapper
python repomap.py . --map-tokens 1000
```

### Test Desktop Notifications:
```bash
python -m mcp_server_notify --debug
```

## What You Can Now Do

With these MCP servers, Claude can:

1. **Execute Code Safely**: Run Python and JavaScript without affecting your system
2. **Navigate Large Codebases**: Quickly understand project structure and find important code
3. **Get Desktop Alerts**: Be notified when long-running tasks complete
4. **Work More Efficiently**: Leverage specialized tools for different development tasks

## Troubleshooting

If servers don't appear in Claude:
1. Check the configuration file path is correct
2. Ensure Python is in your PATH
3. Verify all dependencies are installed
4. Check Claude Desktop logs for errors

## Next Steps

Consider exploring more MCP servers from:
- https://github.com/punkpeye/awesome-mcp-servers
- Official MCP servers: https://github.com/modelcontextprotocol/servers

Each server extends Claude's capabilities, making it more powerful for your specific workflow needs.