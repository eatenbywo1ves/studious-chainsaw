# Data Storage Architecture

## Storage Overview

**Important**: All data is stored locally on your Windows machine. There is no remote server component - everything runs and saves on your local file system.

## Primary Storage Locations

### 1. Development Directory (`C:\Users\Corbin\development\`)
**Purpose**: Main working directory for all development activities

| Subdirectory | Content Type | Examples |
|-------------|--------------|----------|
| `/agents/` | Agent implementations | director-agent.py, observatory-agent/ |
| `/mcp-servers/` | MCP server code | financial/, utilities/ |
| `/shared/` | Shared libraries | workflow_engine.py, message_queue.py |
| `/configs/` | Configuration files | agent-registry.json, mcp-registry.json |
| `/logs/` | Application logs | workflow.log, agent-*.log |
| `/scripts/` | Automation scripts | deploy.sh, test-runner.py |
| `/docker/` | Container configs | Dockerfile, docker-compose.yml |
| `/k8s/` | Kubernetes manifests | deployments/, services/ |

### 2. Configuration Storage

#### System-Level Configurations
```
C:\Users\Corbin\
├── .claude.json          → Claude Code MCP server configurations
├── .mcp.json            → MCP server registry and settings
├── .gitconfig           → Git configuration and aliases
├── .bashrc              → Shell customizations
└── .bash_profile        → Shell startup scripts
```

#### Application Configurations
```
C:\Users\Corbin\development\configs\
├── agents\
│   └── agent-registry.json     → Agent discovery registry
├── mcp\
│   ├── mcp-registry.json       → MCP server registry
│   ├── claude-code-updated.json → Claude Code config
│   └── claude-desktop-updated.json → Claude Desktop config
└── environment.json            → Environment variables
```

### 3. Hidden Directories

#### Claude-Specific Data (`C:\Users\Corbin\.claude\`)
```
.claude\
├── CLAUDE.md               → Personal instructions/preferences
├── shell-snapshots\        → Bash session snapshots
└── cache\                  → Temporary cache files
```

## Data Persistence Patterns

### 1. JSON-Based Registries
**Location**: `configs/agents/agent-registry.json`, `configs/mcp/mcp-registry.json`
**Pattern**: File-based database using JSON
```json
{
  "agentRegistry": {
    "production": {
      "agent-id": {
        "name": "Agent Name",
        "path": "C:\\path\\to\\agent",
        "status": "active"
      }
    }
  }
}
```

### 2. Workflow State Persistence
**Location**: In-memory (not persisted by default)
**Options for persistence**:
- SQLite database (when configured)
- Redis cache (when enabled)
- JSON file snapshots

### 3. Message Queue Storage
**Default**: In-memory queues
**Durable Options**:
- File-based queue persistence
- Redis-backed queues
- PostgreSQL for event sourcing

### 4. Log Files
**Location**: `development/logs/`
**Format**: JSON-structured logs
```json
{
  "timestamp": "2025-01-20T10:30:00Z",
  "component": "WorkflowEngine",
  "level": "INFO",
  "message": "Task completed",
  "task_id": "workflow-123:task-456"
}
```

## Git Repository Structure

Your work is version-controlled locally:
```
Repository Root: C:\Users\Corbin\
Branch: master
Remote: Not configured (local only)
```

### Tracked vs Untracked Files
- **Tracked**: Files committed to git
- **Untracked** (marked with ??): New files not yet added to git
  - development/ (entire directory untracked)
  - .claude.json
  - .mcp.json
  - projects/

## Data Backup Strategies

### 1. Local Backups
Since there's no remote server, consider these backup approaches:

#### Manual Backup
```bash
# Create timestamped backup
cp -r C:/Users/Corbin/development C:/Users/Corbin/backups/dev-$(date +%Y%m%d)
```

#### Git-Based Backup
```bash
# Add all work to git
git add development/
git commit -m "Backup: $(date)"

# Push to remote repository (when configured)
git remote add origin https://github.com/yourusername/yourrepo.git
git push -u origin master
```

### 2. Critical Files to Backup

**High Priority** (Unique configurations):
- `.claude/CLAUDE.md` - Personal instructions
- `.mcp.json` - MCP configurations
- `development/configs/` - All configurations
- `development/shared/libraries/` - Custom libraries

**Medium Priority** (Recreatable but time-consuming):
- `development/agents/` - Agent implementations
- `development/mcp-servers/` - MCP servers
- `development/*.md` - Documentation

**Low Priority** (Can be regenerated):
- `development/logs/` - Log files
- `node_modules/` - NPM packages
- `__pycache__/` - Python cache

## Recovery Procedures

### Full System Recovery
1. **Restore files** from backup location
2. **Reinstall dependencies**:
   ```bash
   # Python dependencies
   pip install -r development/requirements.txt
   
   # Node.js dependencies (per MCP server)
   cd development/mcp-servers/[server]
   npm install
   ```
3. **Verify configurations**:
   ```bash
   python development/verify-mcp-setup.py
   ```
4. **Restart services**:
   ```bash
   python development/initialize.py
   ```

### Partial Recovery (Single Component)
```bash
# Restore specific agent
cp -r /backup/agents/director-agent development/agents/production/

# Re-register in registry
python -c "from shared.libraries.agent_registry import get_registry; 
          registry = get_registry(); 
          registry.discover_agents('development/agents')"
```

## Storage Optimization

### Clean Up Temporary Files
```bash
# Remove Python cache
find development -type d -name "__pycache__" -exec rm -rf {} +

# Clear old logs (older than 30 days)
find development/logs -name "*.log" -mtime +30 -delete

# Remove node_modules for rebuild
rm -rf development/mcp-servers/*/node_modules
```

### Disk Usage Analysis
```bash
# Check development directory size
du -sh development/

# Find large files
find development -type f -size +10M

# Directory breakdown
du -h --max-depth=2 development/ | sort -rh | head -20
```

## Important Notes

1. **No Cloud Storage**: All data remains on your local machine
2. **No Automatic Backups**: Manual backup strategy required
3. **Local Git Only**: Repository exists locally unless you push to remote
4. **Session Data**: Claude shell snapshots are temporary
5. **Configuration Priority**: 
   - User configs (`.claude/`) override defaults
   - Local configs override global configs

## Security Considerations

Since all data is local:
- **Physical Security**: Protect your machine
- **Encryption**: Consider disk encryption (BitLocker)
- **Access Control**: Windows user permissions apply
- **Sensitive Data**: Avoid storing credentials in plain text
- **Git Security**: Use `.gitignore` for sensitive files

## Recommended Backup Schedule

| Frequency | What to Backup | Method |
|-----------|---------------|---------|
| Daily | Active development work | Git commit |
| Weekly | Full development/ directory | Compressed archive |
| Monthly | Entire C:\Users\Corbin\ | System backup |
| On Change | Configuration files | Git commit |