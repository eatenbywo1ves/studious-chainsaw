# Development Environment

## Overview

This is a comprehensive development environment for managing autonomous agents and MCP (Model Context Protocol) servers. The structure is organized to provide clear separation of concerns, standardized configurations, and efficient development workflows.

## Directory Structure

```
development/
├── agents/                     # Autonomous agents
│   ├── production/            # Production-ready agents
│   │   ├── director-agent/    # Central orchestrator
│   │   ├── observatory-agent/ # Monitoring and observability
│   │   └── von-neumann-agent/ # Self-replicating agent
│   ├── experimental/          # Experimental agents
│   └── templates/             # Agent development templates
├── mcp-servers/               # MCP servers organized by domain
│   ├── financial/            # Financial modeling and analysis
│   │   ├── localization/     # Financial localization
│   │   ├── stochastic/       # Stochastic financial modeling
│   │   └── multidimensional/ # Multi-asset stochastic processes
│   ├── utilities/            # General-purpose utilities
│   │   ├── filesystem/       # File system operations
│   │   └── random-walk/      # Random walk generation
│   └── templates/            # MCP development templates
├── configs/                  # Configuration management
│   ├── mcp/                 # MCP server configurations
│   └── agents/              # Agent configurations
└── shared/                  # Shared libraries and utilities
    ├── libraries/           # Common libraries
    ├── schemas/            # JSON schemas
    └── utilities/          # Utility functions
```

## Quick Start

### 1. Agent Development

To create a new agent:

```bash
# Copy the template
cp -r agents/templates/basic-agent-template agents/experimental/my-new-agent

# Customize the agent
cd agents/experimental/my-new-agent
# Edit agent.py to implement your functionality

# Test the agent
python agent.py
```

### 2. MCP Server Development

To create a new MCP server:

```bash
# Copy the template
cp -r mcp-servers/templates/basic-mcp-template mcp-servers/utilities/my-new-server

# Customize the server
cd mcp-servers/utilities/my-new-server
npm install

# Edit src/index.js to implement your tools
# Test the server
npm run dev
```

### 3. Configuration Management

Update MCP configurations:

```python
from shared.libraries.mcp_registry import get_mcp_registry
from shared.utilities.config_manager import get_config_manager

# Register a new MCP server
registry = get_mcp_registry()
# ... register your server

# Sync configurations
config_manager = get_config_manager()
config_manager.sync_mcp_configs()
```

## Available Components

### Production Agents

1. **Director Agent** (`director-agent`)
   - Central orchestrator for multi-agent systems
   - Project management and task coordination
   - Workflow automation

2. **Observatory Agent** (`observatory-agent`)
   - Real-time monitoring and observability
   - Health checks and metrics collection
   - Live dashboard interface

3. **Von Neumann Agent** (`von-neumann-agent`)
   - Self-replicating and self-modifying capabilities
   - Autonomous operation and evolution

### MCP Servers

#### Financial Domain

1. **Financial Localization** (`financial/localization`)
   - Multi-language financial terminology translation
   - Currency formatting for different locales
   - Regional financial standards compliance

2. **Financial Stochastic** (`financial/stochastic`)
   - Geometric Brownian Motion (GBM) for stock prices
   - Ornstein-Uhlenbeck mean-reverting processes
   - Heston stochastic volatility modeling
   - Merton jump diffusion processes
   - Cox-Ingersoll-Ross interest rate modeling
   - Risk metrics calculation (VaR, CVaR, Sharpe ratio)

3. **Multidimensional Stochastic** (`financial/multidimensional`)
   - Multi-asset correlated GBM processes
   - Correlated Ornstein-Uhlenbeck processes
   - Multi-asset Heston models
   - Portfolio risk and performance metrics
   - Dynamic correlation analysis

#### Utilities Domain

1. **Filesystem** (`utilities/filesystem`)
   - File and directory operations
   - File search and pattern matching
   - Content reading and writing

2. **Random Walk** (`utilities/random-walk`)
   - Simple uniform step random walks
   - Biased random walks with directional preference
   - Lévy flights with power-law step distribution
   - Correlated random walks with memory
   - Statistical analysis of walk properties

## Development Workflow

### 1. Setting Up Development Environment

```bash
# Set up Python environment for agents
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r shared/requirements.txt

# Set up Node.js environment for MCP servers
npm install  # In each MCP server directory
```

### 2. Configuration Management

All configurations are centralized in the `configs/` directory:

- `configs/mcp/` - MCP server configurations
- `configs/agents/` - Agent configurations
- `configs/environment.json` - Environment settings

### 3. Logging and Monitoring

Standardized logging is available through shared utilities:

```python
from shared.utilities.logging_utils import setup_agent_logging

logger = setup_agent_logging("my-agent", level="INFO")
logger.info("Agent started")
```

### 4. Registry and Discovery

Components can register themselves for discovery:

```python
from shared.libraries.agent_registry import AgentRegistry
from shared.libraries.mcp_registry import MCPRegistry

# Register an agent
agent_registry = AgentRegistry()
agent_registry.register_agent("my-agent", agent_info)

# Register an MCP server
mcp_registry = MCPRegistry()
mcp_registry.register_server("my-server", server_info)
```

## Integration with Claude

### Claude Code Configuration

Use the generated configuration file:
```bash
cp configs/mcp/claude-code-updated.json ~/.mcp.json
```

### Claude Desktop Configuration

Use the generated configuration file:
```bash
cp configs/mcp/claude-desktop-updated.json ~/AppData/Roaming/Claude/claude_desktop_config.json
```

## Testing and Validation

### Agent Testing

```bash
cd agents/production/director-agent
python -m pytest tests/
```

### MCP Server Testing

```bash
cd mcp-servers/financial/stochastic
npm test
```

### Integration Testing

```bash
# Test agent registry
python -c "from shared.libraries.agent_registry import get_registry; print(get_registry().list_agents())"

# Test MCP registry  
python -c "from shared.libraries.mcp_registry import get_mcp_registry; print(get_mcp_registry().list_servers())"
```

## Performance Monitoring

The observatory agent provides real-time monitoring:

1. Agent health and status tracking
2. Performance metrics collection
3. Resource usage monitoring
4. Real-time dashboard visualization

Access the dashboard at `http://localhost:3000` when the observatory agent is running.

## Best Practices

### Agent Development

1. **Use the registry system** - Register agents for discovery
2. **Implement health checks** - Provide status and health endpoints
3. **Follow logging standards** - Use shared logging utilities
4. **Handle errors gracefully** - Implement proper error handling
5. **Document capabilities** - Clearly define what your agent can do

### MCP Server Development

1. **Validate inputs** - Always validate tool parameters
2. **Provide clear descriptions** - Document tools and their usage
3. **Handle edge cases** - Test and handle error conditions
4. **Use appropriate schemas** - Define input/output schemas
5. **Follow naming conventions** - Use consistent naming patterns

### Configuration Management

1. **Use environment-specific configs** - Separate dev/prod configurations
2. **Validate configurations** - Use JSON schemas for validation
3. **Keep secrets secure** - Never commit sensitive information
4. **Document changes** - Keep track of configuration modifications

## Troubleshooting

### Common Issues

1. **Import errors** - Ensure shared libraries are in Python path
2. **Configuration not found** - Check file paths and permissions
3. **MCP server not starting** - Verify dependencies and configuration
4. **Agent registration fails** - Check registry file permissions

### Debugging

Enable debug logging:
```python
from shared.utilities.logging_utils import setup_logging
logger = setup_logging("component", level="DEBUG")
```

### Health Checks

Check component health:
```python
# Agent health check
from shared.libraries.agent_registry import get_registry
registry = get_registry()
health = registry.health_check("agent_id")

# MCP server health check  
from shared.libraries.mcp_registry import get_mcp_registry
mcp_registry = get_mcp_registry()
health = mcp_registry.health_check("server_id")
```

## Contributing

1. Follow the established directory structure
2. Use the provided templates for new components
3. Register new components in the appropriate registries
4. Include comprehensive documentation
5. Add appropriate tests and validation

## License

This development environment is provided under the MIT License.

---

**Generated**: August 27, 2025  
**Version**: 1.0.0  
**Status**: Production Ready