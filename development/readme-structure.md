# Development Directory Structure - Hybrid Monorepo

## Overview
This directory follows a hybrid monorepo structure, balancing modularity with practical organization.

## Directory Layout

```
development/
├── apps/                   # Main applications
│   ├── catalytic/         # Core catalytic computing application
│   │                      # - GPU-accelerated lattice algorithms
│   │                      # - Memory optimization tools
│   │                      # - Performance benchmarks
│   └── api-gateway/       # Production API server
│                          # - REST endpoints
│                          # - Service orchestration
│
├── libs/                  # Shared libraries
│   ├── core/             # Core computational algorithms
│   ├── utils/            # Utility functions
│   │   ├── exceptions.py # Custom exceptions
│   │   └── validation.py # Input validation
│   └── constants/        # Shared constants and configurations
│
├── services/             # Microservices
│   ├── mcp/             # Model Context Protocol servers
│   │   ├── financial/   # Financial computation services
│   │   ├── utilities/   # Utility MCP servers
│   │   └── ...         # Other MCP implementations
│   └── webhooks/        # Webhook management system
│                        # - Event processing
│                        # - Callback handling
│
├── tools/               # Development and integration tools
│   ├── claude/         # Claude AI integrations
│   │                   # - Workflow tools
│   │                   # - Custom tools
│   └── audio/          # Audio alert system
│
├── infra/              # Infrastructure and deployment
│   ├── docker/         # Docker configurations
│   ├── k8s/           # Kubernetes manifests
│   ├── monitoring/     # Prometheus, Grafana configs
│   └── *.sh           # Deployment scripts
│
├── tests/              # Test suite
│   ├── unit/          # Unit tests
│   ├── integration/    # Integration tests
│   └── performance/    # Performance benchmarks
│
├── docs/               # Documentation
│   └── *.md           # All documentation files
│
└── .config/            # Configuration files
    ├── pyproject.toml  # Python project config
    ├── requirements.txt # Dependencies
    └── ...            # Other configurations
```

## Key Benefits

1. **Clear Separation**: Each directory has a single, clear purpose
2. **Scalability**: Easy to add new services, apps, or tools
3. **Dependency Management**: Shared code in `libs/` reduces duplication
4. **Service Independence**: Each service in `services/` can be developed/deployed independently
5. **Clean Root**: Configuration hidden in `.config/`, keeping root clean

## Migration Tools

- **update_imports.py**: Updates Python import paths to match new structure
- **migration_rollback.py**: Reverts to original structure if needed

## Working with the Structure

### Adding a New Service
```bash
mkdir services/new-service
# Add service-specific code, tests, and configs
```

### Adding Shared Code
```bash
# Place in appropriate libs/ subdirectory
# Update imports using update_imports.py
```

### Running Tests
```bash
python tests/run_tests.py
```

## Quick Reference

- **Core Computing**: `apps/catalytic/`
- **API Server**: `apps/api-gateway/`
- **MCP Servers**: `services/mcp/`
- **Deployment**: `infra/`
- **Configuration**: `.config/`