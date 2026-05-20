# Development Workspace

## Directory Structure

```
C:\Users\Corbin\
├── development/              # Main development monorepo
│   ├── apps/                 # Applications
│   │   ├── api-gateway/      # Production API server
│   │   └── catalytic/        # GPU-accelerated lattice computing
│   ├── GhidraGo/             # Ghidra plugin (Gradle/Java)
│   ├── Ghidraaas/            # Ghidra-as-a-Service (Docker)
│   ├── saas/                 # Multi-tenant SaaS platform (FastAPI + PostgreSQL + Redis)
│   ├── monitoring/           # Prometheus, Grafana dashboards
│   ├── security/             # Security deployment scripts
│   ├── vault/                # HashiCorp Vault configuration
│   ├── services/mcp/         # MCP server submodules
│   ├── scripts/              # Automation scripts (Python, PowerShell, Bash)
│   └── tests/                # Integration and GPU test suites
│
├── projects/                 # Standalone projects
│   ├── active/               # Active development
│   │   ├── architecture/     # Architecture documents
│   │   ├── guides/           # Setup and workflow guides
│   │   ├── phases/           # Phase implementation reports
│   │   └── security/         # Security assessments
│   ├── agents/               # Multi-agent systems
│   ├── mcp-servers/          # Financial MCP servers (localization, stochastic, random-walk)
│   ├── financial-apps/       # Financial simulation apps
│   └── packages/             # Shared NPM packages
│
├── Insights/                 # Key insights tracker and mind map
├── ghidra-claude/            # Ghidra-Claude bridge scripts
├── archives/                 # Archived docs by month
└── .claude/                  # Claude Code configuration
```

## Active Projects

| Project | Path | Stack |
|---------|------|-------|
| Catalytic Computing | `development/apps/catalytic/` | Python, PyTorch, CUDA, GPU |
| SaaS Platform | `development/saas/` | FastAPI, PostgreSQL, Redis, JWT |
| GhidraGo Plugin | `development/GhidraGo/` | Java, Gradle, Ghidra API |
| Ghidra-as-a-Service | `development/Ghidraaas/` | Docker, Python, REST API |
| MCP Servers | `projects/mcp-servers/` | Node.js, TypeScript |
| Financial Apps | `projects/financial-apps/` | React, TypeScript |

## Quick Start

```bash
# Start core Docker services
cd ~/development && docker-compose up -d

# Start SaaS stack
cd ~/development && docker-compose -f docker-compose-saas.yml up -d

# Run tests
cd ~/development && python -m pytest tests/ -v
```

## Key Infrastructure

- **Secrets Management**: HashiCorp Vault (`development/vault/`)
- **Monitoring**: Prometheus + Grafana (`development/monitoring/`)
- **Security**: Multi-phase audit completed Jan 2026 (SEC-004 through SEC-012)
- **CI/CD**: GitHub Actions, Docker Compose profiles
- **MCP Servers**: 13 configured (financial, stochastic, filesystem, memory, etc.)

## Security

- All secrets managed through Vault or environment variables
- Pre-commit hooks enforce secret scanning
- Seven-layer security architecture documented
- SOC2/ISO 27001/D3FEND compliance framework in place

---

*Last Updated: January 2026*
