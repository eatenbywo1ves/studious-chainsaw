# Projects Monorepo

A comprehensive monorepo for multi-agent systems, financial applications, and stochastic modeling components.

## 🌟 Overview

This monorepo contains a collection of TypeScript/JavaScript packages organized around financial modeling, stochastic processes, and multi-agent systems. Built with modern tooling and designed for scalability.

### Key Features
- 🏗️ **NPM Workspaces** - Efficient dependency management
- ⚡ **Parallel Builds** - Fast development and CI/CD
- 🔒 **Type Safety** - Full TypeScript support with project references
- 🚀 **Modern Tooling** - ESLint, Prettier, Husky, Changesets
- 🐳 **Docker Ready** - Container support for agents and services
- 📊 **Financial Modeling** - Advanced stochastic process libraries

## 📦 Packages

### Core Libraries (`packages/`)
- **[@monorepo/shared](packages/shared/)** - Common utilities and types
- **[@monorepo/stochastic-components](packages/stochastic-components/)** - Multidimensional stochastic visualization
- **[@monorepo/random-walk-components](packages/random-walk-components/)** - Random walk analysis tools

### Applications (`financial-apps/`)
- **[financial-simulator](financial-apps/financial-simulator/)** - React-based financial modeling application
- **[tldraw-demo](financial-apps/tldraw-demo/)** - Interactive drawing and visualization tools

### Services (`mcp-servers/`)
- **[financial-stochastic-mcp](mcp-servers/financial-stochastic-mcp/)** - Stochastic process MCP server
- **[financial-localization-mcp](mcp-servers/financial-localization-mcp/)** - Localization services
- **[multidimensional-stochastic-mcp](mcp-servers/multidimensional-stochastic-mcp/)** - Multi-dimensional modeling
- **[random-walk-mcp](mcp-servers/random-walk-mcp/)** - Random walk generation service

### Multi-Agent Systems (`agents/`)
- **[multi-agent-observatory](agents/multi-agent-observatory/)** - Agent coordination and monitoring

## 🚀 Quick Start

### Prerequisites
- **Node.js** >= 18.0.0
- **npm** >= 9.0.0
- **Docker** (optional, for agent services)

### Installation
```bash
git clone <repository-url>
cd projects
npm install
```

### Development
```bash
# Start all development services
npm run dev:parallel

# Or start specific components
npm run dev --workspace=@monorepo/stochastic-components

# Build all packages
npm run build:parallel

# Run quality checks
npm run check
```

### Testing
```bash
# Run all tests
npm run test

# Type checking
npm run typecheck

# Linting
npm run lint
```

## 🏗️ Architecture

### Workspace Structure
```
├── packages/           # Reusable component libraries
├── financial-apps/    # End-user applications
├── mcp-servers/       # Model Context Protocol servers
├── agents/            # Multi-agent systems
├── scripts/           # Build and utility scripts
└── .github/           # CI/CD workflows
```

### Dependency Graph
```
┌─────────────────┐
│  Applications   │ ─┐
└─────────────────┘  │
                     ▼
┌─────────────────┐  ┌─────────────────┐
│   Components    │◄─│     Shared      │
└─────────────────┘  └─────────────────┘
                     ▲
┌─────────────────┐  │
│   MCP Servers   │ ─┘
└─────────────────┘
```

### Technology Stack
- **Frontend**: React 19, TypeScript, Vite, TailwindCSS
- **Backend**: Node.js, Express, Model Context Protocol
- **Build**: NPM Workspaces, ESBuild, TypeScript Project References
- **Quality**: ESLint, Prettier, Husky, Changesets
- **CI/CD**: GitHub Actions, Docker
- **Visualization**: Recharts, D3.js (via custom components)

## 📋 Scripts Reference

### Build Commands
| Command | Description |
|---------|-------------|
| `npm run build` | Build all packages sequentially |
| `npm run build:parallel` | Build packages in parallel (recommended) |
| `npm run clean` | Remove all build artifacts |

### Development Commands
| Command | Description |
|---------|-------------|
| `npm run dev` | Start development mode for all packages |
| `npm run dev:parallel` | Start parallel development servers |
| `npm run start:all` | Start both agents and development servers |

### Quality Commands
| Command | Description |
|---------|-------------|
| `npm run check` | Run lint + typecheck + test |
| `npm run lint` | Lint all TypeScript/JavaScript files |
| `npm run typecheck` | Type check without emitting |
| `npm run test` | Run all tests |

### Version Management
| Command | Description |
|---------|-------------|
| `npm run changeset` | Create a new changeset |
| `npm run version` | Apply changesets and bump versions |
| `npm run release` | Publish packages to registry |

### Utility Commands
| Command | Description |
|---------|-------------|
| `npm run status` | Show workspace dependency tree |
| `npm run start:agents` | Start Docker services |
| `npm run stop:agents` | Stop Docker services |

## 🔧 Configuration

### TypeScript
- **Project References**: Enabled for fast incremental builds
- **Strict Mode**: All packages use strict TypeScript settings
- **Path Mapping**: Direct imports between workspace packages

### ESLint
- **React Hooks**: Enforced for all React components
- **TypeScript**: Full TypeScript-aware linting
- **Import Organization**: Automatic import sorting

### Prettier
- **Consistent Formatting**: Applied to all TypeScript, JavaScript, JSON, and Markdown files
- **Pre-commit Hooks**: Automatic formatting on commit

## 🚢 Deployment

### Docker Support
```bash
# Build agent services
npm run start:agents

# Stop services
npm run stop:agents
```

### CI/CD Pipeline
- **GitHub Actions**: Automated testing on Node 18, 20, 22
- **Security Audits**: Automatic vulnerability scanning
- **Build Verification**: All packages must compile successfully

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for detailed information about:
- Development workflow
- Code quality standards
- Testing guidelines
- Package creation process

### Quick Contribution Guide
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm run check` to verify quality
5. Create a changeset: `npm run changeset`
6. Submit a pull request

## 📚 Documentation

### Package Documentation
- **Core Libraries**: Complete API docs with TypeScript type definitions
- **React Components**: Storybook integration and component examples
- **MCP Servers**: Protocol specifications and usage guides
- **Applications**: User guides and deployment instructions

### Architecture Documentation
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development workflow and guidelines
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design and agent-based workflow
- [BUILD_OPTIMIZATION.md](BUILD_OPTIMIZATION_REPORT.md) - Performance improvements and metrics
- [API_DOCUMENTATION.md](docs/api/README.md) - Generated TypeDoc API references
- [TESTING.md](docs/TESTING.md) - Testing strategies and best practices
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - Common issues and solutions

### Recent Optimizations (2024)
- **React 19 Upgrade**: Latest React features and performance improvements
- **TypeScript Project References**: 40% faster incremental builds
- **Jest Testing Framework**: Comprehensive test coverage across workspaces
- **Build Optimization**: Parallel builds and bundle size reduction
- **ESLint Configuration**: Modern linting with React 19 support

## 🐛 Troubleshooting

### Common Issues

**Installation problems:**
```bash
rm -rf node_modules package-lock.json
npm install
```

**Build failures:**
```bash
npm run clean
npm run build:parallel
```

**Type errors:**
```bash
npm run typecheck
# Review and fix errors, then rebuild
```

### Performance Tips
- Use `npm run build:parallel` for faster builds
- Enable TypeScript incremental compilation
- Use `npm ci` instead of `npm install` in CI/CD

## 📊 Metrics

### Workspace Stats
- **Packages**: 10 total (3 libraries, 2 apps, 4 services, 1 agent system)
- **Dependencies**: Shared and optimized across workspaces
- **Build Time**: ~30s for full parallel build
- **Test Coverage**: Varies by package (aim for 80%+)

### Performance
- **Cold Build**: ~45s (full workspace)
- **Incremental Build**: ~5-15s (changed packages only)
- **Development Reload**: <3s (hot module replacement)

## 📄 License

This project is licensed under the MIT License - see individual package licenses for details.

## 🙏 Acknowledgments

- Built with [NPM Workspaces](https://docs.npmjs.com/cli/v7/using-npm/workspaces)
- Version management by [Changesets](https://github.com/changesets/changesets)
- CI/CD powered by [GitHub Actions](https://github.com/features/actions)
- Code quality enforced by [ESLint](https://eslint.org/) and [Prettier](https://prettier.io/)

---

**Happy coding!** 🎉