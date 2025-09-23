# Contributing to Projects Monorepo

Welcome to the Projects Monorepo! This guide will help you understand our workspace structure and development workflow.

## 🏗️ Workspace Structure

```
projects/
├── packages/           # Shared component libraries
│   ├── shared/        # Common utilities and types
│   ├── stochastic-components/  # Stochastic visualization components
│   └── random-walk-components/ # Random walk components
├── agents/            # Multi-agent systems
│   └── multi-agent-observatory/
├── financial-apps/    # Financial applications
│   ├── financial-simulator/
│   └── tldraw-demo/
├── mcp-servers/      # Model Context Protocol servers
│   ├── financial-stochastic-mcp/
│   ├── financial-localization-mcp/
│   ├── multidimensional-stochastic-mcp/
│   └── random-walk-mcp/
└── scripts/          # Build and development scripts
```

## 🚀 Development Setup

### Prerequisites
- Node.js >= 18.0.0
- npm >= 9.0.0

### Installation
```bash
cd projects
npm install
```

This will install dependencies for all workspaces automatically.

## 📋 Available Scripts

### Core Commands
- `npm run build` - Build all packages in dependency order
- `npm run build:parallel` - Build packages in parallel (faster)
- `npm run dev` - Start development mode for all packages
- `npm run dev:parallel` - Start parallel development servers
- `npm run check` - Run linting, type checking, and tests
- `npm run typecheck` - Type check all TypeScript code
- `npm run lint` - Lint all JavaScript/TypeScript files
- `npm run test` - Run tests across all packages
- `npm run clean` - Clean build artifacts

### Version Management
- `npm run changeset` - Create a new changeset for versioning
- `npm run version` - Apply changesets and update versions
- `npm run release` - Publish packages

### Workspace Management
- `npm run status` - Show workspace dependency tree
- `npm run start:agents` - Start Docker services for agents
- `npm run stop:agents` - Stop Docker services

## 🔄 Development Workflow

### 1. Making Changes
1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes in the appropriate workspace
3. Test your changes: `npm run check`
4. Create a changeset if needed: `npm run changeset`

### 2. Package Dependencies
- **Internal dependencies**: Use `@monorepo/*` scoped packages
- **External dependencies**: Add to individual package.json files
- **Shared dependencies**: Add to root package.json

### 3. TypeScript Configuration
- Packages extend the root `tsconfig.json`
- Each package builds to its own `dist/` directory
- Type declarations are generated automatically

### 4. Testing
- Unit tests: Place in `src/__tests__/` or `tests/` directories
- Integration tests: Use workspace-level test commands
- End-to-end tests: Run from individual package directories

## 📦 Creating New Packages

### Component Package Template
```json
{
  "name": "@monorepo/your-package",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch",
    "clean": "rm -rf dist"
  },
  "dependencies": {
    "@monorepo/shared": "^1.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
```

### TypeScript Configuration
```json
{
  "extends": "../../tsconfig.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src",
    "declaration": true,
    "declarationMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## 🧪 Testing Guidelines

### Unit Tests
- Use Jest or your preferred testing framework
- Place tests close to source code
- Mock external dependencies
- Aim for 80%+ code coverage

### Integration Tests
- Test package interactions
- Use real dependencies where possible
- Test error conditions
- Validate API contracts

## 📋 Code Quality

### Pre-commit Hooks
- ESLint automatically fixes issues
- TypeScript compilation is validated
- Prettier formats code automatically

### CI/CD Pipeline
- Tests run on Node.js 18, 20, and 22
- Security audits check for vulnerabilities
- Builds verify all packages compile correctly

## 🐛 Troubleshooting

### Common Issues

**Build failures:**
```bash
npm run clean
npm install
npm run build:parallel
```

**Type errors:**
```bash
npm run typecheck
# Fix errors, then rebuild
npm run build
```

**Dependency conflicts:**
```bash
rm -rf node_modules package-lock.json
npm install
```

### Getting Help
- Check existing issues in the repository
- Review workspace structure and dependencies
- Run `npm run status` to understand package relationships

## 📚 Architecture Decisions

### Why NPM Workspaces?
- **Simplified dependency management**: Single lock file
- **Efficient builds**: Shared node_modules
- **Type safety**: Direct TypeScript references
- **Development speed**: Parallel operations

### Why Changesets?
- **Semantic versioning**: Automated version bumps
- **Release notes**: Generated changelogs
- **Coordination**: Manages inter-package dependencies

### Package Organization
- **`packages/`**: Reusable components and utilities
- **`agents/`**: Standalone applications and services
- **`financial-apps/`**: End-user applications
- **`mcp-servers/`**: Protocol-specific servers

---

Thank you for contributing! 🎉