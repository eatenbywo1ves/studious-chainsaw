# Monorepo Project Structure

This project has been organized as a monorepo with workspaces, combining TypeScript components, Python agents, and MCP servers for parallel development and execution.

## Project Structure

```
projects/
├── packages/                    # Shared TypeScript packages
│   ├── shared/                 # Common utilities and types
│   ├── stochastic-components/ # Stochastic process visualizations
│   └── random-walk-components/ # Random walk visualizations
├── agents/                     # Python-based agent systems
│   ├── director-agent/        # Orchestration agent with Redis
│   ├── ui-ux-agent/          # UI/UX specialized agent
│   └── multi-agent-observatory/ # Multi-agent monitoring system
├── financial-apps/            # Financial applications
│   ├── financial-simulator/  # Financial simulation app
│   └── financial-stochastic-webapp/ # Stochastic web app
├── mcp-servers/              # Model Context Protocol servers
│   ├── financial-stochastic-mcp/
│   ├── multidimensional-stochastic-mcp/
│   └── random-walk-mcp/
└── scripts/                  # Build and automation scripts
    ├── build-all.js         # Parallel build script
    └── run-parallel.js      # Parallel execution script
```

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Build All Packages
```bash
# Sequential build
npm run build

# Parallel build (faster)
npm run build:parallel
```

### 3. Start All Services
```bash
# Start everything (Docker + Node services)
npm run start:all

# Or start individually:
npm run start:agents   # Start Docker services
npm run dev:parallel   # Start Node.js services
```

## Available Commands

### Root Level Commands
- `npm run build` - Build all workspaces sequentially
- `npm run build:parallel` - Build all workspaces in parallel
- `npm run dev` - Start dev mode for all workspaces
- `npm run dev:parallel` - Start all services in parallel
- `npm run test` - Run tests in all workspaces
- `npm run lint` - Lint all TypeScript/JavaScript files
- `npm run typecheck` - Type check all TypeScript files
- `npm run clean` - Clean all build artifacts
- `npm run start:agents` - Start Docker containers
- `npm run stop:agents` - Stop Docker containers
- `npm run status` - Show workspace status

## Working with Workspaces

### Adding Dependencies to a Specific Workspace
```bash
npm install <package> -w @monorepo/shared
```

### Running Commands in Specific Workspaces
```bash
npm run build -w @monorepo/stochastic-components
npm run test -w agents/director-agent
```

### Cross-Workspace Dependencies
Packages can depend on each other:
```json
{
  "dependencies": {
    "@monorepo/shared": "^1.0.0"
  }
}
```

## Docker Services

The project includes Docker configurations for Python agents:

### Services
- **redis** - Message broker for agent communication
- **redis-commander** - Web UI for Redis monitoring (port 8081)
- **director-agent** - Main orchestration agent (port 8000)
- **ui-ux-agent** - UI/UX agent with WebSocket (port 8765)
- **observatory-server** - Multi-agent observatory (port 8080)
- **financial-simulator** - Financial simulation app (port 5173)

### Docker Management
```bash
# Start all containers
docker-compose up -d

# View logs
docker-compose logs -f [service-name]

# Stop all containers
docker-compose down

# Rebuild containers
docker-compose build
```

## Parallel Development Workflow

### 1. Development Mode
Start all services in parallel for development:
```bash
npm run dev:parallel
```

This launches:
- Director Agent (Docker)
- UI/UX Agent (Docker)
- Observatory Server
- MCP Servers
- Component watchers

### 2. Building for Production
```bash
npm run build:parallel
```

### 3. Testing Changes
Make changes to any project and the appropriate services will hot-reload.

## Port Assignments

| Service | Port | Description |
|---------|------|-------------|
| Director Agent API | 8000 | REST API |
| UI/UX Agent WebSocket | 8765 | WebSocket interface |
| Observatory Server | 8080 | Main server |
| Observatory WebSocket | 3001 | Real-time updates |
| Redis | 6379 | Message broker |
| Redis Commander | 8081 | Redis web UI |
| Financial Simulator | 5173 | Vite dev server |

## Environment Variables

Create a `.env` file in the root:
```env
NODE_ENV=development
REDIS_HOST=localhost
REDIS_PORT=6379
```

## Troubleshooting

### Port Already in Use
```bash
# Find process using port
netstat -ano | findstr :8000

# Kill process
taskkill /PID <process_id> /F
```

### Rebuild Node Modules
```bash
npm run clean
rm -rf node_modules
npm install
```

### Docker Issues
```bash
# Reset Docker environment
docker-compose down -v
docker system prune -a
docker-compose build --no-cache
docker-compose up
```

## Next Steps

1. Add more MCP servers to the workspace
2. Implement shared authentication
3. Add integration tests
4. Set up CI/CD pipeline
5. Add monitoring and logging