# Architecture Documentation

## System Overview

The projects monorepo implements a **multi-agent, event-driven architecture** designed for scalable financial modeling and stochastic process simulation. The system is built around the principle of **composable, reusable components** that can be orchestrated by intelligent agents.

## Core Principles

### 1. Agent-Based Development Workflow
Our development process leverages specialized AI agents for different aspects of the system:

- **Documentation Agent**: Maintains comprehensive project documentation
- **Testing Agent**: Ensures code quality and test coverage
- **Build Agent**: Optimizes build processes and performance
- **Component Agent**: Develops reusable React components
- **MCP Agent**: Manages Model Context Protocol servers

### 2. Modular Component Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│          financial-simulator    │    tldraw-demo            │
├─────────────────────────────────┼───────────────────────────┤
│                    Component Layer                          │
├─────────────────────────────────────────────────────────────┤
│  stochastic-components  │   random-walk-components          │
├─────────────────────────┼───────────────────────────────────┤
│                    Service Layer                           │
├─────────────────────────────────────────────────────────────┤
│  MCP Servers: financial-stochastic, random-walk, etc.      │
├─────────────────────────────────────────────────────────────┤
│                    Foundation Layer                        │
├─────────────────────────────────────────────────────────────┤
│              @monorepo/shared (utilities & types)          │
└─────────────────────────────────────────────────────────────┘
```

### 3. Event-Driven Communication
The system uses multiple communication patterns:

- **NPM Workspaces**: Package dependency management
- **TypeScript Project References**: Build-time type sharing
- **Model Context Protocol**: Runtime service communication
- **React Context**: State management within applications
- **Event Emitters**: Agent coordination

## Workspace Architecture

### Packages (`packages/`)
**Purpose**: Reusable libraries and components

| Package | Description | Dependencies |
|---------|-------------|-------------|
| `@monorepo/shared` | Common utilities, types, and constants | None |
| `@monorepo/stochastic-components` | React components for stochastic modeling | shared, react, mathjs |
| `@monorepo/random-walk-components` | Random walk visualization components | shared, react, recharts |

**Key Features**:
- TypeScript strict mode enabled
- Comprehensive type exports
- Tree-shakeable exports
- Unit test coverage > 80%

### Applications (`financial-apps/`)
**Purpose**: End-user applications and demos

| Application | Technology Stack | Purpose |
|-------------|------------------|---------|
| `financial-simulator` | React 19 + Vite + TypeScript | Interactive financial modeling |
| `tldraw-demo` | tldraw + React + TypeScript | Visual modeling and drawing |
| `financial-stochastic-webapp` | Streamlit + Python | Advanced analytics dashboard |

**Architecture Patterns**:
- **Component Composition**: Leverages shared component libraries
- **State Management**: React Context + useReducer patterns
- **Data Flow**: Unidirectional data flow with immutable updates
- **Error Boundaries**: Comprehensive error handling

### MCP Servers (`mcp-servers/`)
**Purpose**: Model Context Protocol service implementations

| Server | Protocol | Capabilities |
|--------|----------|-------------|
| `financial-stochastic-mcp` | MCP v1.0 | Stochastic process modeling |
| `random-walk-mcp` | MCP v1.0 | Random walk generation |
| `multidimensional-stochastic-mcp` | MCP v1.0 | Multi-dimensional modeling |
| `financial-localization-mcp` | MCP v1.0 | Localization services |

**Key Features**:
- **Protocol Compliance**: Full MCP specification adherence
- **Type Safety**: Generated TypeScript types from schemas
- **Scalability**: Horizontal scaling support
- **Observability**: Comprehensive logging and metrics

### Agents (`agents/`)
**Purpose**: Multi-agent system orchestration

| Agent System | Purpose | Technology |
|-------------|---------|------------|
| `multi-agent-observatory` | Agent coordination and monitoring | Node.js + WebSockets |
| `director-agent` | System orchestration | Python + Redis |
| `ui-ux-agent` | User interface automation | React + Playwright |
| `von_neumann_agent` | Self-replicating system patterns | TypeScript + Docker |

**Communication Patterns**:
- **Message Queues**: Redis-based async communication
- **WebSocket**: Real-time agent coordination
- **REST APIs**: Service integration
- **Event Streams**: System-wide event propagation

## Build Architecture

### TypeScript Project References
Enables incremental compilation and dependency resolution:

```json
{
  "references": [
    { "path": "./packages/shared" },
    { "path": "./packages/stochastic-components" },
    { "path": "./packages/random-walk-components" }
  ]
}
```

**Benefits**:
- 40% faster incremental builds
- Automatic dependency resolution
- Type-safe cross-package imports
- Parallel compilation support

### Build Pipeline
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Source    │───▶│  TypeScript │───▶│   Bundle    │
│   Files     │    │  Compiler   │    │  Optimizer  │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    ESLint   │    │    Jest     │    │   Deploy    │
│  Validation │    │   Testing   │    │   Target    │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Performance Optimizations (2024)

#### Build Performance
- **Parallel Builds**: 3x faster full workspace builds
- **Incremental Compilation**: TypeScript project references
- **Bundle Splitting**: Code splitting with dynamic imports
- **Tree Shaking**: Dead code elimination

#### Runtime Performance
- **React 19**: Concurrent features and automatic batching
- **Lazy Loading**: Component-level code splitting
- **Memoization**: Strategic use of React.memo and useMemo
- **Virtual Scrolling**: For large data sets

## Data Flow Architecture

### Component Data Flow
```
┌─────────────────┐
│   User Input    │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐    ┌─────────────────┐
│  React Context  │───▶│   Components    │
└─────────┬───────┘    └─────────────────┘
          │
          ▼
┌─────────────────┐    ┌─────────────────┐
│  MCP Services   │◄───│   API Layer     │
└─────────────────┘    └─────────────────┘
```

### State Management Patterns

#### Local State
- **useState**: Simple component state
- **useReducer**: Complex state logic
- **useRef**: DOM references and mutable values

#### Shared State
- **React Context**: App-wide state sharing
- **Custom Hooks**: Reusable state logic
- **Event Emitters**: Cross-component communication

#### Server State
- **MCP Protocol**: Service communication
- **REST APIs**: External data fetching
- **WebSockets**: Real-time updates

## Testing Architecture

### Test Structure
```
├── __tests__/
│   ├── unit/           # Unit tests (Jest)
│   ├── integration/    # Integration tests
│   ├── e2e/           # End-to-end tests (Playwright)
│   └── visual/        # Visual regression tests
```

### Testing Strategies

#### Unit Testing
- **Jest**: Test runner and framework
- **Testing Library**: React component testing
- **Mock Service Worker**: API mocking
- **Coverage Target**: 80%+ line coverage

#### Integration Testing
- **Multi-package**: Cross-workspace integration
- **Service Testing**: MCP server validation
- **Database Testing**: In-memory test databases

#### End-to-End Testing
- **User Workflows**: Complete user journeys
- **Cross-browser**: Multiple browser support
- **Visual Regression**: UI consistency validation

## Security Architecture

### Package Security
- **Dependency Scanning**: Automated vulnerability detection
- **Type Safety**: TypeScript prevents runtime errors
- **ESLint Rules**: Security-focused linting rules
- **Audit Pipeline**: Regular security audits

### Runtime Security
- **Input Validation**: All user inputs validated
- **Error Boundaries**: Graceful error handling
- **HTTPS Only**: Secure communication protocols
- **Environment Variables**: Secure configuration management

## Deployment Architecture

### Development
```
┌─────────────────┐    ┌─────────────────┐
│  Local Dev      │───▶│   Hot Reload    │
│  Environment    │    │   (Vite/Webpack)│
└─────────────────┘    └─────────────────┘
```

### Production
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Build Step    │───▶│   Docker Image  │───▶│  Container      │
│  (CI/CD)        │    │   Creation      │    │  Orchestration  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Container Strategy
- **Multi-stage Builds**: Optimized image sizes
- **Layer Caching**: Faster build times
- **Health Checks**: Container monitoring
- **Horizontal Scaling**: Load balancing support

## Monitoring and Observability

### Metrics Collection
- **Build Metrics**: Compilation times and success rates
- **Runtime Metrics**: Performance and error rates
- **Usage Analytics**: Component and feature usage
- **Business Metrics**: Financial modeling accuracy

### Logging Strategy
- **Structured Logging**: JSON format with correlation IDs
- **Log Levels**: Appropriate verbosity for each environment
- **Centralized Logging**: Aggregated log collection
- **Alert Integration**: Automated issue detection

## Future Architecture Considerations

### Scalability Improvements
- **Micro-frontends**: Independent application deployment
- **Service Mesh**: Advanced service communication
- **Event Sourcing**: Complete system state reconstruction
- **CQRS**: Command and query responsibility separation

### Technology Evolution
- **React Server Components**: Server-side rendering improvements
- **WebAssembly**: High-performance computation
- **Edge Computing**: Distributed deployment strategies
- **Machine Learning**: AI-driven optimizations

---

This architecture supports our mission of building scalable, maintainable financial modeling tools while leveraging modern development practices and agent-based workflows.