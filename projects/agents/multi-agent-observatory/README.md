# Multi-Agent Observability System

A real-time monitoring and observability platform for multi-agent systems with live dashboard updates.

## Architecture

- **Agents (A1-A5)**: Independent processes with monitoring hooks
- **BUN Server**: Central coordination server with WebSocket support
- **SQLite Database**: Persistent storage for metrics and events
- **Live Dashboard**: Real-time web interface

## Quick Start

```bash
# Install dependencies
npm install

# Start the system
./scripts/start-all.sh
```

## Components

### Server
- BUN.js runtime with WebSocket support
- SQLite database integration
- Real-time event broadcasting

### Agents
- Standardized monitoring hooks
- Health checks and metrics collection
- Automatic registration with server

### Dashboard
- Real-time visualization
- Agent status monitoring
- Historical data analysis

## Development

Each component can be developed and tested independently:

```bash
# Start server only
cd server && bun run dev

# Start specific agent
cd agents/agent-1 && npm start

# Start dashboard
cd dashboard && npm run dev
```

## Monitoring Features

- Agent health and status tracking
- Performance metrics (CPU, memory, network)
- Custom event logging and correlation
- Real-time alerting system