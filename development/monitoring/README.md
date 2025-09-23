# Development Environment Monitoring System

A comprehensive monitoring solution for development environments, providing health checks, performance monitoring, alerting, and real-time dashboards.

## Features

- **Health Check Endpoints**: Automatic health monitoring for all MCP servers and services
- **Performance Monitoring**: Real-time CPU, memory, disk, and network monitoring
- **Build Monitoring**: Track build times, success rates, and test execution
- **Real-time Dashboard**: Web-based dashboard with live updates
- **Alerting System**: Configurable alerts with multiple notification channels
- **Monitoring Scripts**: Standalone utilities for health checks and build monitoring

## Quick Start

1. **Install Dependencies**:
   ```bash
   cd C:/Users/Corbin/development/monitoring
   npm install
   ```

2. **Start the Monitoring System**:
   ```bash
   npm start
   ```

3. **Access the Dashboard**:
   Open http://localhost:3002 in your browser

## Components

### 1. Health Check System

- **Base Health Check Module**: `health-check.js`
- **Service Health Checker**: `health-checker.js`
- **MCP Server Integration**: Automatic health endpoints for all MCP servers

**Usage**:
```bash
# Check all services once
npm run health

# Continuous monitoring
npm run health:watch
```

### 2. Performance Monitoring

- **Performance Monitor**: `performance-monitor.js`
- **Real-time Metrics**: CPU, Memory, Disk, Network
- **Service Response Times**: HTTP endpoint monitoring
- **Build and Test Metrics**: Duration tracking and success rates

**Metrics Collected**:
- System CPU usage percentage
- Memory usage (process and system)
- Disk usage and accessibility
- Service availability and response times
- Build duration and success rates
- Test execution times and results

### 3. Monitoring Dashboard

- **Dashboard Server**: `dashboard.js`
- **Real-time Updates**: WebSocket-based live data
- **Interactive Charts**: CPU and memory usage over time
- **Service Status**: Visual service health indicators
- **Alert Management**: View and manage active alerts

**Features**:
- Responsive web interface
- Real-time charts using Chart.js
- Service status indicators
- Build and test metrics display
- Alert notifications
- Data export (JSON, CSV, Prometheus)

### 4. Alerting System

- **Alert Engine**: `alerting-system.js`
- **Multiple Channels**: Console, File, Webhook, Email (configurable)
- **Alert Rules**: Filtering, routing, and escalation
- **Cooldown Protection**: Prevent alert flooding

**Alert Types**:
- High CPU usage (>80%)
- High memory usage (>85%)
- Service unavailability
- Slow response times (>5s)
- Build failures
- Test failures

### 5. Build Monitoring

- **Build Monitor**: `build-monitor.js`
- **Test Execution**: Monitor test runs and results
- **File Watching**: Auto-rebuild on file changes
- **Metrics Tracking**: Build times and success rates

**Usage**:
```bash
# Run single build
npm run build [project-path] [build-command]

# Run tests
npm run test [project-path] [test-command]

# Watch for changes
npm run watch [project-path] [build-command] [test-command]
```

## Configuration

### Monitor Configuration (`monitor-config.js`)

```javascript
module.exports = {
    // Monitoring interval (5 seconds)
    interval: 5000,
    
    // Services to monitor
    services: [
        {
            name: 'webhook-audio-tracker',
            type: 'express',
            healthUrl: 'http://localhost:3000/health',
            port: 3000
        },
        // ... more services
    ],
    
    // Alert thresholds
    thresholds: {
        cpu: 80,
        memory: 85,
        disk: 90,
        responseTime: 5000
    },
    
    // Dashboard settings
    dashboard: {
        port: 3002,
        refreshInterval: 5000
    }
};
```

### Adding New Services

1. Add service configuration to `monitor-config.js`:
   ```javascript
   {
       name: 'my-service',
       type: 'express', // or 'mcp'
       healthUrl: 'http://localhost:8080/health', // for HTTP services
       port: 8080,
       processName: 'node', // for process monitoring
       description: 'My Custom Service'
   }
   ```

2. For MCP servers, ensure they include the health check module:
   ```javascript
   const HealthCheck = require('./health-check');
   // Add health endpoint to your server
   ```

## API Endpoints

### Dashboard API

- `GET /api/metrics?range=3600000` - Get metrics for time range
- `GET /api/status` - Get current system status
- `GET /api/alerts` - Get active alerts
- `GET /api/export/json` - Export metrics as JSON
- `GET /api/export/csv` - Export metrics as CSV
- `GET /api/export/prometheus` - Export metrics in Prometheus format

### Health Endpoints

Each monitored service exposes:
- `/health` - Basic health status
- `/metrics` - Detailed performance metrics

## Alerting

### Alert Channels

1. **Console**: Colored output to terminal
2. **File**: JSON log entries to `logs/alerts.log`
3. **Webhook**: HTTP POST to configured endpoint
4. **Email**: Email notifications (requires setup)
5. **Slack**: Slack channel notifications (requires setup)

### Alert Rules

Configure custom alert rules in `monitor-config.js`:

```javascript
alerting: {
    enabled: true,
    channels: ['console', 'file', 'webhook'],
    rules: [
        {
            type: 'filter',
            conditions: { severity: 'info' },
            action: 'suppress'
        },
        {
            type: 'routing',
            conditions: { severity: 'critical' },
            channels: ['webhook', 'email']
        }
    ]
}
```

## Monitoring Scripts

### Health Checker
```bash
# Single check
node health-checker.js

# Continuous monitoring
node health-checker.js --watch --interval 30000
```

### Build Monitor
```bash
# Monitor build
node build-monitor.js build ./my-project "npm run build"

# Monitor tests
node build-monitor.js test ./my-project "npm test"

# Watch project for changes
node build-monitor.js watch ./my-project "npm run build" "npm test"
```

## Data Export

### Export Formats

1. **JSON**: Complete metrics data
2. **CSV**: Simplified metrics for spreadsheets
3. **Prometheus**: Compatible with Prometheus monitoring

### Automated Exports

Configure automatic exports in `monitor-config.js`:

```javascript
export: {
    formats: ['json', 'csv', 'prometheus'],
    schedule: '0 0 * * *', // Daily at midnight
    retention: 7 // Keep 7 days
}
```

## Troubleshooting

### Common Issues

1. **Dashboard not loading**: Check if port 3002 is available
2. **Services not detected**: Verify service configuration in `monitor-config.js`
3. **High memory usage**: Adjust retention settings to reduce data storage

### Logs

Monitor logs in:
- `logs/monitoring.log` - General monitoring logs
- `logs/alerts.log` - Alert history
- `reports/` - Status reports

### Debug Mode

Run with debug output:
```bash
DEBUG=* npm start
```

## Integration

### With Existing Services

Add health endpoints to your services:

```javascript
// Express.js example
const HealthCheck = require('./health-check');
const health = new HealthCheck('my-service', '1.0.0');

app.get('/health', health.middleware());
```

### With CI/CD

Use health checker in build pipelines:

```bash
# Check health before deployment
npm run health || exit 1

# Monitor build
npm run build && npm run test
```

## Performance Impact

- **CPU Usage**: <1% during normal operation
- **Memory Usage**: ~50MB for monitoring system
- **Disk Usage**: Configurable retention (default 24h)
- **Network**: Minimal impact from health checks

## Security Considerations

- Dashboard runs on localhost by default
- No authentication required for local development
- Configure firewall rules for production use
- Sensitive data not logged by default

## Support

For issues or questions:
1. Check logs in `logs/` directory
2. Verify configuration in `monitor-config.js`
3. Test individual components separately
4. Review service status in dashboard

## License

MIT License - see LICENSE file for details.