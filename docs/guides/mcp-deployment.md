# MCP Servers Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying MCP servers in a production environment with high availability, monitoring, and automated management.

## Deployment Options

### Option 1: PM2 Process Manager (Recommended for Windows)

PM2 provides automatic restarts, monitoring, and log management.

#### Installation

```powershell
# Install dependencies
npm install -g pm2
npm install -g pm2-windows-startup

# Install MCP server dependencies
powershell -ExecutionPolicy Bypass -File deploy-mcp-production.ps1 -Action install
```

#### Starting Servers

```powershell
# Start all servers
powershell -ExecutionPolicy Bypass -File deploy-mcp-production.ps1 -Action start

# Start specific server
powershell -ExecutionPolicy Bypass -File deploy-mcp-production.ps1 -Action start -Server mcp-filesystem

# View status
powershell -ExecutionPolicy Bypass -File deploy-mcp-production.ps1 -Action status
```

#### Monitoring

```powershell
# View real-time logs
pm2 logs

# Monitor resources
pm2 monit

# View detailed status
pm2 list
```

### Option 2: Docker Deployment (Cross-platform)

Docker provides isolation, resource limits, and easy scaling.

#### Prerequisites

- Docker Desktop installed
- Docker Compose installed

#### Deployment

```bash
# Build and start all services
docker-compose -f docker-compose.production.yml up -d

# View status
docker-compose -f docker-compose.production.yml ps

# View logs
docker-compose -f docker-compose.production.yml logs -f

# Stop services
docker-compose -f docker-compose.production.yml down
```

### Option 3: Windows Service

Run MCP servers as Windows services for automatic startup.

```powershell
# Install as Windows service
pm2 save
pm2 startup
pm2-installer

# The services will now start automatically on boot
```

## Configuration Files

### 1. `mcp-production-config.yaml`

Main configuration file containing:
- Server settings
- Resource limits
- Health check intervals
- Logging configuration
- Security settings

### 2. `ecosystem.config.js`

PM2 configuration for process management:
- Memory limits
- Restart policies
- Log file locations
- Environment variables

### 3. `docker-compose.production.yml`

Docker deployment configuration:
- Service definitions
- Resource constraints
- Network configuration
- Volume mappings

## Server Endpoints

| Server | Port | Purpose | Health Check |
|--------|------|---------|--------------|
| Filesystem | 3000 | File operations | `/health` |
| Financial Localization | 3001 | Currency formatting | `/health` |
| Financial Stochastic | 3002 | Stochastic models | `/health` |
| Multidimensional | 3003 | High-dim computations | `/health` |
| Random Walk | 3004 | Random processes | `/health` |
| Adaptive Control | 3005 | Control systems | `/health` |

## Monitoring

### Health Monitoring

Start the health monitor:

```bash
node mcp-health-monitor.js
```

Access monitoring endpoints:
- `http://localhost:9091/metrics` - Prometheus metrics
- `http://localhost:9091/health` - Overall health status
- `http://localhost:9091/alerts` - Recent alerts

### Prometheus & Grafana

1. **Prometheus** (Port 9090)
   - Collects metrics from all servers
   - 30-day retention
   - Alerting rules

2. **Grafana** (Port 3000)
   - Visual dashboards
   - Real-time monitoring
   - Alert notifications

Access Grafana: `http://localhost:3000` (admin/admin)

## Resource Management

### Memory Limits

| Server | Development | Production |
|--------|-------------|------------|
| Filesystem | 256MB | 512MB |
| Financial Localization | 128MB | 256MB |
| Financial Stochastic | 512MB | 1GB |
| Multidimensional | 1GB | 2GB |
| Random Walk | 256MB | 512MB |
| Adaptive Control | 512MB | 1GB |

### CPU Limits

- Light servers: 0.25-0.5 CPU
- Medium servers: 1.0 CPU
- Heavy servers: 2.0 CPU

## Security Best Practices

1. **Environment Variables**
   - Never commit secrets to git
   - Use `.env` files (gitignored)
   - Rotate keys regularly

2. **Network Security**
   - Use HTTPS in production
   - Implement rate limiting
   - Configure CORS properly

3. **Access Control**
   - API key authentication
   - JWT for stateless auth
   - IP whitelisting for admin endpoints

## Backup & Recovery

### Automated Backups

```powershell
# Create backup script
$backupScript = @"
# Daily backup of logs and data
$date = Get-Date -Format "yyyy-MM-dd"
$backupDir = "C:\Users\Corbin\mcp-backups\$date"
New-Item -ItemType Directory -Path $backupDir -Force

# Backup logs
Copy-Item -Path "C:\Users\Corbin\logs\*" -Destination "$backupDir\logs" -Recurse

# Backup configurations
Copy-Item -Path "*.yaml", "*.json", "*.js" -Destination "$backupDir\config"

# Compress
Compress-Archive -Path $backupDir -DestinationPath "$backupDir.zip"
Remove-Item -Path $backupDir -Recurse
"@

# Schedule daily backup
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File backup-mcp.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "MCP Backup" -Action $action -Trigger $trigger
```

### Recovery Procedures

1. **Service Failure**
   - PM2 automatically restarts failed services
   - Maximum 5 restarts before marking as failed
   - Manual intervention required after max restarts

2. **Data Recovery**
   - Restore from latest backup
   - Check logs for corruption
   - Validate configuration files

## Troubleshooting

### Common Issues

1. **Server won't start**
   - Check port availability: `netstat -an | findstr :300`
   - Verify dependencies: `npm list`
   - Check logs: `pm2 logs [server-name]`

2. **High memory usage**
   - Monitor with: `pm2 monit`
   - Adjust limits in ecosystem.config.js
   - Enable memory profiling

3. **Connection refused**
   - Check firewall rules
   - Verify server is running: `pm2 list`
   - Test health endpoint: `curl http://localhost:3001/health`

### Debug Mode

Enable debug logging:

```powershell
# Set environment variable
$env:DEBUG = "*"
$env:LOG_LEVEL = "debug"

# Restart servers
pm2 restart all
```

## Performance Optimization

### 1. Enable Clustering

```javascript
// In ecosystem.config.js
{
  name: 'mcp-server',
  instances: 'max', // Use all CPU cores
  exec_mode: 'cluster'
}
```

### 2. Cache Configuration

```yaml
# In production config
cache:
  enabled: true
  ttl: 3600
  max_size: 1000
```

### 3. Database Connection Pooling

```javascript
// If using database
pool: {
  min: 2,
  max: 10,
  idle: 30000
}
```

## Scaling

### Horizontal Scaling

1. **Load Balancer** (NGINX)
   - Round-robin distribution
   - Health check routing
   - SSL termination

2. **Multiple Instances**
   - Run multiple server instances
   - Different ports per instance
   - Shared state via Redis

### Vertical Scaling

1. Increase resource limits
2. Optimize algorithms
3. Add GPU acceleration where applicable

## Maintenance

### Regular Tasks

- **Daily**: Check logs for errors
- **Weekly**: Review metrics and alerts
- **Monthly**: Update dependencies
- **Quarterly**: Security audit

### Update Procedure

```powershell
# 1. Backup current deployment
./backup-mcp.ps1

# 2. Update dependencies
npm update

# 3. Test in staging
$env:NODE_ENV = "staging"
pm2 restart all

# 4. Deploy to production
$env:NODE_ENV = "production"
pm2 restart all
```

## Support

### Monitoring Dashboard

Access the unified monitoring dashboard:
- Local: `http://localhost:9091/health`
- Grafana: `http://localhost:3000`
- Logs: `C:\Users\Corbin\logs\`

### Alert Channels

Configure alerts in `mcp-production-config.yaml`:
- Console logging
- File logging
- Webhook notifications
- Email alerts

### Documentation

- API Documentation: `/docs` endpoint on each server
- Configuration Reference: `mcp-production-config.yaml`
- Troubleshooting Guide: This document, section 10

## Conclusion

This production deployment provides:
- ✅ High availability with automatic restarts
- ✅ Comprehensive monitoring and alerting
- ✅ Resource management and limits
- ✅ Security best practices
- ✅ Backup and recovery procedures
- ✅ Scalability options

Follow this guide to maintain a robust, production-ready MCP server deployment.