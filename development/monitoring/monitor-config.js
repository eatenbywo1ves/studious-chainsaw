/**
 * Monitoring Configuration
 * Defines services to monitor and thresholds
 */

module.exports = {
    // Performance monitoring interval (5 seconds)
    interval: 5000,
    
    // Data retention period (24 hours)
    retention: 86400000,
    
    // Services to monitor - KA Lattice Production
    services: [
        {
            name: 'monitoring-dashboard',
            type: 'express',
            healthUrl: 'http://localhost:3002/health',
            port: 3002,
            processName: 'node',
            description: 'Monitoring Dashboard (this service)',
            enabled: true
        },
        // Uncomment services below when they are deployed:
        /*
        {
            name: 'webhook-audio-tracker',
            type: 'express',
            healthUrl: 'http://localhost:3000/health',
            port: 3000,
            processName: 'node',
            description: 'Webhook Audio Tracker MCP Server',
            enabled: false
        },
        {
            name: 'saas-api',
            type: 'express',
            healthUrl: 'http://localhost:8000/health',
            port: 8000,
            processName: 'python',
            description: 'SaaS API Server',
            enabled: false
        },
        {
            name: 'api-gateway',
            type: 'express',
            healthUrl: 'http://localhost:8080/health',
            port: 8080,
            processName: 'python',
            description: 'API Gateway',
            enabled: false
        }
        */
    ],
    
    // Alert thresholds
    thresholds: {
        cpu: 80,         // CPU usage %
        memory: 85,      // Memory usage %
        disk: 90,        // Disk usage %
        responseTime: 5000, // Response time in ms
        errorRate: 10    // Error rate %
    },
    
    // Metrics to collect
    metrics: {
        cpu: true,
        memory: true,
        disk: true,
        network: true,
        buildTimes: true,
        testTimes: true
    },
    
    // Dashboard configuration
    dashboard: {
        port: 3002,
        refreshInterval: 5000,
        title: 'Development Environment Monitor'
    },
    
    // Alerting configuration
    alerting: {
        enabled: true,
        channels: ['console', 'file', 'webhook'],
        webhook: {
            url: 'http://localhost:3000/webhook/alerts',
            timeout: 5000
        },
        logFile: 'alerts.log'
    },
    
    // Export configuration
    export: {
        formats: ['json', 'csv', 'prometheus'],
        schedule: '0 0 * * *', // Daily at midnight
        retention: 7 // Keep 7 days of exports
    }
};