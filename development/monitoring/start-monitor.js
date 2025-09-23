#!/usr/bin/env node
/**
 * Monitoring System Starter
 * Initializes and runs the complete monitoring system
 */

const PerformanceMonitor = require('./performance-monitor');
const config = require('./monitor-config');
const fs = require('fs').promises;
const path = require('path');

class MonitoringSystem {
    constructor() {
        this.performanceMonitor = new PerformanceMonitor(config);
        this.alertHandlers = new Map();
        this.logFile = path.join(__dirname, 'monitoring.log');
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        // Performance monitoring events
        this.performanceMonitor.on('metrics', (metrics) => {
            this.handleMetrics(metrics);
        });

        this.performanceMonitor.on('alert', (alert) => {
            this.handleAlert(alert);
        });

        this.performanceMonitor.on('started', () => {
            this.log('Performance monitoring started');
        });

        this.performanceMonitor.on('stopped', () => {
            this.log('Performance monitoring stopped');
        });

        // Process events
        process.on('SIGINT', () => {
            this.shutdown();
        });

        process.on('SIGTERM', () => {
            this.shutdown();
        });

        process.on('uncaughtException', (error) => {
            this.log(`Uncaught exception: ${error.message}`, 'error');
            this.shutdown();
        });
    }

    async start() {
        this.log('Starting monitoring system...');
        
        try {
            // Ensure log directory exists
            await this.ensureDirectories();
            
            // Start performance monitoring
            this.performanceMonitor.start();
            
            // Setup alert handlers
            this.setupAlertHandlers();
            
            // Start dashboard if configured
            if (config.dashboard) {
                await this.startDashboard();
            }
            
            this.log('Monitoring system started successfully');
            
            // Initial status report
            setTimeout(() => {
                this.generateStatusReport();
            }, 10000); // Wait 10 seconds for initial data
            
        } catch (error) {
            this.log(`Failed to start monitoring system: ${error.message}`, 'error');
            process.exit(1);
        }
    }

    async ensureDirectories() {
        const dirs = [
            path.join(__dirname, 'logs'),
            path.join(__dirname, 'exports'),
            path.join(__dirname, 'reports')
        ];

        for (const dir of dirs) {
            try {
                await fs.mkdir(dir, { recursive: true });
            } catch (error) {
                // Directory might already exist
            }
        }
    }

    setupAlertHandlers() {
        if (!config.alerting.enabled) return;

        // Console alerting
        if (config.alerting.channels.includes('console')) {
            this.alertHandlers.set('console', (alert) => {
                const color = alert.severity === 'critical' ? '\x1b[31m' : '\x1b[33m';
                const reset = '\x1b[0m';
                console.log(`${color}[ALERT] ${alert.message}${reset}`);
            });
        }

        // File alerting
        if (config.alerting.channels.includes('file')) {
            this.alertHandlers.set('file', async (alert) => {
                const logEntry = `${new Date().toISOString()} [${alert.severity.toUpperCase()}] ${alert.message}\n`;
                const logPath = path.join(__dirname, 'logs', config.alerting.logFile);
                try {
                    await fs.appendFile(logPath, logEntry);
                } catch (error) {
                    console.error('Failed to write alert to file:', error.message);
                }
            });
        }

        // Webhook alerting
        if (config.alerting.channels.includes('webhook') && config.alerting.webhook.url) {
            this.alertHandlers.set('webhook', async (alert) => {
                try {
                    const response = await fetch(config.alerting.webhook.url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            type: 'monitoring_alert',
                            alert,
                            timestamp: Date.now()
                        }),
                        signal: AbortSignal.timeout(config.alerting.webhook.timeout)
                    });

                    if (!response.ok) {
                        throw new Error(`Webhook responded with ${response.status}`);
                    }
                } catch (error) {
                    console.error('Failed to send alert webhook:', error.message);
                }
            });
        }
    }

    async startDashboard() {
        try {
            const dashboardPath = path.join(__dirname, 'dashboard.js');
            const dashboardExists = await fs.access(dashboardPath).then(() => true).catch(() => false);
            
            if (dashboardExists) {
                const Dashboard = require('./dashboard');
                this.dashboard = new Dashboard(config.dashboard, this.performanceMonitor);
                await this.dashboard.start();
                this.log(`Dashboard started on port ${config.dashboard.port}`);
            } else {
                this.log('Dashboard not found, skipping dashboard startup');
            }
        } catch (error) {
            this.log(`Failed to start dashboard: ${error.message}`, 'error');
        }
    }

    handleMetrics(metrics) {
        // Log metrics every minute to reduce noise
        const now = Date.now();
        if (!this.lastMetricsLog || now - this.lastMetricsLog > 60000) {
            this.log(`Metrics collected - CPU: ${metrics.system.cpu.usage?.total?.toFixed(2) || 'N/A'}%, Memory: ${((metrics.system.memory.used / metrics.system.memory.total) * 100).toFixed(2)}%`);
            this.lastMetricsLog = now;
        }
    }

    async handleAlert(alert) {
        this.log(`Alert triggered: ${alert.message}`, 'warn');
        
        // Send alert through all configured channels
        for (const [name, handler] of this.alertHandlers) {
            try {
                await handler(alert);
            } catch (error) {
                this.log(`Failed to send alert via ${name}: ${error.message}`, 'error');
            }
        }
    }

    async generateStatusReport() {
        try {
            const metrics = this.performanceMonitor.getMetrics();
            const report = {
                generated: new Date().toISOString(),
                system: {
                    uptime: process.uptime(),
                    monitoring: {
                        running: this.performanceMonitor.isRunning,
                        metricsCollected: metrics.metrics.length,
                        activeAlerts: metrics.alerts.length
                    }
                },
                services: {},
                summary: metrics.summary || {},
                build: metrics.build || {},
                test: metrics.test || {}
            };

            // Service status summary
            if (metrics.summary && metrics.summary.latest) {
                for (const [serviceName, serviceMetrics] of Object.entries(metrics.summary.latest.services)) {
                    report.services[serviceName] = {
                        status: serviceMetrics.status,
                        available: serviceMetrics.available,
                        responseTime: serviceMetrics.responseTime
                    };
                }
            }

            // Save report
            const reportPath = path.join(__dirname, 'reports', `status-${Date.now()}.json`);
            await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
            
            this.log('Status report generated');
            
            // Console summary
            console.log('\n=== MONITORING STATUS REPORT ===');
            console.log(`Generated: ${report.generated}`);
            console.log(`Monitoring: ${report.system.monitoring.running ? 'RUNNING' : 'STOPPED'}`);
            console.log(`Metrics Collected: ${report.system.monitoring.metricsCollected}`);
            console.log(`Active Alerts: ${report.system.monitoring.activeAlerts}`);
            
            if (Object.keys(report.services).length > 0) {
                console.log('\nServices:');
                for (const [name, service] of Object.entries(report.services)) {
                    const status = service.available ? '✓' : '✗';
                    const responseTime = service.responseTime ? ` (${service.responseTime}ms)` : '';
                    console.log(`  ${status} ${name}: ${service.status}${responseTime}`);
                }
            }
            
            if (report.build.total > 0) {
                console.log(`\nBuilds: ${report.build.total} total, ${report.build.successRate}% success rate`);
            }
            
            if (report.test.total > 0) {
                console.log(`Tests: ${report.test.total} total, ${report.test.successRate}% success rate`);
            }
            
            console.log('=====================================\n');
            
        } catch (error) {
            this.log(`Failed to generate status report: ${error.message}`, 'error');
        }
    }

    async trackBuild(projectName, buildType, startTime, success = true) {
        const duration = Date.now() - startTime;
        const buildId = this.performanceMonitor.trackBuildTime(projectName, buildType, duration, success);
        this.log(`Build tracked: ${projectName} ${buildType} - ${duration}ms (${success ? 'SUCCESS' : 'FAILED'})`);
        return buildId;
    }

    async trackTest(projectName, testSuite, startTime, passed, failed, skipped = 0) {
        const duration = Date.now() - startTime;
        const testId = this.performanceMonitor.trackTestTime(projectName, testSuite, duration, passed, failed, skipped);
        this.log(`Test tracked: ${projectName} ${testSuite} - ${duration}ms (${passed}/${passed+failed} passed)`);
        return testId;
    }

    async exportMetrics(format = 'json') {
        try {
            const data = this.performanceMonitor.exportMetrics(format);
            const filename = `metrics-${Date.now()}.${format}`;
            const exportPath = path.join(__dirname, 'exports', filename);
            
            await fs.writeFile(exportPath, data);
            this.log(`Metrics exported to ${filename}`);
            
            return exportPath;
        } catch (error) {
            this.log(`Failed to export metrics: ${error.message}`, 'error');
            throw error;
        }
    }

    async shutdown() {
        this.log('Shutting down monitoring system...');
        
        try {
            // Stop performance monitoring
            this.performanceMonitor.stop();
            
            // Stop dashboard
            if (this.dashboard) {
                await this.dashboard.stop();
            }
            
            // Export final metrics
            await this.exportMetrics('json');
            
            this.log('Monitoring system shut down successfully');
            
        } catch (error) {
            this.log(`Error during shutdown: ${error.message}`, 'error');
        }
        
        process.exit(0);
    }

    async log(message, level = 'info') {
        const timestamp = new Date().toISOString();
        const logEntry = `${timestamp} [${level.toUpperCase()}] ${message}`;
        
        console.log(logEntry);
        
        try {
            await fs.appendFile(this.logFile, logEntry + '\n');
        } catch (error) {
            // Silent fail for logging errors
        }
    }
}

// Start monitoring if this is the main module
if (require.main === module) {
    const monitor = new MonitoringSystem();
    monitor.start().catch((error) => {
        console.error('Failed to start monitoring:', error);
        process.exit(1);
    });
}

module.exports = MonitoringSystem;