#!/usr/bin/env node
/**
 * Health Check Module for MCP Servers
 * Provides standardized health monitoring capabilities
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

class HealthCheck {
    constructor(serverName, version = '1.0.0') {
        this.serverName = serverName;
        this.version = version;
        this.startTime = Date.now();
        this.healthChecks = new Map();
        this.metrics = {
            requestCount: 0,
            errorCount: 0,
            avgResponseTime: 0,
            lastRequestTime: null,
            responseTimes: []
        };
        
        // Register default health checks
        this.registerHealthCheck('server', this.checkServerHealth.bind(this));
        this.registerHealthCheck('memory', this.checkMemoryHealth.bind(this));
        this.registerHealthCheck('disk', this.checkDiskHealth.bind(this));
        this.registerHealthCheck('dependencies', this.checkDependencies.bind(this));
    }

    registerHealthCheck(name, checkFunction) {
        this.healthChecks.set(name, checkFunction);
    }

    async checkServerHealth() {
        const uptime = Date.now() - this.startTime;
        return {
            status: 'healthy',
            uptime: uptime,
            uptimeFormatted: this.formatUptime(uptime),
            version: this.version,
            serverName: this.serverName,
            timestamp: new Date().toISOString()
        };
    }

    async checkMemoryHealth() {
        const memUsage = process.memoryUsage();
        const systemMem = {
            total: os.totalmem(),
            free: os.freemem(),
            used: os.totalmem() - os.freemem()
        };

        const memoryUsagePercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;
        const systemMemoryPercent = (systemMem.used / systemMem.total) * 100;

        return {
            status: memoryUsagePercent > 90 ? 'warning' : 'healthy',
            processMemory: {
                heapUsed: this.formatBytes(memUsage.heapUsed),
                heapTotal: this.formatBytes(memUsage.heapTotal),
                external: this.formatBytes(memUsage.external),
                rss: this.formatBytes(memUsage.rss),
                usagePercent: Math.round(memoryUsagePercent * 100) / 100
            },
            systemMemory: {
                total: this.formatBytes(systemMem.total),
                free: this.formatBytes(systemMem.free),
                used: this.formatBytes(systemMem.used),
                usagePercent: Math.round(systemMemoryPercent * 100) / 100
            }
        };
    }

    async checkDiskHealth() {
        try {
            const stats = fs.statSync(process.cwd());
            return {
                status: 'healthy',
                workingDirectory: process.cwd(),
                accessible: true,
                lastModified: stats.mtime
            };
        } catch (error) {
            return {
                status: 'error',
                workingDirectory: process.cwd(),
                accessible: false,
                error: error.message
            };
        }
    }

    async checkDependencies() {
        try {
            const packagePath = path.join(process.cwd(), 'package.json');
            if (fs.existsSync(packagePath)) {
                const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
                const dependencies = Object.keys(packageData.dependencies || {});
                const devDependencies = Object.keys(packageData.devDependencies || {});
                
                return {
                    status: 'healthy',
                    packageName: packageData.name,
                    packageVersion: packageData.version,
                    dependencyCount: dependencies.length,
                    devDependencyCount: devDependencies.length,
                    dependencies: dependencies.slice(0, 10), // Show first 10
                    hasPackageJson: true
                };
            } else {
                return {
                    status: 'warning',
                    hasPackageJson: false,
                    message: 'No package.json found'
                };
            }
        } catch (error) {
            return {
                status: 'error',
                error: error.message,
                hasPackageJson: false
            };
        }
    }

    async runAllChecks() {
        const results = {};
        let overallStatus = 'healthy';

        for (const [name, checkFunction] of this.healthChecks) {
            try {
                const result = await checkFunction();
                results[name] = result;
                
                if (result.status === 'error') {
                    overallStatus = 'error';
                } else if (result.status === 'warning' && overallStatus !== 'error') {
                    overallStatus = 'warning';
                }
            } catch (error) {
                results[name] = {
                    status: 'error',
                    error: error.message
                };
                overallStatus = 'error';
            }
        }

        return {
            status: overallStatus,
            timestamp: new Date().toISOString(),
            checks: results,
            metrics: this.getMetrics()
        };
    }

    recordRequest(responseTime) {
        this.metrics.requestCount++;
        this.metrics.lastRequestTime = new Date().toISOString();
        
        if (responseTime) {
            this.metrics.responseTimes.push(responseTime);
            // Keep only last 100 response times for rolling average
            if (this.metrics.responseTimes.length > 100) {
                this.metrics.responseTimes.shift();
            }
            
            this.metrics.avgResponseTime = 
                this.metrics.responseTimes.reduce((a, b) => a + b, 0) / 
                this.metrics.responseTimes.length;
        }
    }

    recordError() {
        this.metrics.errorCount++;
    }

    getMetrics() {
        return {
            ...this.metrics,
            errorRate: this.metrics.requestCount > 0 ? 
                (this.metrics.errorCount / this.metrics.requestCount) * 100 : 0,
            avgResponseTime: Math.round(this.metrics.avgResponseTime * 100) / 100
        };
    }

    formatUptime(milliseconds) {
        const seconds = Math.floor(milliseconds / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
        if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
        if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
        return `${seconds}s`;
    }

    formatBytes(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    // Express.js middleware for health endpoint
    middleware() {
        return async (req, res) => {
            const startTime = Date.now();
            try {
                const healthData = await this.runAllChecks();
                const responseTime = Date.now() - startTime;
                this.recordRequest(responseTime);
                
                res.status(healthData.status === 'healthy' ? 200 : 
                          healthData.status === 'warning' ? 200 : 503);
                res.json(healthData);
            } catch (error) {
                this.recordError();
                res.status(500).json({
                    status: 'error',
                    error: error.message,
                    timestamp: new Date().toISOString()
                });
            }
        };
    }

    // Simple health check for MCP servers without Express
    async getHealthStatus() {
        try {
            const healthData = await this.runAllChecks();
            this.recordRequest();
            return healthData;
        } catch (error) {
            this.recordError();
            return {
                status: 'error',
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }
}

module.exports = HealthCheck;