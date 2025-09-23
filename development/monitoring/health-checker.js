#!/usr/bin/env node
/**
 * Health Checker Utility
 * Standalone script to check health of all services
 */

const config = require('./monitor-config');
const { spawn, exec } = require('child_process');

class HealthChecker {
    constructor() {
        this.services = config.services;
        this.results = new Map();
    }

    async checkAllServices() {
        console.log('Checking health of all services...\n');
        
        const promises = this.services.map(service => this.checkService(service));
        await Promise.allSettled(promises);
        
        this.displayResults();
        return this.getOverallStatus();
    }

    async checkService(service) {
        const startTime = Date.now();
        
        try {
            let result;
            
            if (service.healthUrl) {
                result = await this.checkHttpHealth(service);
            } else if (service.type === 'mcp') {
                result = await this.checkProcessHealth(service);
            } else {
                result = {
                    status: 'unknown',
                    message: 'No health check method configured'
                };
            }
            
            result.responseTime = Date.now() - startTime;
            this.results.set(service.name, result);
            
        } catch (error) {
            this.results.set(service.name, {
                status: 'error',
                message: error.message,
                responseTime: Date.now() - startTime
            });
        }
    }

    async checkHttpHealth(service) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            
            const response = await fetch(service.healthUrl, {
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
                const data = await response.json();
                return {
                    status: 'healthy',
                    message: 'HTTP health check passed',
                    data
                };
            } else {
                return {
                    status: 'unhealthy',
                    message: `HTTP ${response.status} ${response.statusText}`
                };
            }
        } catch (error) {
            if (error.name === 'AbortError') {
                return {
                    status: 'timeout',
                    message: 'Health check timed out'
                };
            }
            throw error;
        }
    }

    async checkProcessHealth(service) {
        return new Promise((resolve) => {
            const command = process.platform === 'win32' 
                ? `tasklist /FI "IMAGENAME eq ${service.processName}.exe" /FO CSV`
                : `pgrep -f ${service.processName}`;
            
            exec(command, (error, stdout) => {
                if (error) {
                    resolve({
                        status: 'down',
                        message: 'Process not found'
                    });
                    return;
                }
                
                const isRunning = process.platform === 'win32'
                    ? stdout.includes(service.processName)
                    : stdout.trim().length > 0;
                
                if (isRunning) {
                    resolve({
                        status: 'running',
                        message: 'Process is running'
                    });
                } else {
                    resolve({
                        status: 'down',
                        message: 'Process not found'
                    });
                }
            });
        });
    }

    displayResults() {
        console.log('Health Check Results:');
        console.log('====================\n');
        
        for (const [serviceName, result] of this.results) {
            const status = this.getStatusSymbol(result.status);
            const responseTime = result.responseTime ? ` (${result.responseTime}ms)` : '';
            
            console.log(`${status} ${serviceName}: ${result.status.toUpperCase()}${responseTime}`);
            if (result.message) {
                console.log(`  └─ ${result.message}`);
            }
            console.log();
        }
    }

    getStatusSymbol(status) {
        const symbols = {
            healthy: '✅',
            running: '✅',
            unhealthy: '⚠️',
            down: '❌',
            error: '❌',
            timeout: '⏱️',
            unknown: '❓'
        };
        return symbols[status] || '❓';
    }

    getOverallStatus() {
        const statuses = Array.from(this.results.values()).map(r => r.status);
        
        if (statuses.includes('error') || statuses.includes('down')) {
            return 'critical';
        } else if (statuses.includes('unhealthy') || statuses.includes('timeout')) {
            return 'warning';
        } else if (statuses.every(s => s === 'healthy' || s === 'running')) {
            return 'healthy';
        } else {
            return 'unknown';
        }
    }

    async watchServices(interval = 30000) {
        console.log(`Starting health monitoring (checking every ${interval/1000}s)...\n`);
        
        const check = async () => {
            const status = await this.checkAllServices();
            console.log(`Overall Status: ${status.toUpperCase()}\n`);
            console.log('---'.repeat(20));
        };
        
        // Initial check
        await check();
        
        // Periodic checks
        setInterval(check, interval);
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const checker = new HealthChecker();
    
    if (args.includes('--watch')) {
        const interval = parseInt(args[args.indexOf('--interval') + 1]) || 30000;
        checker.watchServices(interval);
    } else {
        checker.checkAllServices().then(status => {
            console.log(`\nOverall Status: ${status.toUpperCase()}`);
            process.exit(status === 'healthy' ? 0 : 1);
        });
    }
}

module.exports = HealthChecker;