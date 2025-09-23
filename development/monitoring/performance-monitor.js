#!/usr/bin/env node
/**
 * Performance Monitoring System
 * Collects and tracks performance metrics across all services
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn, exec } = require('child_process');
const EventEmitter = require('events');

class PerformanceMonitor extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            interval: config.interval || 5000, // 5 seconds
            retention: config.retention || 86400000, // 24 hours
            services: config.services || [],
            metrics: config.metrics || {
                cpu: true,
                memory: true,
                disk: true,
                network: true,
                buildTimes: true,
                testTimes: true
            },
            ...config
        };
        
        this.metrics = new Map();
        this.alerts = [];
        this.thresholds = {
            cpu: 80,
            memory: 85,
            disk: 90,
            responseTime: 5000
        };
        
        this.isRunning = false;
        this.intervalId = null;
        this.buildMetrics = new Map();
        this.testMetrics = new Map();
    }

    start() {
        if (this.isRunning) {
            console.log('Performance monitor already running');
            return;
        }

        this.isRunning = true;
        console.log('Starting performance monitoring...');
        
        // Start periodic metric collection
        this.intervalId = setInterval(() => {
            this.collectMetrics();
        }, this.config.interval);

        // Initial collection
        this.collectMetrics();
        
        // Clean old metrics periodically
        setInterval(() => {
            this.cleanOldMetrics();
        }, 300000); // Every 5 minutes

        this.emit('started');
    }

    stop() {
        if (!this.isRunning) {
            return;
        }

        this.isRunning = false;
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }

        console.log('Performance monitoring stopped');
        this.emit('stopped');
    }

    async collectMetrics() {
        const timestamp = Date.now();
        const metrics = {
            timestamp,
            system: await this.getSystemMetrics(),
            services: await this.getServiceMetrics(),
            build: this.getBuildMetrics(),
            test: this.getTestMetrics()
        };

        // Store metrics
        const key = `metrics_${timestamp}`;
        this.metrics.set(key, metrics);

        // Check thresholds and generate alerts
        this.checkThresholds(metrics);

        // Emit metrics for real-time monitoring
        this.emit('metrics', metrics);

        return metrics;
    }

    async getSystemMetrics() {
        const memUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();
        
        return {
            cpu: {
                user: cpuUsage.user,
                system: cpuUsage.system,
                usage: await this.getCPUUsage()
            },
            memory: {
                total: os.totalmem(),
                free: os.freemem(),
                used: os.totalmem() - os.freemem(),
                process: {
                    heapUsed: memUsage.heapUsed,
                    heapTotal: memUsage.heapTotal,
                    external: memUsage.external,
                    rss: memUsage.rss
                }
            },
            disk: await this.getDiskUsage(),
            network: os.networkInterfaces(),
            loadAverage: os.loadavg(),
            uptime: os.uptime()
        };
    }

    async getServiceMetrics() {
        const serviceMetrics = {};
        
        for (const service of this.config.services) {
            try {
                const metrics = await this.getServiceHealth(service);
                serviceMetrics[service.name] = metrics;
            } catch (error) {
                serviceMetrics[service.name] = {
                    status: 'error',
                    error: error.message,
                    available: false
                };
            }
        }

        return serviceMetrics;
    }

    async getServiceHealth(service) {
        const startTime = Date.now();
        
        try {
            // Try to fetch health endpoint
            if (service.healthUrl) {
                const response = await this.fetchWithTimeout(service.healthUrl, 5000);
                const responseTime = Date.now() - startTime;
                
                return {
                    status: 'healthy',
                    responseTime,
                    available: true,
                    data: response
                };
            }

            // For MCP servers, check if process is running
            if (service.type === 'mcp') {
                const isRunning = await this.checkProcessRunning(service.processName);
                return {
                    status: isRunning ? 'healthy' : 'down',
                    available: isRunning,
                    processRunning: isRunning
                };
            }

            return {
                status: 'unknown',
                available: false
            };
        } catch (error) {
            return {
                status: 'error',
                error: error.message,
                available: false,
                responseTime: Date.now() - startTime
            };
        }
    }

    async fetchWithTimeout(url, timeout = 5000) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        try {
            const response = await fetch(url, {
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return await response.json();
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    async checkProcessRunning(processName) {
        return new Promise((resolve) => {
            const command = process.platform === 'win32' 
                ? `tasklist /FI "IMAGENAME eq ${processName}" /FO CSV`
                : `pgrep -f ${processName}`;
            
            exec(command, (error, stdout) => {
                if (error) {
                    resolve(false);
                    return;
                }
                
                const isRunning = process.platform === 'win32'
                    ? stdout.includes(processName)
                    : stdout.trim().length > 0;
                
                resolve(isRunning);
            });
        });
    }

    async getCPUUsage() {
        return new Promise((resolve) => {
            const startUsage = process.cpuUsage();
            setTimeout(() => {
                const endUsage = process.cpuUsage(startUsage);
                const userPercent = (endUsage.user / 1000000) * 100;
                const systemPercent = (endUsage.system / 1000000) * 100;
                resolve({
                    user: userPercent,
                    system: systemPercent,
                    total: userPercent + systemPercent
                });
            }, 100);
        });
    }

    async getDiskUsage() {
        return new Promise((resolve) => {
            const command = process.platform === 'win32'
                ? 'dir /-c'
                : 'df -h';
            
            exec(command, (error, stdout) => {
                if (error) {
                    resolve({ error: error.message });
                    return;
                }
                
                resolve({
                    raw: stdout,
                    usage: this.parseDiskUsage(stdout)
                });
            });
        });
    }

    parseDiskUsage(output) {
        // Simple disk usage parsing
        const lines = output.split('\n');
        const usage = [];
        
        for (const line of lines) {
            if (line.includes('%') || line.includes('GB') || line.includes('MB')) {
                usage.push(line.trim());
            }
        }
        
        return usage;
    }

    trackBuildTime(projectName, buildType, duration, success = true) {
        const buildId = `${projectName}_${buildType}_${Date.now()}`;
        const buildData = {
            id: buildId,
            projectName,
            buildType,
            duration,
            success,
            timestamp: Date.now()
        };

        this.buildMetrics.set(buildId, buildData);
        this.emit('build_metric', buildData);

        return buildId;
    }

    trackTestTime(projectName, testSuite, duration, passed, failed, skipped = 0) {
        const testId = `${projectName}_${testSuite}_${Date.now()}`;
        const testData = {
            id: testId,
            projectName,
            testSuite,
            duration,
            passed,
            failed,
            skipped,
            success: failed === 0,
            timestamp: Date.now()
        };

        this.testMetrics.set(testId, testData);
        this.emit('test_metric', testData);

        return testId;
    }

    getBuildMetrics() {
        const builds = Array.from(this.buildMetrics.values());
        const last24h = builds.filter(b => Date.now() - b.timestamp < 86400000);
        
        return {
            total: builds.length,
            last24h: last24h.length,
            averageDuration: this.calculateAverage(last24h, 'duration'),
            successRate: this.calculateSuccessRate(last24h),
            recent: last24h.slice(-10)
        };
    }

    getTestMetrics() {
        const tests = Array.from(this.testMetrics.values());
        const last24h = tests.filter(t => Date.now() - t.timestamp < 86400000);
        
        return {
            total: tests.length,
            last24h: last24h.length,
            averageDuration: this.calculateAverage(last24h, 'duration'),
            successRate: this.calculateSuccessRate(last24h),
            totalPassed: last24h.reduce((sum, t) => sum + t.passed, 0),
            totalFailed: last24h.reduce((sum, t) => sum + t.failed, 0),
            recent: last24h.slice(-10)
        };
    }

    calculateAverage(array, property) {
        if (array.length === 0) return 0;
        const sum = array.reduce((total, item) => total + item[property], 0);
        return Math.round((sum / array.length) * 100) / 100;
    }

    calculateSuccessRate(array) {
        if (array.length === 0) return 100;
        const successful = array.filter(item => item.success).length;
        return Math.round((successful / array.length) * 100 * 100) / 100;
    }

    checkThresholds(metrics) {
        const alerts = [];

        // CPU threshold
        if (metrics.system.cpu.usage && metrics.system.cpu.usage.total > this.thresholds.cpu) {
            alerts.push({
                type: 'cpu_high',
                severity: 'warning',
                message: `CPU usage is high: ${metrics.system.cpu.usage.total.toFixed(2)}%`,
                value: metrics.system.cpu.usage.total,
                threshold: this.thresholds.cpu,
                timestamp: Date.now()
            });
        }

        // Memory threshold
        const memoryUsage = (metrics.system.memory.used / metrics.system.memory.total) * 100;
        if (memoryUsage > this.thresholds.memory) {
            alerts.push({
                type: 'memory_high',
                severity: 'warning',
                message: `Memory usage is high: ${memoryUsage.toFixed(2)}%`,
                value: memoryUsage,
                threshold: this.thresholds.memory,
                timestamp: Date.now()
            });
        }

        // Service response time
        for (const [serviceName, serviceMetrics] of Object.entries(metrics.services)) {
            if (serviceMetrics.responseTime > this.thresholds.responseTime) {
                alerts.push({
                    type: 'response_time_high',
                    severity: 'warning',
                    message: `${serviceName} response time is high: ${serviceMetrics.responseTime}ms`,
                    service: serviceName,
                    value: serviceMetrics.responseTime,
                    threshold: this.thresholds.responseTime,
                    timestamp: Date.now()
                });
            }

            if (!serviceMetrics.available) {
                alerts.push({
                    type: 'service_down',
                    severity: 'critical',
                    message: `${serviceName} is not available`,
                    service: serviceName,
                    timestamp: Date.now()
                });
            }
        }

        // Store and emit alerts
        this.alerts.push(...alerts);
        alerts.forEach(alert => this.emit('alert', alert));
    }

    cleanOldMetrics() {
        const cutoff = Date.now() - this.config.retention;
        
        // Clean system metrics
        for (const [key, metric] of this.metrics.entries()) {
            if (metric.timestamp < cutoff) {
                this.metrics.delete(key);
            }
        }

        // Clean build metrics
        for (const [id, build] of this.buildMetrics.entries()) {
            if (build.timestamp < cutoff) {
                this.buildMetrics.delete(id);
            }
        }

        // Clean test metrics
        for (const [id, test] of this.testMetrics.entries()) {
            if (test.timestamp < cutoff) {
                this.testMetrics.delete(id);
            }
        }

        // Clean old alerts
        this.alerts = this.alerts.filter(alert => alert.timestamp > cutoff);
    }

    getMetrics(timeRange = 3600000) { // Default 1 hour
        const cutoff = Date.now() - timeRange;
        const recentMetrics = Array.from(this.metrics.values())
            .filter(m => m.timestamp > cutoff)
            .sort((a, b) => a.timestamp - b.timestamp);

        return {
            metrics: recentMetrics,
            summary: this.getMetricsSummary(recentMetrics),
            alerts: this.alerts.filter(a => a.timestamp > cutoff),
            build: this.getBuildMetrics(),
            test: this.getTestMetrics()
        };
    }

    getMetricsSummary(metrics) {
        if (metrics.length === 0) return {};

        const latest = metrics[metrics.length - 1];
        const averages = this.calculateAverages(metrics);

        return {
            latest,
            averages,
            trends: this.calculateTrends(metrics),
            availability: this.calculateAvailability(metrics)
        };
    }

    calculateAverages(metrics) {
        const cpuUsages = metrics.map(m => m.system.cpu.usage?.total).filter(Boolean);
        const memoryUsages = metrics.map(m => (m.system.memory.used / m.system.memory.total) * 100);
        
        return {
            cpu: this.calculateAverage(cpuUsages.map(v => ({ duration: v })), 'duration'),
            memory: this.calculateAverage(memoryUsages.map(v => ({ duration: v })), 'duration')
        };
    }

    calculateTrends(metrics) {
        // Simple trend calculation (increasing/decreasing)
        if (metrics.length < 2) return {};

        const first = metrics[0];
        const last = metrics[metrics.length - 1];

        return {
            cpu: last.system.cpu.usage?.total > first.system.cpu.usage?.total ? 'increasing' : 'decreasing',
            memory: (last.system.memory.used / last.system.memory.total) > 
                   (first.system.memory.used / first.system.memory.total) ? 'increasing' : 'decreasing'
        };
    }

    calculateAvailability(metrics) {
        const availability = {};
        
        for (const service of this.config.services) {
            const serviceMetrics = metrics.map(m => m.services[service.name]).filter(Boolean);
            const available = serviceMetrics.filter(m => m.available).length;
            availability[service.name] = serviceMetrics.length > 0 ? 
                (available / serviceMetrics.length) * 100 : 0;
        }

        return availability;
    }

    exportMetrics(format = 'json') {
        const data = this.getMetrics();
        
        switch (format) {
            case 'json':
                return JSON.stringify(data, null, 2);
            case 'csv':
                return this.exportToCSV(data);
            case 'prometheus':
                return this.exportToPrometheus(data);
            default:
                return data;
        }
    }

    exportToCSV(data) {
        // Simple CSV export for metrics
        const lines = ['timestamp,cpu_usage,memory_usage,alerts'];
        
        for (const metric of data.metrics) {
            const cpu = metric.system.cpu.usage?.total || 0;
            const memory = (metric.system.memory.used / metric.system.memory.total) * 100;
            const alertCount = this.alerts.filter(a => 
                Math.abs(a.timestamp - metric.timestamp) < 5000).length;
            
            lines.push(`${metric.timestamp},${cpu},${memory},${alertCount}`);
        }
        
        return lines.join('\n');
    }

    exportToPrometheus(data) {
        // Simple Prometheus metrics format
        const lines = [];
        const latest = data.summary.latest;
        
        if (latest) {
            lines.push('# HELP system_cpu_usage CPU usage percentage');
            lines.push('# TYPE system_cpu_usage gauge');
            lines.push(`system_cpu_usage ${latest.system.cpu.usage?.total || 0}`);
            
            lines.push('# HELP system_memory_usage Memory usage percentage');
            lines.push('# TYPE system_memory_usage gauge');
            const memUsage = (latest.system.memory.used / latest.system.memory.total) * 100;
            lines.push(`system_memory_usage ${memUsage}`);
            
            lines.push('# HELP active_alerts Number of active alerts');
            lines.push('# TYPE active_alerts gauge');
            lines.push(`active_alerts ${data.alerts.length}`);
        }
        
        return lines.join('\n');
    }
}

module.exports = PerformanceMonitor;