// Multi-Agent Observatory - Monitoring Hooks
import { EventEmitter } from 'events';
import { performance } from 'perf_hooks';
import { cpus, totalmem, freemem, loadavg } from 'os';

class ObservatoryHooks extends EventEmitter {
    constructor(options = {}) {
        super();
        this.options = {
            metricsInterval: 5000,  // 5 seconds
            cpuSampleInterval: 1000, // 1 second for CPU sampling
            ...options
        };
        
        this.startTime = Date.now();
        this.metrics = new Map();
        this.eventLog = [];
        this.isMonitoring = false;
        
        this.initializeMonitoring();
    }

    initializeMonitoring() {
        console.log('🔧 Initializing Observatory Hooks...');
        
        // Set up performance monitoring
        this.startPerformanceMonitoring();
        
        // Set up custom event tracking
        this.setupEventTracking();
        
        console.log('✅ Observatory Hooks initialized');
    }

    startPerformanceMonitoring() {
        if (this.isMonitoring) return;
        
        this.isMonitoring = true;
        
        // Start periodic metrics collection
        this.metricsTimer = setInterval(() => {
            this.collectSystemMetrics();
        }, this.options.metricsInterval);

        console.log(`📊 Performance monitoring started (${this.options.metricsInterval}ms interval)`);
    }

    stopPerformanceMonitoring() {
        if (!this.isMonitoring) return;
        
        this.isMonitoring = false;
        
        if (this.metricsTimer) {
            clearInterval(this.metricsTimer);
            this.metricsTimer = null;
        }

        console.log('🛑 Performance monitoring stopped');
    }

    collectSystemMetrics() {
        const metrics = [];
        
        try {
            // Memory metrics
            const totalMem = totalmem();
            const freeMem = freemem();
            const usedMem = totalMem - freeMem;
            const memUsagePercent = (usedMem / totalMem) * 100;
            
            metrics.push(
                { name: 'memory_total', value: totalMem / (1024 * 1024), unit: 'MB' },
                { name: 'memory_used', value: usedMem / (1024 * 1024), unit: 'MB' },
                { name: 'memory_free', value: freeMem / (1024 * 1024), unit: 'MB' },
                { name: 'memory_usage_percent', value: memUsagePercent, unit: '%' }
            );

            // CPU metrics (simplified - in production, you'd want more accurate CPU usage)
            const cpuCount = cpus().length;
            const loadAverage = loadavg();
            
            metrics.push(
                { name: 'cpu_cores', value: cpuCount, unit: 'count' },
                { name: 'load_1min', value: loadAverage[0], unit: 'load' },
                { name: 'load_5min', value: loadAverage[1], unit: 'load' },
                { name: 'load_15min', value: loadAverage[2], unit: 'load' }
            );

            // Process metrics
            const processMemory = process.memoryUsage();
            metrics.push(
                { name: 'process_memory_rss', value: processMemory.rss / (1024 * 1024), unit: 'MB' },
                { name: 'process_memory_heap_used', value: processMemory.heapUsed / (1024 * 1024), unit: 'MB' },
                { name: 'process_memory_heap_total', value: processMemory.heapTotal / (1024 * 1024), unit: 'MB' }
            );

            // Uptime
            metrics.push(
                { name: 'uptime', value: process.uptime(), unit: 'seconds' },
                { name: 'agent_uptime', value: (Date.now() - this.startTime) / 1000, unit: 'seconds' }
            );

            // Store metrics
            const timestamp = Date.now();
            for (const metric of metrics) {
                this.storeMetric(metric.name, metric.value, metric.unit, timestamp);
            }

            // Emit metrics event
            this.emit('metrics', {
                timestamp: new Date().toISOString(),
                metrics
            });

        } catch (error) {
            this.logEvent('error', 'metric_collection_failed', error.message);
        }
    }

    storeMetric(name, value, unit, timestamp = Date.now()) {
        if (!this.metrics.has(name)) {
            this.metrics.set(name, []);
        }
        
        const metricHistory = this.metrics.get(name);
        metricHistory.push({ value, unit, timestamp });
        
        // Keep only last 100 values to prevent memory leaks
        if (metricHistory.length > 100) {
            metricHistory.shift();
        }
    }

    getMetric(name) {
        return this.metrics.get(name);
    }

    getLatestMetric(name) {
        const history = this.metrics.get(name);
        return history ? history[history.length - 1] : null;
    }

    getAllMetrics() {
        const result = {};
        for (const [name, history] of this.metrics) {
            result[name] = history;
        }
        return result;
    }

    setupEventTracking() {
        // Track process events
        process.on('uncaughtException', (error) => {
            this.logEvent('error', 'uncaught_exception', error.message, { stack: error.stack });
        });

        process.on('unhandledRejection', (reason) => {
            this.logEvent('error', 'unhandled_rejection', String(reason));
        });

        process.on('warning', (warning) => {
            this.logEvent('warning', 'process_warning', warning.message, { 
                name: warning.name, 
                code: warning.code 
            });
        });

        // Track memory warnings
        process.on('memoryUsage', () => {
            const usage = process.memoryUsage();
            const rssUsageMB = usage.rss / (1024 * 1024);
            
            if (rssUsageMB > 500) { // Warn if using more than 500MB
                this.logEvent('warning', 'high_memory_usage', `Process using ${rssUsageMB.toFixed(2)}MB RAM`);
            }
        });
    }

    logEvent(severity, eventType, message, data = {}) {
        const event = {
            severity,
            eventType,
            message,
            data,
            timestamp: new Date().toISOString(),
            timestampMs: Date.now()
        };

        // Store in local log
        this.eventLog.push(event);
        
        // Keep only last 500 events
        if (this.eventLog.length > 500) {
            this.eventLog.shift();
        }

        // Emit event
        this.emit('event', event);

        console.log(`[${severity.toUpperCase()}] ${eventType}: ${message}`);
    }

    getEvents(limit = 50) {
        return this.eventLog.slice(-limit);
    }

    getEventsByType(eventType, limit = 50) {
        return this.eventLog
            .filter(event => event.eventType === eventType)
            .slice(-limit);
    }

    getEventsBySeverity(severity, limit = 50) {
        return this.eventLog
            .filter(event => event.severity === severity)
            .slice(-limit);
    }

    // Custom monitoring methods
    measurePerformance(name, fn) {
        const start = performance.now();
        
        try {
            const result = fn();
            const duration = performance.now() - start;
            
            this.storeMetric(`performance_${name}`, duration, 'ms');
            this.logEvent('info', 'performance_measurement', 
                `${name} completed in ${duration.toFixed(2)}ms`);
            
            return result;
        } catch (error) {
            const duration = performance.now() - start;
            this.logEvent('error', 'performance_measurement_failed', 
                `${name} failed after ${duration.toFixed(2)}ms: ${error.message}`);
            throw error;
        }
    }

    async measureAsyncPerformance(name, asyncFn) {
        const start = performance.now();
        
        try {
            const result = await asyncFn();
            const duration = performance.now() - start;
            
            this.storeMetric(`performance_${name}`, duration, 'ms');
            this.logEvent('info', 'async_performance_measurement', 
                `${name} completed in ${duration.toFixed(2)}ms`);
            
            return result;
        } catch (error) {
            const duration = performance.now() - start;
            this.logEvent('error', 'async_performance_measurement_failed', 
                `${name} failed after ${duration.toFixed(2)}ms: ${error.message}`);
            throw error;
        }
    }

    // Health check
    getHealthStatus() {
        const latestMemory = this.getLatestMetric('memory_usage_percent');
        const latestLoad = this.getLatestMetric('load_1min');
        const recentErrors = this.getEventsBySeverity('error', 10);
        
        let status = 'healthy';
        const issues = [];
        
        // Check memory usage
        if (latestMemory && latestMemory.value > 90) {
            status = 'warning';
            issues.push('High memory usage');
        }
        
        // Check system load
        if (latestLoad && latestLoad.value > cpus().length * 2) {
            status = 'warning';
            issues.push('High system load');
        }
        
        // Check recent errors
        if (recentErrors.length > 5) {
            status = 'critical';
            issues.push('Multiple recent errors');
        }
        
        return {
            status,
            issues,
            uptime: process.uptime(),
            timestamp: new Date().toISOString()
        };
    }

    // Cleanup
    destroy() {
        this.stopPerformanceMonitoring();
        this.removeAllListeners();
        this.metrics.clear();
        this.eventLog.length = 0;
        console.log('🧹 Observatory Hooks destroyed');
    }
}

export default ObservatoryHooks;