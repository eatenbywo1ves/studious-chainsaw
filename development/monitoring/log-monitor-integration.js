/**
 * Log Monitoring Integration
 * Connects the centralized logging system with the monitoring dashboard
 */

const path = require('path');
const fs = require('fs');
const EventEmitter = require('events');

// Import loggers
const loggerPath = path.join(__dirname, '../logs/centralized/logger');
const { createLogger, logConfig } = require(loggerPath);
const PerformanceLogger = require(path.join(__dirname, '../logs/centralized/performance-logger'));
const AgentLogger = require(path.join(__dirname, '../logs/centralized/agent-logger'));
const MCPLogger = require(path.join(__dirname, '../logs/centralized/mcp-logger'));

class LogMonitorIntegration extends EventEmitter {
    constructor() {
        super();
        this.logger = createLogger('monitoring-dashboard', 'services');
        this.perfLogger = new PerformanceLogger('dashboard');
        this.logStreams = new Map();
        this.metrics = {
            logCounts: new Map(),
            errorRates: new Map(),
            performanceMetrics: [],
            alerts: []
        };
        this.isMonitoring = false;
    }
    
    async initialize() {
        this.logger.info('Log monitoring integration initializing', {
            logConfig: {
                categories: Object.keys(logConfig.config.services),
                retention: logConfig.config.rotation.maxAge,
                alerting: logConfig.config.alerts.enabled
            }
        });
        
        // Start performance monitoring
        this.perfLogger.startMonitoring(30000); // Every 30 seconds
        
        // Set up log watchers for each category
        this.setupLogWatchers();
        
        // Start metrics aggregation
        this.startMetricsAggregation();
        
        this.logger.info('Log monitoring integration initialized');
    }
    
    setupLogWatchers() {
        const categories = ['agents', 'services', 'performance', 'errors'];
        const baseDir = path.join(__dirname, '../logs/centralized');
        
        categories.forEach(category => {
            const dir = path.join(baseDir, category);
            
            // Ensure directory exists
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            
            // Watch for changes
            fs.watch(dir, (eventType, filename) => {
                if (filename && filename.endsWith('.log')) {
                    this.handleLogFileChange(category, path.join(dir, filename));
                }
            });
            
            this.logger.debug(`Watching log directory: ${category}`);
        });
    }
    
    async handleLogFileChange(category, filePath) {
        try {
            // Read new lines from the file
            const content = await this.readNewLines(filePath);
            
            if (content) {
                const lines = content.split('\n').filter(line => line.trim());
                
                for (const line of lines) {
                    try {
                        const log = JSON.parse(line);
                        this.processLogEntry(category, log);
                    } catch (e) {
                        // Skip non-JSON lines
                    }
                }
            }
        } catch (error) {
            this.logger.error('Error processing log file change', {
                file: filePath,
                error: error.message
            });
        }
    }
    
    async readNewLines(filePath) {
        // Track file position to read only new content
        const lastPosition = this.logStreams.get(filePath) || 0;
        
        try {
            const stats = await fs.promises.stat(filePath);
            
            if (stats.size > lastPosition) {
                const buffer = Buffer.alloc(stats.size - lastPosition);
                const fd = await fs.promises.open(filePath, 'r');
                
                await fd.read(buffer, 0, buffer.length, lastPosition);
                await fd.close();
                
                this.logStreams.set(filePath, stats.size);
                return buffer.toString();
            }
        } catch (error) {
            // File might not exist yet
        }
        
        return null;
    }
    
    processLogEntry(category, log) {
        // Update log counts
        const service = log.service || 'unknown';
        const counts = this.metrics.logCounts.get(service) || {
            total: 0,
            debug: 0,
            info: 0,
            warn: 0,
            error: 0,
            fatal: 0
        };
        
        counts.total++;
        counts[log.level.toLowerCase()]++;
        this.metrics.logCounts.set(service, counts);
        
        // Track errors for error rate calculation
        if (log.level === 'ERROR' || log.level === 'FATAL') {
            this.trackError(service, log);
        }
        
        // Emit events for real-time dashboard updates
        this.emit('log', {
            category,
            log,
            timestamp: Date.now()
        });
        
        // Check for alert conditions
        this.checkAlertConditions(service, log);
    }
    
    trackError(service, log) {
        const now = Date.now();
        const window = 60000; // 1 minute window
        
        const errors = this.metrics.errorRates.get(service) || [];
        
        // Add new error
        errors.push({
            timestamp: now,
            message: log.message,
            level: log.level
        });
        
        // Remove old errors outside the window
        const cutoff = now - window;
        const recent = errors.filter(e => e.timestamp > cutoff);
        
        this.metrics.errorRates.set(service, recent);
        
        // Calculate error rate
        const errorRate = recent.length; // Errors per minute
        
        if (errorRate > 10) {
            this.createAlert('error_rate', service, `High error rate: ${errorRate} errors/min`, 'high');
        }
    }
    
    checkAlertConditions(service, log) {
        // Check for critical errors
        if (log.level === 'FATAL') {
            this.createAlert('fatal_error', service, `Fatal error: ${log.message}`, 'critical');
        }
        
        // Check for performance thresholds in performance logs
        if (log.cpu?.usage > 90) {
            this.createAlert('high_cpu', service, `CPU usage critical: ${log.cpu.usage}%`, 'high');
        }
        
        if (log.memory?.usage > 90) {
            this.createAlert('high_memory', service, `Memory usage critical: ${log.memory.usage}%`, 'high');
        }
    }
    
    createAlert(type, service, message, severity) {
        const alert = {
            id: `${type}_${service}_${Date.now()}`,
            type,
            service,
            message,
            severity,
            timestamp: new Date().toISOString()
        };
        
        this.metrics.alerts.push(alert);
        
        // Keep only recent alerts
        if (this.metrics.alerts.length > 100) {
            this.metrics.alerts = this.metrics.alerts.slice(-100);
        }
        
        // Emit alert event
        this.emit('alert', alert);
        
        // Log the alert
        this.logger.warn('Alert triggered', alert);
    }
    
    startMetricsAggregation() {
        // Aggregate metrics every 10 seconds
        setInterval(() => {
            this.aggregateMetrics();
        }, 10000);
    }
    
    aggregateMetrics() {
        const summary = {
            timestamp: new Date().toISOString(),
            services: {},
            totals: {
                logs: 0,
                errors: 0,
                warnings: 0
            },
            errorRate: 0,
            alerts: this.metrics.alerts.filter(a => 
                new Date(a.timestamp).getTime() > Date.now() - 300000 // Last 5 minutes
            ).length
        };
        
        // Aggregate per-service metrics
        for (const [service, counts] of this.metrics.logCounts.entries()) {
            summary.services[service] = {
                total: counts.total,
                errors: counts.error + counts.fatal,
                warnings: counts.warn,
                errorRate: (this.metrics.errorRates.get(service) || []).length
            };
            
            summary.totals.logs += counts.total;
            summary.totals.errors += counts.error + counts.fatal;
            summary.totals.warnings += counts.warn;
        }
        
        // Calculate overall error rate
        let totalErrors = 0;
        for (const errors of this.metrics.errorRates.values()) {
            totalErrors += errors.length;
        }
        summary.errorRate = totalErrors;
        
        // Add performance metrics
        const perfAvg = this.perfLogger.getAverageMetrics(5);
        if (perfAvg) {
            summary.performance = perfAvg;
        }
        
        // Emit aggregated metrics
        this.emit('metrics', summary);
        
        // Log summary
        this.logger.debug('Metrics aggregated', summary);
    }
    
    getDashboardData() {
        // Provide current state for dashboard initialization
        return {
            logCounts: Object.fromEntries(this.metrics.logCounts),
            errorRates: Object.fromEntries(
                Array.from(this.metrics.errorRates.entries()).map(([k, v]) => [k, v.length])
            ),
            recentAlerts: this.metrics.alerts.slice(-10),
            performance: this.perfLogger.getAverageMetrics(5)
        };
    }
    
    getRecentLogs(service = null, limit = 50) {
        // This would fetch recent logs from files
        // For now, return empty array as placeholder
        return [];
    }
    
    async shutdown() {
        this.logger.info('Log monitoring integration shutting down');
        
        // Stop performance monitoring
        this.perfLogger.stopMonitoring();
        
        // Flush all loggers
        await this.logger.flush();
        await this.perfLogger.flush();
        
        this.logger.info('Log monitoring integration shut down');
    }
}

// Export singleton instance
module.exports = new LogMonitorIntegration();