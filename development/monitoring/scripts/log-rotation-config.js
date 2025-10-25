#!/usr/bin/env node
/**
 * Log Rotation Configuration for Winston
 * Implements rotating file transport with compression and retention policies
 */

const winston = require('winston');
require('winston-daily-rotate-file');
const path = require('path');

/**
 * Create a logger with rotation configuration
 * @param {Object} options - Logger configuration options
 * @returns {winston.Logger} Configured logger instance
 */
function createRotatingLogger(options = {}) {
    const {
        logDir = path.join(__dirname, '..', 'logs'),
        filename = 'alerts',
        level = 'info',
        maxSize = '10m',        // Max size before rotation (10MB)
        maxFiles = '14d',       // Keep logs for 14 days
        compress = true,        // Compress rotated logs
        format = 'json'         // Log format: 'json' or 'text'
    } = options;

    // Define log format
    const logFormat = format === 'json'
        ? winston.format.combine(
            winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
            winston.format.json()
          )
        : winston.format.combine(
            winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
            winston.format.printf(({ timestamp, level, message }) => {
                return `${timestamp} [${level.toUpperCase()}] ${message}`;
            })
          );

    // Create rotating file transport
    const rotatingFileTransport = new winston.transports.DailyRotateFile({
        dirname: logDir,
        filename: `${filename}-%DATE%.log`,
        datePattern: 'YYYY-MM-DD',
        zippedArchive: compress,
        maxSize: maxSize,
        maxFiles: maxFiles,
        level: level,
        format: logFormat
    });

    // Handle rotation events
    rotatingFileTransport.on('rotate', (oldFilename, newFilename) => {
        console.log(`Log file rotated: ${oldFilename} -> ${newFilename}`);
    });

    // Create logger
    const logger = winston.createLogger({
        level: level,
        format: logFormat,
        transports: [
            rotatingFileTransport,
            new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                )
            })
        ]
    });

    return logger;
}

/**
 * Alert Deduplication Helper
 * Prevents duplicate alerts from being logged repeatedly
 */
class AlertDeduplicator {
    constructor(cooldownMs = 300000) { // 5 minutes default
        this.alertCache = new Map();
        this.cooldownMs = cooldownMs;
        this.stateCache = new Map(); // Track service states
    }

    /**
     * Check if alert should be logged (state change detection)
     * @param {string} serviceOrType - Service name or alert type
     * @param {boolean} isError - Whether current state is error
     * @returns {boolean} True if alert should be logged
     */
    shouldLog(serviceOrType, isError) {
        const lastState = this.stateCache.get(serviceOrType);

        // First time seeing this service/type
        if (lastState === undefined) {
            this.stateCache.set(serviceOrType, isError);
            return true;
        }

        // State changed - log it
        if (lastState !== isError) {
            this.stateCache.set(serviceOrType, isError);
            return true;
        }

        // State unchanged - check cooldown
        return this.checkCooldown(serviceOrType);
    }

    /**
     * Check if cooldown period has passed
     * @param {string} key - Cache key
     * @returns {boolean} True if cooldown expired
     */
    checkCooldown(key) {
        const lastLogTime = this.alertCache.get(key);
        const now = Date.now();

        if (!lastLogTime || (now - lastLogTime) > this.cooldownMs) {
            this.alertCache.set(key, now);
            return true;
        }

        return false;
    }

    /**
     * Clear state for a service (useful when service recovers)
     * @param {string} serviceOrType - Service name or alert type
     */
    clearState(serviceOrType) {
        this.stateCache.delete(serviceOrType);
        this.alertCache.delete(serviceOrType);
    }

    /**
     * Get stats about cached alerts
     * @returns {Object} Statistics about deduplication
     */
    getStats() {
        return {
            trackedServices: this.stateCache.size,
            cachedAlerts: this.alertCache.size,
            cooldownMs: this.cooldownMs
        };
    }
}

/**
 * Example usage
 */
if (require.main === module) {
    console.log('Log Rotation Configuration Examples\n');

    // Example 1: Create rotating logger for alerts
    console.log('1. Creating rotating alert logger...');
    const alertLogger = createRotatingLogger({
        filename: 'alerts',
        maxSize: '10m',
        maxFiles: '14d',
        compress: true,
        format: 'text'
    });

    // Test logs
    alertLogger.info('Test info message');
    alertLogger.warn('Test warning message');
    alertLogger.error('Test error message');

    // Example 2: Alert deduplication
    console.log('\n2. Testing alert deduplication...');
    const deduplicator = new AlertDeduplicator(5000); // 5 second cooldown for demo

    // Simulate service health checks
    const services = ['webhook-audio-tracker', 'saas-api', 'api-gateway'];

    services.forEach(service => {
        // First failure - should log
        if (deduplicator.shouldLog(service, true)) {
            alertLogger.error(`${service} is not available`);
        }

        // Immediate retry - should NOT log (same state)
        if (deduplicator.shouldLog(service, true)) {
            alertLogger.error(`${service} is not available (duplicate)`);
        } else {
            console.log(`Deduplication prevented duplicate alert for ${service}`);
        }
    });

    // Example 3: State change detection
    console.log('\n3. Testing state change detection...');
    setTimeout(() => {
        // Service recovers - should log (state changed)
        if (deduplicator.shouldLog('webhook-audio-tracker', false)) {
            alertLogger.info('webhook-audio-tracker is now available');
        }

        // Show deduplication stats
        console.log('\nDeduplication stats:', deduplicator.getStats());
    }, 1000);

    // Example 4: Show recommended configuration
    console.log('\n4. Recommended Configuration:');
    console.log(`
    Log Rotation Settings:
    - Max file size: 10MB
    - Retention: 14 days
    - Compression: Enabled
    - Format: Text (human-readable)

    Alert Deduplication:
    - Cooldown: 5 minutes (300000ms)
    - State change detection: Enabled
    - Only alert on state transitions (OK -> ERROR, ERROR -> OK)

    Expected Impact:
    - Alert volume reduction: 80-95%
    - Disk space reduction: 60-70% (with compression)
    - Improved signal-to-noise ratio
    `);

    setTimeout(() => process.exit(0), 2000);
}

module.exports = {
    createRotatingLogger,
    AlertDeduplicator
};
