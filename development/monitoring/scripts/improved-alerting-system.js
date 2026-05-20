#!/usr/bin/env node
/**
 * Improved Alerting System with Deduplication and Smart Filtering
 * This addresses the alert spam issue identified in the log analysis
 */

const fs = require('fs').promises;
const path = require('path');
const { EventEmitter } = require('events');

class ImprovedAlertingSystem extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            enabled: config.enabled !== false,
            channels: config.channels || ['console', 'file'],
            cooldown: config.cooldown || 300000, // 5 minutes
            stateChangeOnly: config.stateChangeOnly !== false, // Alert only on state changes
            exponentialBackoff: config.exponentialBackoff !== false,
            backoffMultiplier: config.backoffMultiplier || 2,
            maxBackoffMs: config.maxBackoffMs || 3600000, // 1 hour max
            ...config
        };

        this.serviceStates = new Map(); // Track current state of each service
        this.lastAlertTime = new Map(); // Track last alert time for cooldown
        this.alertCounts = new Map();   // Track consecutive alerts for backoff
        this.suppressedCount = new Map(); // Track suppressed alert count
    }

    /**
     * Process an alert with smart deduplication
     * @param {Object} alert - Alert data
     * @returns {Object|null} Processed alert or null if suppressed
     */
    async processAlert(alert) {
        if (!this.config.enabled) return null;

        const alertKey = this.getAlertKey(alert);

        // Check if this is a state change
        const currentState = this.getAlertState(alert);
        const previousState = this.serviceStates.get(alertKey);
        const isStateChange = previousState !== currentState;

        // Update state
        this.serviceStates.set(alertKey, currentState);

        // State change only mode
        if (this.config.stateChangeOnly && !isStateChange) {
            // Only alert on state transitions
            if (previousState !== undefined) {
                this.incrementSuppressed(alertKey);
                return null;
            }
        }

        // Check cooldown with exponential backoff
        if (!this.shouldAlert(alertKey, isStateChange)) {
            this.incrementSuppressed(alertKey);
            return null;
        }

        // Enhance alert with metadata
        const enhancedAlert = {
            ...alert,
            id: this.generateAlertId(),
            timestamp: Date.now(),
            isStateChange,
            previousState,
            currentState,
            suppressedSinceLastAlert: this.getSuppressedCount(alertKey)
        };

        // Send alert
        await this.sendAlert(enhancedAlert);

        // Update tracking
        this.lastAlertTime.set(alertKey, Date.now());
        this.incrementAlertCount(alertKey);
        this.resetSuppressed(alertKey);

        this.emit('alert', enhancedAlert);
        return enhancedAlert;
    }

    /**
     * Determine if alert should be sent based on cooldown and backoff
     * @param {string} alertKey - Unique identifier for alert type
     * @param {boolean} isStateChange - Whether this is a state change
     * @returns {boolean} True if alert should be sent
     */
    shouldAlert(alertKey, isStateChange) {
        // Always alert on state changes
        if (isStateChange) {
            this.resetAlertCount(alertKey);
            return true;
        }

        const lastAlertTime = this.lastAlertTime.get(alertKey);
        if (!lastAlertTime) {
            return true; // First alert
        }

        const timeSinceLastAlert = Date.now() - lastAlertTime;
        const cooldownPeriod = this.getCooldownPeriod(alertKey);

        return timeSinceLastAlert >= cooldownPeriod;
    }

    /**
     * Calculate cooldown period with exponential backoff
     * @param {string} alertKey - Alert key
     * @returns {number} Cooldown period in milliseconds
     */
    getCooldownPeriod(alertKey) {
        if (!this.config.exponentialBackoff) {
            return this.config.cooldown;
        }

        const alertCount = this.alertCounts.get(alertKey) || 0;
        const backoff = this.config.cooldown * Math.pow(this.config.backoffMultiplier, alertCount);

        return Math.min(backoff, this.config.maxBackoffMs);
    }

    /**
     * Generate unique alert key
     * @param {Object} alert - Alert object
     * @returns {string} Unique key
     */
    getAlertKey(alert) {
        return `${alert.type}_${alert.service || alert.source || 'system'}`;
    }

    /**
     * Extract state from alert (for state change detection)
     * @param {Object} alert - Alert object
     * @returns {string} State identifier
     */
    getAlertState(alert) {
        // For service alerts, state is 'up' or 'down'
        if (alert.type === 'service_down') {
            return 'down';
        }
        if (alert.type === 'service_up' || alert.type === 'service_recovered') {
            return 'up';
        }

        // For threshold alerts, use severity
        return alert.severity || 'unknown';
    }

    /**
     * Send alert through configured channels
     * @param {Object} alert - Alert object
     */
    async sendAlert(alert) {
        const timestamp = new Date(alert.timestamp).toISOString();

        // Console channel
        if (this.config.channels.includes('console')) {
            const color = this.getColorCode(alert.severity);
            const reset = '\x1b[0m';
            const stateChange = alert.isStateChange ? ' [STATE CHANGE]' : '';
            const suppressed = alert.suppressedSinceLastAlert > 0
                ? ` (${alert.suppressedSinceLastAlert} similar alerts suppressed)`
                : '';

            console.log(`${color}${timestamp} [${alert.severity.toUpperCase()}]${stateChange} ${alert.message}${suppressed}${reset}`);
        }

        // File channel
        if (this.config.channels.includes('file')) {
            const logEntry = `${timestamp} [${alert.severity.toUpperCase()}] ${alert.message}\n`;
            const logPath = path.join(__dirname, '..', 'logs', this.config.logFile || 'alerts.log');

            try {
                await fs.appendFile(logPath, logEntry);
            } catch (error) {
                console.error('Failed to write alert to file:', error.message);
            }
        }

        // Webhook channel
        if (this.config.channels.includes('webhook') && this.config.webhook?.url) {
            try {
                await fetch(this.config.webhook.url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...(this.config.webhook.headers || {})
                    },
                    body: JSON.stringify({
                        type: 'monitoring_alert',
                        alert,
                        timestamp: Date.now()
                    }),
                    signal: AbortSignal.timeout(this.config.webhook.timeout || 5000)
                });
            } catch (error) {
                console.error('Failed to send webhook alert:', error.message);
            }
        }
    }

    /**
     * Helper methods for tracking
     */
    incrementAlertCount(key) {
        const current = this.alertCounts.get(key) || 0;
        this.alertCounts.set(key, current + 1);
    }

    resetAlertCount(key) {
        this.alertCounts.set(key, 0);
    }

    incrementSuppressed(key) {
        const current = this.suppressedCount.get(key) || 0;
        this.suppressedCount.set(key, current + 1);
    }

    getSuppressedCount(key) {
        return this.suppressedCount.get(key) || 0;
    }

    resetSuppressed(key) {
        this.suppressedCount.set(key, 0);
    }

    getColorCode(severity) {
        const colors = {
            critical: '\x1b[31m', // Red
            warning: '\x1b[33m',  // Yellow
            info: '\x1b[36m'      // Cyan
        };
        return colors[severity] || '\x1b[37m'; // White
    }

    generateAlertId() {
        return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Get statistics about alert processing
     * @returns {Object} Stats
     */
    getStats() {
        const totalSuppressed = Array.from(this.suppressedCount.values())
            .reduce((sum, count) => sum + count, 0);

        return {
            trackedServices: this.serviceStates.size,
            activeAlerts: this.lastAlertTime.size,
            totalSuppressed,
            currentStates: Object.fromEntries(this.serviceStates),
            backoffLevels: Object.fromEntries(this.alertCounts)
        };
    }

    /**
     * Clear state for a service (e.g., when service is removed)
     * @param {string} serviceName - Service name
     */
    clearService(serviceName) {
        const keys = Array.from(this.serviceStates.keys())
            .filter(key => key.includes(serviceName));

        keys.forEach(key => {
            this.serviceStates.delete(key);
            this.lastAlertTime.delete(key);
            this.alertCounts.delete(key);
            this.suppressedCount.delete(key);
        });
    }
}

/**
 * Example usage
 */
if (require.main === module) {
    console.log('Improved Alerting System Demo\n');

    const alerting = new ImprovedAlertingSystem({
        channels: ['console'],
        stateChangeOnly: true,
        exponentialBackoff: true,
        cooldown: 5000  // 5 seconds for demo
    });

    // Simulate service health checks every 5 seconds
    const services = ['webhook-audio-tracker', 'saas-api', 'api-gateway'];
    let checkCount = 0;

    const simulateHealthCheck = async () => {
        checkCount++;
        console.log(`\n--- Health Check #${checkCount} ---`);

        for (const service of services) {
            // Service is down
            await alerting.processAlert({
                type: 'service_down',
                severity: 'critical',
                service: service,
                message: `${service} is not available`,
                source: 'monitoring'
            });
        }

        if (checkCount === 5) {
            // After 5 checks, simulate recovery
            console.log('\n--- Simulating Service Recovery ---');
            await alerting.processAlert({
                type: 'service_up',
                severity: 'info',
                service: services[0],
                message: `${services[0]} is now available`,
                source: 'monitoring'
            });
        }

        if (checkCount < 10) {
            setTimeout(simulateHealthCheck, 5000);
        } else {
            console.log('\n--- Final Statistics ---');
            console.log(JSON.stringify(alerting.getStats(), null, 2));
            console.log('\nDemo complete. Notice how duplicate alerts were suppressed!');
            process.exit(0);
        }
    };

    simulateHealthCheck();
}

module.exports = ImprovedAlertingSystem;
