#!/usr/bin/env node
/**
 * Alerting System
 * Handles alert generation, routing, and notification delivery
 */

const fs = require('fs').promises;
const path = require('path');
const { EventEmitter } = require('events');

class AlertingSystem extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            enabled: config.enabled !== false,
            channels: config.channels || ['console', 'file'],
            rules: config.rules || [],
            escalation: config.escalation || {},
            cooldown: config.cooldown || 300000, // 5 minutes
            retention: config.retention || 86400000, // 24 hours
            ...config
        };
        
        this.alerts = new Map();
        this.activeAlerts = new Map();
        this.alertHistory = [];
        this.cooldownTimers = new Map();
        this.channels = new Map();
        
        this.setupChannels();
        this.setupEscalation();
    }

    setupChannels() {
        // Console channel
        this.channels.set('console', {
            send: (alert) => {
                const color = this.getAlertColor(alert.severity);
                const reset = '\x1b[0m';
                const timestamp = new Date(alert.timestamp).toLocaleString();
                console.log(`${color}[ALERT ${alert.severity.toUpperCase()}] ${timestamp}: ${alert.message}${reset}`);
                if (alert.details) {
                    console.log(`${color}Details: ${JSON.stringify(alert.details, null, 2)}${reset}`);
                }
            }
        });

        // File channel
        this.channels.set('file', {
            send: async (alert) => {
                const logEntry = {
                    timestamp: new Date(alert.timestamp).toISOString(),
                    severity: alert.severity,
                    type: alert.type,
                    message: alert.message,
                    details: alert.details,
                    source: alert.source
                };
                
                const logPath = path.join(__dirname, 'logs', this.config.logFile || 'alerts.log');
                await this.ensureLogDirectory();
                await fs.appendFile(logPath, JSON.stringify(logEntry) + '\n');
            }
        });

        // Email channel (placeholder - would need email service integration)
        this.channels.set('email', {
            send: async (alert) => {
                console.log(`[EMAIL] Would send alert: ${alert.message}`);
                // Implementation would depend on email service (SendGrid, etc.)
            }
        });

        // Webhook channel
        this.channels.set('webhook', {
            send: async (alert) => {
                if (!this.config.webhook?.url) return;
                
                try {
                    const response = await fetch(this.config.webhook.url, {
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

                    if (!response.ok) {
                        throw new Error(`Webhook responded with ${response.status}`);
                    }
                } catch (error) {
                    console.error(`Failed to send webhook alert: ${error.message}`);
                }
            }
        });

        // Slack channel (placeholder)
        this.channels.set('slack', {
            send: async (alert) => {
                console.log(`[SLACK] Would send alert: ${alert.message}`);
                // Implementation would use Slack API
            }
        });

        // Discord channel (placeholder)
        this.channels.set('discord', {
            send: async (alert) => {
                console.log(`[DISCORD] Would send alert: ${alert.message}`);
                // Implementation would use Discord webhooks
            }
        });
    }

    setupEscalation() {
        // Set up escalation timers based on configuration
        if (this.config.escalation.enabled) {
            setInterval(() => {
                this.checkEscalation();
            }, this.config.escalation.checkInterval || 60000); // Check every minute
        }
    }

    async processAlert(alertData) {
        if (!this.config.enabled) return null;

        const alert = this.createAlert(alertData);
        
        // Check if this alert should be suppressed (cooldown)
        if (this.isInCooldown(alert)) {
            return null;
        }

        // Apply alert rules
        const processedAlert = this.applyRules(alert);
        if (!processedAlert) return null;

        // Store alert
        this.storeAlert(processedAlert);
        
        // Send through configured channels
        await this.sendAlert(processedAlert);
        
        // Set cooldown
        this.setCooldown(processedAlert);
        
        // Emit event
        this.emit('alert', processedAlert);
        
        return processedAlert;
    }

    createAlert(data) {
        const alert = {
            id: this.generateAlertId(),
            timestamp: Date.now(),
            severity: data.severity || 'warning',
            type: data.type || 'unknown',
            message: data.message || 'Unknown alert',
            source: data.source || 'monitoring',
            details: data.details || {},
            value: data.value,
            threshold: data.threshold,
            service: data.service,
            resolved: false,
            escalated: false,
            escalationLevel: 0,
            ...data
        };

        return alert;
    }

    applyRules(alert) {
        // Apply filtering rules
        for (const rule of this.config.rules) {
            if (rule.type === 'filter') {
                if (this.matchesRule(alert, rule.conditions)) {
                    if (rule.action === 'suppress') {
                        return null; // Suppress this alert
                    } else if (rule.action === 'modify') {
                        Object.assign(alert, rule.modifications);
                    }
                }
            }
        }

        // Apply severity rules
        for (const rule of this.config.rules) {
            if (rule.type === 'severity') {
                if (this.matchesRule(alert, rule.conditions)) {
                    alert.severity = rule.severity;
                }
            }
        }

        // Apply routing rules
        alert.channels = [...this.config.channels];
        for (const rule of this.config.rules) {
            if (rule.type === 'routing') {
                if (this.matchesRule(alert, rule.conditions)) {
                    alert.channels = rule.channels || alert.channels;
                }
            }
        }

        return alert;
    }

    matchesRule(alert, conditions) {
        for (const [key, value] of Object.entries(conditions)) {
            if (key === 'severity') {
                if (alert.severity !== value) return false;
            } else if (key === 'type') {
                if (alert.type !== value) return false;
            } else if (key === 'source') {
                if (alert.source !== value) return false;
            } else if (key === 'service') {
                if (alert.service !== value) return false;
            } else if (key === 'value_gt') {
                if (!alert.value || alert.value <= value) return false;
            } else if (key === 'value_lt') {
                if (!alert.value || alert.value >= value) return false;
            } else if (key === 'message_contains') {
                if (!alert.message.includes(value)) return false;
            }
        }
        return true;
    }

    isInCooldown(alert) {
        const cooldownKey = `${alert.type}_${alert.source}_${alert.service || 'global'}`;
        return this.cooldownTimers.has(cooldownKey);
    }

    setCooldown(alert) {
        const cooldownKey = `${alert.type}_${alert.source}_${alert.service || 'global'}`;
        const cooldownTime = this.getCooldownTime(alert);
        
        if (cooldownTime > 0) {
            this.cooldownTimers.set(cooldownKey, Date.now() + cooldownTime);
            
            setTimeout(() => {
                this.cooldownTimers.delete(cooldownKey);
            }, cooldownTime);
        }
    }

    getCooldownTime(alert) {
        // Different cooldown times based on severity
        const cooldowns = {
            critical: this.config.cooldown || 300000, // 5 minutes
            warning: (this.config.cooldown || 300000) * 2, // 10 minutes
            info: (this.config.cooldown || 300000) * 4 // 20 minutes
        };
        
        return cooldowns[alert.severity] || this.config.cooldown || 300000;
    }

    storeAlert(alert) {
        this.alerts.set(alert.id, alert);
        this.alertHistory.push(alert);
        
        // Mark as active if not resolved
        if (!alert.resolved) {
            this.activeAlerts.set(alert.id, alert);
        }
        
        // Clean old alerts
        this.cleanOldAlerts();
    }

    async sendAlert(alert) {
        const channels = alert.channels || this.config.channels;
        
        for (const channelName of channels) {
            const channel = this.channels.get(channelName);
            if (channel) {
                try {
                    await channel.send(alert);
                } catch (error) {
                    console.error(`Failed to send alert via ${channelName}:`, error.message);
                }
            }
        }
    }

    resolveAlert(alertId, resolvedBy = 'system') {
        const alert = this.alerts.get(alertId);
        if (!alert) return false;

        alert.resolved = true;
        alert.resolvedAt = Date.now();
        alert.resolvedBy = resolvedBy;
        
        this.activeAlerts.delete(alertId);
        
        this.emit('alert_resolved', alert);
        
        return true;
    }

    escalateAlert(alertId) {
        const alert = this.alerts.get(alertId);
        if (!alert) return false;

        alert.escalated = true;
        alert.escalationLevel++;
        alert.escalatedAt = Date.now();
        
        // Escalate to higher severity if configured
        if (this.config.escalation.increaseSeverity) {
            const severityLevels = ['info', 'warning', 'critical'];
            const currentIndex = severityLevels.indexOf(alert.severity);
            if (currentIndex < severityLevels.length - 1) {
                alert.severity = severityLevels[currentIndex + 1];
            }
        }
        
        // Send to escalation channels
        if (this.config.escalation.channels) {
            alert.channels = this.config.escalation.channels;
            this.sendAlert(alert);
        }
        
        this.emit('alert_escalated', alert);
        
        return true;
    }

    checkEscalation() {
        const escalationTimeout = this.config.escalation.timeout || 1800000; // 30 minutes
        const now = Date.now();
        
        for (const alert of this.activeAlerts.values()) {
            if (!alert.escalated && 
                alert.severity === 'critical' && 
                (now - alert.timestamp) > escalationTimeout) {
                this.escalateAlert(alert.id);
            }
        }
    }

    getAlerts(options = {}) {
        let alerts = Array.from(this.alerts.values());
        
        // Filter by options
        if (options.severity) {
            alerts = alerts.filter(a => a.severity === options.severity);
        }
        
        if (options.type) {
            alerts = alerts.filter(a => a.type === options.type);
        }
        
        if (options.source) {
            alerts = alerts.filter(a => a.source === options.source);
        }
        
        if (options.service) {
            alerts = alerts.filter(a => a.service === options.service);
        }
        
        if (options.active) {
            alerts = alerts.filter(a => !a.resolved);
        }
        
        if (options.since) {
            alerts = alerts.filter(a => a.timestamp > options.since);
        }
        
        // Sort by timestamp (newest first)
        alerts.sort((a, b) => b.timestamp - a.timestamp);
        
        // Limit results
        if (options.limit) {
            alerts = alerts.slice(0, options.limit);
        }
        
        return alerts;
    }

    getActiveAlerts() {
        return Array.from(this.activeAlerts.values())
            .sort((a, b) => b.timestamp - a.timestamp);
    }

    getAlertStats() {
        const now = Date.now();
        const last24h = this.alertHistory.filter(a => now - a.timestamp < 86400000);
        const lastHour = this.alertHistory.filter(a => now - a.timestamp < 3600000);
        
        const severityCounts = {
            critical: 0,
            warning: 0,
            info: 0
        };
        
        for (const alert of last24h) {
            severityCounts[alert.severity]++;
        }
        
        return {
            total: this.alertHistory.length,
            active: this.activeAlerts.size,
            last24h: last24h.length,
            lastHour: lastHour.length,
            severityCounts,
            avgResolutionTime: this.calculateAverageResolutionTime(last24h)
        };
    }

    calculateAverageResolutionTime(alerts) {
        const resolvedAlerts = alerts.filter(a => a.resolved && a.resolvedAt);
        if (resolvedAlerts.length === 0) return 0;
        
        const totalTime = resolvedAlerts.reduce((sum, alert) => {
            return sum + (alert.resolvedAt - alert.timestamp);
        }, 0);
        
        return Math.round(totalTime / resolvedAlerts.length);
    }

    cleanOldAlerts() {
        const cutoff = Date.now() - this.config.retention;
        
        // Clean alert history
        this.alertHistory = this.alertHistory.filter(a => a.timestamp > cutoff);
        
        // Clean stored alerts
        for (const [id, alert] of this.alerts.entries()) {
            if (alert.timestamp < cutoff) {
                this.alerts.delete(id);
            }
        }
    }

    async ensureLogDirectory() {
        const logDir = path.join(__dirname, 'logs');
        try {
            await fs.mkdir(logDir, { recursive: true });
        } catch (error) {
            // Directory might already exist
        }
    }

    getAlertColor(severity) {
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

    // Test alert generation
    async testAlert(severity = 'warning') {
        const testAlert = {
            type: 'test',
            severity,
            message: `Test alert with ${severity} severity`,
            source: 'alerting_system',
            details: {
                test: true,
                timestamp: new Date().toISOString()
            }
        };
        
        return await this.processAlert(testAlert);
    }

    // Bulk alert operations
    async resolveAllAlerts(source) {
        let resolved = 0;
        
        for (const alert of this.activeAlerts.values()) {
            if (!source || alert.source === source) {
                this.resolveAlert(alert.id, 'bulk_operation');
                resolved++;
            }
        }
        
        return resolved;
    }

    // Export alerts
    exportAlerts(format = 'json', options = {}) {
        const alerts = this.getAlerts(options);
        
        switch (format) {
            case 'json':
                return JSON.stringify(alerts, null, 2);
            case 'csv':
                return this.exportToCSV(alerts);
            default:
                return alerts;
        }
    }

    exportToCSV(alerts) {
        const headers = ['timestamp', 'severity', 'type', 'message', 'source', 'service', 'resolved'];
        const lines = [headers.join(',')];
        
        for (const alert of alerts) {
            const row = [
                new Date(alert.timestamp).toISOString(),
                alert.severity,
                alert.type,
                `"${alert.message.replace(/"/g, '""')}"`, // Escape quotes
                alert.source,
                alert.service || '',
                alert.resolved
            ];
            lines.push(row.join(','));
        }
        
        return lines.join('\n');
    }
}

module.exports = AlertingSystem;