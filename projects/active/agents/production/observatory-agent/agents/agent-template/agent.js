#!/usr/bin/env node
// Multi-Agent Observatory - Agent Template
import WebSocket from 'ws';
import { v4 as uuidv4 } from 'uuid';
import ObservatoryHooks from './hooks.js';

class ObservatoryAgent {
    constructor(agentName, serverUrl = 'ws://localhost:8080/ws', options = {}) {
        this.agentName = agentName || `Agent-${uuidv4().substr(0, 8)}`;
        this.serverUrl = serverUrl;
        this.options = {
            reconnectInterval: 5000,
            heartbeatInterval: 30000,
            maxReconnectAttempts: 10,
            ...options
        };
        
        this.ws = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.heartbeatTimer = null;
        this.reconnectTimer = null;
        
        // Initialize monitoring hooks
        this.hooks = new ObservatoryHooks({
            metricsInterval: 5000,
            ...options.hooks
        });
        
        this.setupHooks();
        this.connect();
        
        // Graceful shutdown handling
        this.setupShutdownHandlers();
    }

    setupHooks() {
        // Listen for metrics from hooks
        this.hooks.on('metrics', (data) => {
            this.sendMetrics(data.metrics);
        });

        // Listen for events from hooks
        this.hooks.on('event', (event) => {
            this.sendEvent(event.eventType, event.severity, event.message, event.data);
        });

        console.log(`🔧 Agent ${this.agentName} hooks configured`);
    }

    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            console.log(`⚠️ Agent ${this.agentName} is already connected`);
            return;
        }

        console.log(`🔌 Agent ${this.agentName} connecting to ${this.serverUrl}...`);
        
        try {
            this.ws = new WebSocket(this.serverUrl);
            this.setupWebSocketHandlers();
        } catch (error) {
            console.error(`❌ Connection failed for ${this.agentName}:`, error.message);
            this.scheduleReconnect();
        }
    }

    setupWebSocketHandlers() {
        this.ws.on('open', () => {
            console.log(`✅ Agent ${this.agentName} connected to observatory server`);
            this.isConnected = true;
            this.reconnectAttempts = 0;
            
            // Register with server
            this.register();
            
            // Start heartbeat
            this.startHeartbeat();
            
            // Log connection event
            this.hooks.logEvent('info', 'connection_established', 
                `Connected to observatory server at ${this.serverUrl}`);
        });

        this.ws.on('message', (data) => {
            try {
                const message = JSON.parse(data.toString());
                this.handleServerMessage(message);
            } catch (error) {
                console.error(`❌ Invalid message from server:`, error.message);
            }
        });

        this.ws.on('close', (code, reason) => {
            console.log(`🔌 Agent ${this.agentName} disconnected: ${code} ${reason}`);
            this.isConnected = false;
            this.stopHeartbeat();
            
            this.hooks.logEvent('warning', 'connection_lost', 
                `Disconnected from server: ${code} ${reason}`);
            
            // Attempt reconnection
            this.scheduleReconnect();
        });

        this.ws.on('error', (error) => {
            console.error(`❌ WebSocket error for ${this.agentName}:`, error.message);
            this.hooks.logEvent('error', 'websocket_error', error.message);
        });
    }

    handleServerMessage(message) {
        switch (message.type) {
            case 'welcome':
                console.log(`👋 Server welcome: ${message.message}`);
                break;
                
            case 'registered':
                console.log(`✅ Agent ${this.agentName} registered successfully`);
                this.hooks.logEvent('info', 'registration_success', 'Agent registered with server');
                break;
                
            case 'heartbeat_ack':
                // Heartbeat acknowledged, no action needed
                break;
                
            case 'error':
                console.error(`❌ Server error: ${message.error}`);
                this.hooks.logEvent('error', 'server_error', message.error);
                break;
                
            default:
                console.log(`📨 Unknown message type: ${message.type}`, message);
        }
    }

    register() {
        const metadata = {
            version: '1.0.0',
            nodeVersion: process.version,
            platform: process.platform,
            arch: process.arch,
            pid: process.pid,
            startTime: new Date().toISOString()
        };

        this.sendMessage({
            type: 'register',
            agentName: this.agentName,
            metadata
        });

        console.log(`📝 Agent ${this.agentName} registration sent`);
    }

    sendMetrics(metrics) {
        if (!this.isConnected) return;

        this.sendMessage({
            type: 'metrics',
            metrics,
            timestamp: new Date().toISOString()
        });
    }

    sendEvent(eventType, severity, eventMessage, data = {}) {
        if (!this.isConnected) return;

        this.sendMessage({
            type: 'event',
            eventType,
            severity,
            eventMessage,
            data,
            timestamp: new Date().toISOString()
        });
    }

    sendStatusUpdate(status) {
        if (!this.isConnected) return;

        this.sendMessage({
            type: 'status',
            status,
            timestamp: new Date().toISOString()
        });

        console.log(`📱 Status update sent: ${status}`);
    }

    sendMessage(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        } else {
            console.warn(`⚠️ Cannot send message, WebSocket not ready:`, message.type);
        }
    }

    startHeartbeat() {
        this.heartbeatTimer = setInterval(() => {
            if (this.isConnected) {
                this.sendMessage({
                    type: 'heartbeat',
                    timestamp: new Date().toISOString()
                });
            }
        }, this.options.heartbeatInterval);

        console.log(`💓 Heartbeat started (${this.options.heartbeatInterval}ms interval)`);
    }

    stopHeartbeat() {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
            console.log(`💓 Heartbeat stopped`);
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts >= this.options.maxReconnectAttempts) {
            console.error(`❌ Max reconnection attempts reached for ${this.agentName}`);
            this.hooks.logEvent('critical', 'max_reconnect_attempts', 
                'Unable to reconnect to server after maximum attempts');
            return;
        }

        this.reconnectAttempts++;
        console.log(`🔄 Scheduling reconnection attempt ${this.reconnectAttempts}/${this.options.maxReconnectAttempts} in ${this.options.reconnectInterval}ms`);
        
        this.reconnectTimer = setTimeout(() => {
            this.connect();
        }, this.options.reconnectInterval);
    }

    // Public methods for custom agent behavior
    performWork() {
        // Override this method in specific agent implementations
        console.log(`🔄 Agent ${this.agentName} performing work...`);
        
        // Example: simulate some work and log metrics
        this.hooks.measurePerformance('work_task', () => {
            // Simulate work
            const start = Date.now();
            while (Date.now() - start < Math.random() * 100) {
                // Busy work
            }
        });

        this.hooks.logEvent('info', 'work_completed', 'Completed scheduled work task');
    }

    // Get current status for health checks
    getStatus() {
        const health = this.hooks.getHealthStatus();
        return {
            agentName: this.agentName,
            connected: this.isConnected,
            reconnectAttempts: this.reconnectAttempts,
            uptime: process.uptime(),
            ...health
        };
    }

    setupShutdownHandlers() {
        const shutdown = async () => {
            console.log(`🛑 Shutting down agent ${this.agentName}...`);
            
            // Send final status
            this.sendStatusUpdate('shutting_down');
            
            // Stop timers
            this.stopHeartbeat();
            if (this.reconnectTimer) {
                clearTimeout(this.reconnectTimer);
            }
            
            // Close WebSocket
            if (this.ws) {
                this.ws.close(1000, 'Agent shutting down');
            }
            
            // Cleanup hooks
            this.hooks.destroy();
            
            console.log(`✅ Agent ${this.agentName} shutdown complete`);
            process.exit(0);
        };

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        process.on('SIGQUIT', shutdown);
    }

    // Start the agent's main work loop
    start() {
        console.log(`🚀 Starting agent ${this.agentName}`);
        
        // Perform initial work
        this.performWork();
        
        // Schedule periodic work (every 10 seconds)
        setInterval(() => {
            this.performWork();
        }, 10000);
        
        console.log(`✅ Agent ${this.agentName} started and running`);
    }
}

// If run directly, create and start an agent
if (import.meta.url === `file://${process.argv[1]}`) {
    const agentName = process.argv[2] || process.env.AGENT_NAME || 'Agent-Template';
    const serverUrl = process.argv[3] || process.env.OBSERVATORY_SERVER || 'ws://localhost:8080/ws';
    
    console.log(`🏗️ Creating agent: ${agentName}`);
    const agent = new ObservatoryAgent(agentName, serverUrl);
    agent.start();
}

export default ObservatoryAgent;