#!/usr/bin/env bun
// Multi-Agent Observatory Server
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { v4 as uuidv4 } from 'uuid';
import ObservatoryDatabase from './database.js';

class ObservatoryServer {
    constructor(port = 8080) {
        this.port = port;
        this.db = new ObservatoryDatabase();
        this.connections = new Map(); // connectionId -> { ws, agentId, agentName }
        this.agentHeartbeats = new Map(); // agentName -> timestamp
        
        this.initServer();
        this.startHeartbeatMonitor();
    }

    initServer() {
        // Create HTTP server
        this.httpServer = createServer((req, res) => {
            this.handleHttpRequest(req, res);
        });

        // Create WebSocket server
        this.wss = new WebSocketServer({ 
            server: this.httpServer,
            path: '/ws'
        });

        this.wss.on('connection', (ws, req) => {
            this.handleWebSocketConnection(ws, req);
        });

        console.log(`🚀 Multi-Agent Observatory Server starting on port ${this.port}`);
    }

    handleHttpRequest(req, res) {
        // Enable CORS
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        if (req.method === 'OPTIONS') {
            res.writeHead(200);
            res.end();
            return;
        }

        const url = new URL(req.url, `http://localhost:${this.port}`);
        
        try {
            switch (true) {
                case url.pathname === '/health':
                    this.handleHealth(req, res);
                    break;
                    
                case url.pathname === '/api/agents':
                    this.handleAgentsAPI(req, res);
                    break;
                    
                case url.pathname === '/api/metrics':
                    this.handleMetricsAPI(req, res);
                    break;
                    
                case url.pathname === '/api/events':
                    this.handleEventsAPI(req, res);
                    break;
                    
                case url.pathname === '/api/stats':
                    this.handleStatsAPI(req, res);
                    break;
                    
                default:
                    this.handle404(req, res);
            }
        } catch (error) {
            this.handleError(res, error);
        }
    }

    handleWebSocketConnection(ws, req) {
        const connectionId = uuidv4();
        const clientIP = req.socket.remoteAddress;
        
        console.log(`🔌 New WebSocket connection: ${connectionId} from ${clientIP}`);

        // Connection state
        let agentInfo = null;

        ws.on('message', async (data) => {
            try {
                const message = JSON.parse(data.toString());
                await this.handleWebSocketMessage(ws, connectionId, message, agentInfo);
                
                // Update agent info after registration
                if (message.type === 'register' && message.agentName) {
                    agentInfo = {
                        agentName: message.agentName,
                        agentId: this.db.getAgent(message.agentName)?.id
                    };
                    this.connections.set(connectionId, {
                        ws,
                        agentId: agentInfo.agentId,
                        agentName: agentInfo.agentName,
                        connectedAt: new Date()
                    });
                }
            } catch (error) {
                console.error('❌ WebSocket message error:', error.message);
                this.sendError(ws, 'Invalid message format');
            }
        });

        ws.on('close', () => {
            console.log(`🔌 WebSocket disconnected: ${connectionId}`);
            this.connections.delete(connectionId);
            this.db.removeConnection(connectionId);
            
            if (agentInfo) {
                this.db.updateAgentStatus(agentInfo.agentName, 'inactive');
                this.broadcastAgentStatusUpdate(agentInfo.agentName, 'inactive');
            }
        });

        ws.on('error', (error) => {
            console.error(`❌ WebSocket error for ${connectionId}:`, error.message);
        });

        // Send welcome message
        this.sendMessage(ws, {
            type: 'welcome',
            connectionId,
            timestamp: new Date().toISOString(),
            message: 'Connected to Multi-Agent Observatory'
        });
    }

    async handleWebSocketMessage(ws, connectionId, message, agentInfo) {
        switch (message.type) {
            case 'register':
                await this.handleAgentRegister(ws, connectionId, message);
                break;
                
            case 'heartbeat':
                await this.handleHeartbeat(ws, connectionId, message, agentInfo);
                break;
                
            case 'metrics':
                await this.handleMetricsData(ws, connectionId, message, agentInfo);
                break;
                
            case 'event':
                await this.handleEventData(ws, connectionId, message, agentInfo);
                break;
                
            case 'status':
                await this.handleStatusUpdate(ws, connectionId, message, agentInfo);
                break;
                
            default:
                this.sendError(ws, `Unknown message type: ${message.type}`);
        }
    }

    async handleAgentRegister(ws, connectionId, message) {
        const { agentName, metadata = {} } = message;
        
        if (!agentName) {
            return this.sendError(ws, 'Agent name is required');
        }

        try {
            // Register or update agent
            const agentId = this.db.registerAgent(agentName, 'active', metadata);
            this.db.addConnection(agentId, connectionId, ws._socket?.remoteAddress);
            
            // Update heartbeat
            this.agentHeartbeats.set(agentName, Date.now());
            
            this.sendMessage(ws, {
                type: 'registered',
                agentName,
                agentId,
                timestamp: new Date().toISOString()
            });

            // Broadcast to all dashboard connections
            this.broadcastToDashboards({
                type: 'agent_registered',
                agentName,
                status: 'active',
                metadata,
                timestamp: new Date().toISOString()
            });

            console.log(`✅ Agent registered: ${agentName} (ID: ${agentId})`);
        } catch (error) {
            this.sendError(ws, `Registration failed: ${error.message}`);
        }
    }

    async handleHeartbeat(ws, connectionId, message, agentInfo) {
        if (!agentInfo?.agentName) {
            return this.sendError(ws, 'Agent must register first');
        }

        this.agentHeartbeats.set(agentInfo.agentName, Date.now());
        this.db.updatePing(connectionId);
        
        this.sendMessage(ws, {
            type: 'heartbeat_ack',
            timestamp: new Date().toISOString()
        });
    }

    async handleMetricsData(ws, connectionId, message, agentInfo) {
        if (!agentInfo?.agentId) {
            return this.sendError(ws, 'Agent must register first');
        }

        const { metrics } = message;
        if (!Array.isArray(metrics)) {
            return this.sendError(ws, 'Metrics must be an array');
        }

        try {
            // Store metrics in database
            for (const metric of metrics) {
                this.db.insertMetric(
                    agentInfo.agentId,
                    metric.name,
                    metric.value,
                    metric.unit
                );
            }

            // Broadcast to dashboards
            this.broadcastToDashboards({
                type: 'metrics_update',
                agentName: agentInfo.agentName,
                metrics,
                timestamp: new Date().toISOString()
            });

            console.log(`📊 Metrics received from ${agentInfo.agentName}: ${metrics.length} metrics`);
        } catch (error) {
            this.sendError(ws, `Failed to store metrics: ${error.message}`);
        }
    }

    async handleEventData(ws, connectionId, message, agentInfo) {
        if (!agentInfo?.agentId) {
            return this.sendError(ws, 'Agent must register first');
        }

        const { eventType, severity = 'info', eventMessage, data = {} } = message;
        
        try {
            this.db.insertEvent(
                agentInfo.agentId,
                eventType,
                severity,
                eventMessage,
                data
            );

            // Broadcast to dashboards
            this.broadcastToDashboards({
                type: 'event_update',
                agentName: agentInfo.agentName,
                eventType,
                severity,
                message: eventMessage,
                data,
                timestamp: new Date().toISOString()
            });

            console.log(`📅 Event from ${agentInfo.agentName}: ${eventType} (${severity})`);
        } catch (error) {
            this.sendError(ws, `Failed to store event: ${error.message}`);
        }
    }

    async handleStatusUpdate(ws, connectionId, message, agentInfo) {
        if (!agentInfo?.agentName) {
            return this.sendError(ws, 'Agent must register first');
        }

        const { status } = message;
        
        try {
            this.db.updateAgentStatus(agentInfo.agentName, status);
            this.broadcastAgentStatusUpdate(agentInfo.agentName, status);
            
            console.log(`📱 Status update from ${agentInfo.agentName}: ${status}`);
        } catch (error) {
            this.sendError(ws, `Failed to update status: ${error.message}`);
        }
    }

    // HTTP API handlers
    handleHealth(req, res) {
        const stats = this.db.getSystemStats();
        const response = {
            status: 'healthy',
            uptime: process.uptime(),
            connections: this.connections.size,
            ...stats
        };
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response, null, 2));
    }

    handleAgentsAPI(req, res) {
        const agents = this.db.getAllAgents();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(agents));
    }

    handleMetricsAPI(req, res) {
        const metrics = this.db.getRecentMetrics();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(metrics));
    }

    handleEventsAPI(req, res) {
        const events = this.db.getRecentEvents();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(events));
    }

    handleStatsAPI(req, res) {
        const stats = this.db.getSystemStats();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(stats));
    }

    handle404(req, res) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not Found' }));
    }

    handleError(res, error) {
        console.error('❌ HTTP request error:', error.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
    }

    // WebSocket utilities
    sendMessage(ws, message) {
        if (ws.readyState === ws.OPEN) {
            ws.send(JSON.stringify(message));
        }
    }

    sendError(ws, error) {
        this.sendMessage(ws, {
            type: 'error',
            error,
            timestamp: new Date().toISOString()
        });
    }

    broadcastToDashboards(message) {
        // Broadcast to all connected dashboard clients
        for (const [connectionId, connection] of this.connections) {
            if (connection.ws.readyState === connection.ws.OPEN) {
                this.sendMessage(connection.ws, message);
            }
        }
    }

    broadcastAgentStatusUpdate(agentName, status) {
        this.broadcastToDashboards({
            type: 'agent_status_update',
            agentName,
            status,
            timestamp: new Date().toISOString()
        });
    }

    // Heartbeat monitoring
    startHeartbeatMonitor() {
        setInterval(() => {
            const now = Date.now();
            const timeout = 60000; // 60 seconds timeout
            
            for (const [agentName, lastHeartbeat] of this.agentHeartbeats) {
                if (now - lastHeartbeat > timeout) {
                    console.log(`⚠️ Agent ${agentName} heartbeat timeout`);
                    this.db.updateAgentStatus(agentName, 'inactive');
                    this.broadcastAgentStatusUpdate(agentName, 'inactive');
                    this.agentHeartbeats.delete(agentName);
                }
            }
        }, 30000); // Check every 30 seconds
    }

    start() {
        this.httpServer.listen(this.port, () => {
            console.log(`✅ Multi-Agent Observatory Server running on:`);
            console.log(`   • HTTP API: http://localhost:${this.port}`);
            console.log(`   • WebSocket: ws://localhost:${this.port}/ws`);
            console.log(`   • Health Check: http://localhost:${this.port}/health`);
        });
    }

    stop() {
        console.log('🛑 Shutting down Multi-Agent Observatory Server...');
        this.wss.close();
        this.httpServer.close();
        this.db.close();
    }
}

// Start server if run directly
if (import.meta.main) {
    const server = new ObservatoryServer(process.env.PORT || 8080);
    server.start();

    // Graceful shutdown
    process.on('SIGINT', () => {
        server.stop();
        process.exit(0);
    });
}

export default ObservatoryServer;