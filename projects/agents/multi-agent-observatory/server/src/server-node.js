#!/usr/bin/env node
// Multi-Agent Observatory Server - Node.js Compatible Version
const { WebSocketServer } = require('ws');
const { createServer } = require('http');
const { randomUUID } = require('crypto');
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

class ObservatoryDatabase {
    constructor(dbPath = './database/observatory.db') {
        this.db = new Database(dbPath);
        this.initDatabase();
        this.prepareStatements();
    }

    initDatabase() {
        const schemaPath = path.join(__dirname, '../database/schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf8');
        this.db.exec(schema);
        console.log('✓ Database initialized with schema');
    }

    prepareStatements() {
        this.statements = {
            registerAgent: this.db.prepare(`INSERT OR REPLACE INTO agents (name, status, metadata) VALUES (?, ?, ?)`),
            updateAgentStatus: this.db.prepare(`UPDATE agents SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE name = ?`),
            getAgent: this.db.prepare(`SELECT * FROM agents WHERE name = ?`),
            getAllAgents: this.db.prepare(`SELECT * FROM agents ORDER BY created_at`),
            insertMetric: this.db.prepare(`INSERT INTO metrics (agent_id, metric_name, value, unit) VALUES (?, ?, ?, ?)`),
            getRecentMetrics: this.db.prepare(`
                SELECT m.*, a.name as agent_name FROM metrics m 
                JOIN agents a ON m.agent_id = a.id 
                WHERE m.timestamp >= datetime('now', '-1 hour') 
                ORDER BY m.timestamp DESC
            `),
            insertEvent: this.db.prepare(`INSERT INTO events (agent_id, event_type, severity, message, data) VALUES (?, ?, ?, ?, ?)`),
            getRecentEvents: this.db.prepare(`
                SELECT e.*, a.name as agent_name FROM events e 
                JOIN agents a ON e.agent_id = a.id 
                WHERE e.timestamp >= datetime('now', '-1 hour') 
                ORDER BY e.timestamp DESC LIMIT 100
            `)
        };
    }

    registerAgent(name, status = 'active', metadata = {}) {
        try {
            const result = this.statements.registerAgent.run(name, status, JSON.stringify(metadata));
            console.log(`✓ Agent registered: ${name}`);
            return result.lastInsertRowid;
        } catch (error) {
            console.error(`Failed to register agent ${name}:`, error.message);
            throw error;
        }
    }

    updateAgentStatus(name, status) {
        try {
            this.statements.updateAgentStatus.run(status, name);
        } catch (error) {
            console.error(`Failed to update agent status for ${name}:`, error.message);
        }
    }

    getAgent(name) {
        return this.statements.getAgent.get(name);
    }

    getAllAgents() {
        return this.statements.getAllAgents.all();
    }

    insertMetric(agentId, metricName, value, unit = null) {
        try {
            this.statements.insertMetric.run(agentId, metricName, value, unit);
        } catch (error) {
            console.error(`Failed to insert metric:`, error.message);
        }
    }

    insertEvent(agentId, eventType, severity = 'info', message = '', data = {}) {
        try {
            this.statements.insertEvent.run(agentId, eventType, severity, message, JSON.stringify(data));
        } catch (error) {
            console.error(`Failed to insert event:`, error.message);
        }
    }

    getRecentMetrics() {
        return this.statements.getRecentMetrics.all();
    }

    getRecentEvents() {
        return this.statements.getRecentEvents.all();
    }

    getSystemStats() {
        const agents = this.getAllAgents();
        const recentMetrics = this.getRecentMetrics();
        const recentEvents = this.getRecentEvents();

        return {
            totalAgents: agents.length,
            activeAgents: agents.filter(a => a.status === 'active').length,
            recentMetricsCount: recentMetrics.length,
            recentEventsCount: recentEvents.length,
            timestamp: new Date().toISOString()
        };
    }

    close() {
        this.db.close();
    }
}

class ObservatoryServer {
    constructor(port = 8080) {
        this.port = port;
        this.db = new ObservatoryDatabase();
        this.connections = new Map();
        this.agentHeartbeats = new Map();
        
        this.initServer();
        this.startHeartbeatMonitor();
    }

    initServer() {
        this.httpServer = createServer((req, res) => {
            this.handleHttpRequest(req, res);
        });

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
            switch (url.pathname) {
                case '/health':
                    this.handleHealth(req, res);
                    break;
                case '/api/agents':
                    this.handleAgentsAPI(req, res);
                    break;
                case '/api/metrics':
                    this.handleMetricsAPI(req, res);
                    break;
                case '/api/events':
                    this.handleEventsAPI(req, res);
                    break;
                case '/api/stats':
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
        const connectionId = randomUUID();
        const clientIP = req.socket.remoteAddress;
        
        console.log(`🔌 New WebSocket connection: ${connectionId} from ${clientIP}`);

        let agentInfo = null;

        ws.on('message', async (data) => {
            try {
                const message = JSON.parse(data.toString());
                await this.handleWebSocketMessage(ws, connectionId, message, agentInfo);
                
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
            }
        });

        ws.on('close', () => {
            console.log(`🔌 WebSocket disconnected: ${connectionId}`);
            this.connections.delete(connectionId);
            
            if (agentInfo) {
                this.db.updateAgentStatus(agentInfo.agentName, 'inactive');
                this.broadcastAgentStatusUpdate(agentInfo.agentName, 'inactive');
            }
        });

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
        }
    }

    async handleAgentRegister(ws, connectionId, message) {
        const { agentName, metadata = {} } = message;
        
        if (!agentName) {
            return this.sendError(ws, 'Agent name is required');
        }

        try {
            const agentId = this.db.registerAgent(agentName, 'active', metadata);
            this.agentHeartbeats.set(agentName, Date.now());
            
            this.sendMessage(ws, {
                type: 'registered',
                agentName,
                agentId,
                timestamp: new Date().toISOString()
            });

            this.broadcastToDashboards({
                type: 'agent_registered',
                agentName,
                status: 'active',
                metadata,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.sendError(ws, `Registration failed: ${error.message}`);
        }
    }

    async handleHeartbeat(ws, connectionId, message, agentInfo) {
        if (!agentInfo?.agentName) {
            return this.sendError(ws, 'Agent must register first');
        }

        this.agentHeartbeats.set(agentInfo.agentName, Date.now());
        
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
            for (const metric of metrics) {
                this.db.insertMetric(agentInfo.agentId, metric.name, metric.value, metric.unit);
            }

            this.broadcastToDashboards({
                type: 'metrics_update',
                agentName: agentInfo.agentName,
                metrics,
                timestamp: new Date().toISOString()
            });
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
            this.db.insertEvent(agentInfo.agentId, eventType, severity, eventMessage, data);

            this.broadcastToDashboards({
                type: 'event_update',
                agentName: agentInfo.agentName,
                eventType,
                severity,
                message: eventMessage,
                data,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.sendError(ws, `Failed to store event: ${error.message}`);
        }
    }

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

    startHeartbeatMonitor() {
        setInterval(() => {
            const now = Date.now();
            const timeout = 60000;
            
            for (const [agentName, lastHeartbeat] of this.agentHeartbeats) {
                if (now - lastHeartbeat > timeout) {
                    console.log(`⚠️ Agent ${agentName} heartbeat timeout`);
                    this.db.updateAgentStatus(agentName, 'inactive');
                    this.broadcastAgentStatusUpdate(agentName, 'inactive');
                    this.agentHeartbeats.delete(agentName);
                }
            }
        }, 30000);
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

if (require.main === module) {
    const server = new ObservatoryServer(process.env.PORT || 8080);
    server.start();

    process.on('SIGINT', () => {
        server.stop();
        process.exit(0);
    });
}

module.exports = ObservatoryServer;