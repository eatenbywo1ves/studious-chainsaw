// Database operations for Multi-Agent Observatory
import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join } from 'path';

class ObservatoryDatabase {
    constructor(dbPath = './database/observatory.db') {
        this.db = new Database(dbPath);
        this.initDatabase();
        this.prepareStatements();
    }

    initDatabase() {
        // Read and execute schema
        const schemaPath = join(import.meta.dir, '../database/schema.sql');
        const schema = readFileSync(schemaPath, 'utf8');
        this.db.exec(schema);
        
        console.log('✓ Database initialized with schema');
    }

    prepareStatements() {
        // Agent operations
        this.statements = {
            // Agent management
            registerAgent: this.db.prepare(`
                INSERT OR REPLACE INTO agents (name, status, metadata) 
                VALUES (?, ?, ?)
            `),
            
            updateAgentStatus: this.db.prepare(`
                UPDATE agents SET status = ?, last_seen = CURRENT_TIMESTAMP 
                WHERE name = ?
            `),
            
            getAgent: this.db.prepare(`
                SELECT * FROM agents WHERE name = ?
            `),
            
            getAllAgents: this.db.prepare(`
                SELECT * FROM agents ORDER BY created_at
            `),
            
            // Metrics operations
            insertMetric: this.db.prepare(`
                INSERT INTO metrics (agent_id, metric_name, value, unit) 
                VALUES (?, ?, ?, ?)
            `),
            
            getRecentMetrics: this.db.prepare(`
                SELECT m.*, a.name as agent_name 
                FROM metrics m 
                JOIN agents a ON m.agent_id = a.id 
                WHERE m.timestamp >= datetime('now', '-1 hour') 
                ORDER BY m.timestamp DESC
            `),
            
            getMetricsByAgent: this.db.prepare(`
                SELECT * FROM metrics 
                WHERE agent_id = ? AND timestamp >= datetime('now', '-1 hour')
                ORDER BY timestamp DESC
            `),
            
            // Events operations
            insertEvent: this.db.prepare(`
                INSERT INTO events (agent_id, event_type, severity, message, data) 
                VALUES (?, ?, ?, ?, ?)
            `),
            
            getRecentEvents: this.db.prepare(`
                SELECT e.*, a.name as agent_name 
                FROM events e 
                JOIN agents a ON e.agent_id = a.id 
                WHERE e.timestamp >= datetime('now', '-1 hour') 
                ORDER BY e.timestamp DESC 
                LIMIT 100
            `),
            
            // Connection management
            addConnection: this.db.prepare(`
                INSERT OR REPLACE INTO agent_connections 
                (agent_id, connection_id, ip_address) 
                VALUES (?, ?, ?)
            `),
            
            updatePing: this.db.prepare(`
                UPDATE agent_connections 
                SET last_ping = CURRENT_TIMESTAMP 
                WHERE connection_id = ?
            `),
            
            removeConnection: this.db.prepare(`
                DELETE FROM agent_connections WHERE connection_id = ?
            `),
            
            getActiveConnections: this.db.prepare(`
                SELECT ac.*, a.name as agent_name 
                FROM agent_connections ac 
                JOIN agents a ON ac.agent_id = a.id 
                WHERE ac.last_ping >= datetime('now', '-30 seconds')
            `)
        };
    }

    // Agent management methods
    registerAgent(name, status = 'active', metadata = {}) {
        try {
            const result = this.statements.registerAgent.run(
                name, 
                status, 
                JSON.stringify(metadata)
            );
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
            console.log(`✓ Agent ${name} status updated: ${status}`);
        } catch (error) {
            console.error(`Failed to update agent status for ${name}:`, error.message);
            throw error;
        }
    }

    getAgent(name) {
        return this.statements.getAgent.get(name);
    }

    getAllAgents() {
        return this.statements.getAllAgents.all();
    }

    // Metrics methods
    insertMetric(agentId, metricName, value, unit = null) {
        try {
            this.statements.insertMetric.run(agentId, metricName, value, unit);
        } catch (error) {
            console.error(`Failed to insert metric:`, error.message);
            throw error;
        }
    }

    getRecentMetrics() {
        return this.statements.getRecentMetrics.all();
    }

    getMetricsByAgent(agentId) {
        return this.statements.getMetricsByAgent.all(agentId);
    }

    // Events methods
    insertEvent(agentId, eventType, severity = 'info', message = '', data = {}) {
        try {
            this.statements.insertEvent.run(
                agentId, 
                eventType, 
                severity, 
                message, 
                JSON.stringify(data)
            );
        } catch (error) {
            console.error(`Failed to insert event:`, error.message);
            throw error;
        }
    }

    getRecentEvents() {
        return this.statements.getRecentEvents.all();
    }

    // Connection management
    addConnection(agentId, connectionId, ipAddress) {
        try {
            this.statements.addConnection.run(agentId, connectionId, ipAddress);
        } catch (error) {
            console.error(`Failed to add connection:`, error.message);
            throw error;
        }
    }

    updatePing(connectionId) {
        this.statements.updatePing.run(connectionId);
    }

    removeConnection(connectionId) {
        this.statements.removeConnection.run(connectionId);
    }

    getActiveConnections() {
        return this.statements.getActiveConnections.all();
    }

    // Utility methods
    getSystemStats() {
        const agents = this.getAllAgents();
        const recentMetrics = this.getRecentMetrics();
        const recentEvents = this.getRecentEvents();
        const activeConnections = this.getActiveConnections();

        return {
            totalAgents: agents.length,
            activeAgents: agents.filter(a => a.status === 'active').length,
            inactiveAgents: agents.filter(a => a.status === 'inactive').length,
            recentMetricsCount: recentMetrics.length,
            recentEventsCount: recentEvents.length,
            activeConnections: activeConnections.length,
            timestamp: new Date().toISOString()
        };
    }

    close() {
        this.db.close();
    }
}

export default ObservatoryDatabase;