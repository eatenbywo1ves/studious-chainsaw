#!/usr/bin/env bun
// Database initialization script
import ObservatoryDatabase from './database.js';

console.log('🚀 Initializing Multi-Agent Observatory Database...');

try {
    const db = new ObservatoryDatabase();
    
    // Create sample agents for testing
    const sampleAgents = [
        { name: 'Agent-1', status: 'active', metadata: { role: 'data-collector', version: '1.0.0' } },
        { name: 'Agent-2', status: 'active', metadata: { role: 'processor', version: '1.0.0' } },
        { name: 'Agent-3', status: 'inactive', metadata: { role: 'analyzer', version: '1.0.0' } },
        { name: 'Agent-4', status: 'active', metadata: { role: 'reporter', version: '1.0.0' } },
        { name: 'Agent-5', status: 'active', metadata: { role: 'monitor', version: '1.0.0' } }
    ];

    console.log('📝 Creating sample agents...');
    for (const agent of sampleAgents) {
        db.registerAgent(agent.name, agent.status, agent.metadata);
    }

    // Insert sample metrics
    console.log('📊 Inserting sample metrics...');
    const agents = db.getAllAgents();
    for (const agent of agents) {
        // CPU usage
        db.insertMetric(agent.id, 'cpu_usage', Math.random() * 100, '%');
        // Memory usage
        db.insertMetric(agent.id, 'memory_usage', Math.random() * 8192, 'MB');
        // Network activity
        db.insertMetric(agent.id, 'network_rx', Math.random() * 1000, 'MB/s');
        db.insertMetric(agent.id, 'network_tx', Math.random() * 500, 'MB/s');
    }

    // Insert sample events
    console.log('📅 Inserting sample events...');
    const eventTypes = ['startup', 'error', 'warning', 'info', 'performance'];
    const severities = ['info', 'warning', 'error', 'critical'];
    
    for (const agent of agents) {
        const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
        const severity = severities[Math.floor(Math.random() * severities.length)];
        
        db.insertEvent(
            agent.id,
            eventType,
            severity,
            `Sample ${eventType} event for ${agent.name}`,
            { source: 'init-script', timestamp: Date.now() }
        );
    }

    console.log('📈 Database statistics:');
    const stats = db.getSystemStats();
    console.log(`  • Total Agents: ${stats.totalAgents}`);
    console.log(`  • Active Agents: ${stats.activeAgents}`);
    console.log(`  • Recent Metrics: ${stats.recentMetricsCount}`);
    console.log(`  • Recent Events: ${stats.recentEventsCount}`);

    db.close();
    console.log('✅ Database initialization completed successfully!');
    
} catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    process.exit(1);
}