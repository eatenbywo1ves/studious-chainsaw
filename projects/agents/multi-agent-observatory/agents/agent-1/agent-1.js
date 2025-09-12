#!/usr/bin/env node
// Agent 1 - Data Collector Agent
import ObservatoryAgent from '../agent-template/agent.js';

class DataCollectorAgent extends ObservatoryAgent {
    constructor(serverUrl) {
        super('Agent-1', serverUrl, {
            heartbeatInterval: 25000,
            hooks: {
                metricsInterval: 4000 // Collect metrics every 4 seconds
            }
        });
        
        this.collectionCount = 0;
        this.dataBuffer = [];
    }

    performWork() {
        // Simulate data collection work
        this.hooks.measurePerformance('data_collection', () => {
            // Simulate collecting data from various sources
            const dataPoints = [];
            for (let i = 0; i < Math.floor(Math.random() * 50) + 10; i++) {
                dataPoints.push({
                    id: i,
                    value: Math.random() * 1000,
                    timestamp: Date.now()
                });
            }
            
            this.dataBuffer.push(...dataPoints);
            this.collectionCount++;
            
            // Custom metrics
            this.hooks.storeMetric('data_points_collected', dataPoints.length, 'count');
            this.hooks.storeMetric('total_collections', this.collectionCount, 'count');
            this.hooks.storeMetric('buffer_size', this.dataBuffer.length, 'count');
            
            // Occasionally clear buffer to simulate processing
            if (this.dataBuffer.length > 200) {
                const processed = this.dataBuffer.splice(0, 100);
                this.hooks.logEvent('info', 'data_processed', 
                    `Processed ${processed.length} data points`);
                this.hooks.storeMetric('data_processed', processed.length, 'count');
            }
        });

        // Random events
        if (Math.random() < 0.1) { // 10% chance
            this.hooks.logEvent('warning', 'data_quality_issue', 
                'Detected anomalous data patterns');
        }
        
        if (Math.random() < 0.05) { // 5% chance
            this.hooks.logEvent('info', 'high_throughput', 
                'Data collection rate above threshold');
        }

        console.log(`📊 Agent-1: Collected ${this.collectionCount} batches, buffer: ${this.dataBuffer.length} items`);
    }
}

// Start the agent
const serverUrl = process.env.OBSERVATORY_SERVER || 'ws://localhost:8080/ws';
const agent = new DataCollectorAgent(serverUrl);
agent.start();