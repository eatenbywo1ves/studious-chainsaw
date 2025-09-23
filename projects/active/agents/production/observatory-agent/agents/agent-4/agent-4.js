#!/usr/bin/env node
import ObservatoryAgent from '../agent-template/agent.js';

class ReporterAgent extends ObservatoryAgent {
    constructor(serverUrl) {
        super('Agent-4', serverUrl);
        this.reportsGenerated = 0;
    }

    performWork() {
        this.hooks.measurePerformance('report_generation', () => {
            const reportSize = Math.floor(Math.random() * 1000) + 500;
            this.reportsGenerated++;
            this.hooks.storeMetric('report_size', reportSize, 'KB');
            this.hooks.storeMetric('reports_generated', this.reportsGenerated, 'count');
        });
        
        console.log(`📄 Agent-4: Generated ${this.reportsGenerated} reports`);
    }
}

const agent = new ReporterAgent(process.env.OBSERVATORY_SERVER || 'ws://localhost:8080/ws');
agent.start();