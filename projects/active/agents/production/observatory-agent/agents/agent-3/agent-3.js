#!/usr/bin/env node
import ObservatoryAgent from '../agent-template/agent.js';

class AnalyzerAgent extends ObservatoryAgent {
    constructor(serverUrl) {
        super('Agent-3', serverUrl, { heartbeatInterval: 35000 });
        this.analysisCount = 0;
    }

    performWork() {
        this.hooks.measurePerformance('data_analysis', () => {
            const analysisComplexity = Math.random() * 200;
            const start = Date.now();
            while (Date.now() - start < analysisComplexity) {}
            
            this.analysisCount++;
            this.hooks.storeMetric('analysis_complexity', analysisComplexity, 'ms');
            this.hooks.storeMetric('total_analyses', this.analysisCount, 'count');
        });
        
        if (Math.random() < 0.15) {
            this.hooks.logEvent('info', 'pattern_detected', 'Found interesting data pattern');
        }
        
        console.log(`🔍 Agent-3: Completed ${this.analysisCount} analyses`);
    }
}

const agent = new AnalyzerAgent(process.env.OBSERVATORY_SERVER || 'ws://localhost:8080/ws');
agent.start();