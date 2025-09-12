#!/usr/bin/env node
import ObservatoryAgent from '../agent-template/agent.js';

class MonitorAgent extends ObservatoryAgent {
    constructor(serverUrl) {
        super('Agent-5', serverUrl);
        this.monitorsExecuted = 0;
    }

    performWork() {
        this.hooks.measurePerformance('system_monitoring', () => {
            const alertsGenerated = Math.floor(Math.random() * 3);
            this.monitorsExecuted++;
            this.hooks.storeMetric('alerts_generated', alertsGenerated, 'count');
            this.hooks.storeMetric('monitor_executions', this.monitorsExecuted, 'count');
            
            if (alertsGenerated > 0) {
                this.hooks.logEvent('warning', 'system_alert', `Generated ${alertsGenerated} system alerts`);
            }
        });
        
        console.log(`🎯 Agent-5: Executed ${this.monitorsExecuted} monitoring cycles`);
    }
}

const agent = new MonitorAgent(process.env.OBSERVATORY_SERVER || 'ws://localhost:8080/ws');
agent.start();