#!/usr/bin/env node
// Agent 2 - Data Processor Agent
import ObservatoryAgent from '../agent-template/agent.js';

class DataProcessorAgent extends ObservatoryAgent {
    constructor(serverUrl) {
        super('Agent-2', serverUrl, {
            heartbeatInterval: 30000,
            hooks: { metricsInterval: 6000 }
        });
        
        this.processedJobs = 0;
        this.processingQueue = [];
    }

    performWork() {
        // Simulate data processing work
        this.hooks.measurePerformance('data_processing', () => {
            // Add jobs to processing queue
            const newJobs = Math.floor(Math.random() * 5) + 1;
            for (let i = 0; i < newJobs; i++) {
                this.processingQueue.push({
                    jobId: `job-${Date.now()}-${i}`,
                    complexity: Math.random(),
                    createdAt: Date.now()
                });
            }
            
            // Process jobs
            const jobsToProcess = Math.min(3, this.processingQueue.length);
            for (let i = 0; i < jobsToProcess; i++) {
                const job = this.processingQueue.shift();
                const processingTime = job.complexity * 100; // Simulate processing time
                
                // Simulate actual processing delay
                const start = Date.now();
                while (Date.now() - start < processingTime) {}
                
                this.processedJobs++;
                this.hooks.storeMetric('job_processing_time', processingTime, 'ms');
            }
            
            this.hooks.storeMetric('queue_size', this.processingQueue.length, 'count');
            this.hooks.storeMetric('jobs_processed_total', this.processedJobs, 'count');
        });

        if (this.processingQueue.length > 10) {
            this.hooks.logEvent('warning', 'queue_overflow', 'Processing queue is getting full');
        }
        
        console.log(`⚙️ Agent-2: Processed ${this.processedJobs} jobs, queue: ${this.processingQueue.length}`);
    }
}

const serverUrl = process.env.OBSERVATORY_SERVER || 'ws://localhost:8080/ws';
const agent = new DataProcessorAgent(serverUrl);
agent.start();