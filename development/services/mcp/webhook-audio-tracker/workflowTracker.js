const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');

class WorkflowTracker extends EventEmitter {
  constructor() {
    super();
    this.workflows = new Map();
    this.workflowHistory = [];
    this.statsFile = path.join(__dirname, 'workflow_stats.json');
    this.loadStats();
  }

  async loadStats() {
    try {
      const data = await fs.readFile(this.statsFile, 'utf8');
      const stats = JSON.parse(data);
      this.workflowHistory = stats.history || [];
    } catch (error) {
      // File doesn't exist yet, start fresh
      this.workflowHistory = [];
    }
  }

  async saveStats() {
    try {
      const stats = {
        history: this.workflowHistory,
        summary: this.generateSummaryStats()
      };
      await fs.writeFile(this.statsFile, JSON.stringify(stats, null, 2));
    } catch (error) {
      console.error('Error saving workflow stats:', error);
    }
  }

  startWorkflow(workflow) {
    const enhancedWorkflow = {
      ...workflow,
      startTime: Date.now(),
      endTime: null,
      duration: null,
      steps: workflow.steps.map(step => ({
        name: step,
        status: 'pending',
        startTime: null,
        endTime: null,
        duration: null,
        attempts: 0,
        events: []
      })),
      events: [],
      metrics: {
        totalEvents: 0,
        successfulSteps: 0,
        failedSteps: 0,
        averageStepDuration: 0
      }
    };

    this.workflows.set(workflow.id, enhancedWorkflow);
    this.emit('workflow:started', enhancedWorkflow);
    
    return enhancedWorkflow;
  }

  updateStep(workflowId, stepName, status, data = {}) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return null;

    const step = workflow.steps.find(s => s.name === stepName);
    if (!step) {
      // Add new step if it doesn't exist
      const newStep = {
        name: stepName,
        status,
        startTime: status === 'in_progress' ? Date.now() : null,
        endTime: status === 'completed' || status === 'failed' ? Date.now() : null,
        duration: null,
        attempts: 1,
        events: [data]
      };
      workflow.steps.push(newStep);
    } else {
      // Update existing step
      step.status = status;
      step.attempts++;
      
      if (status === 'in_progress' && !step.startTime) {
        step.startTime = Date.now();
      } else if ((status === 'completed' || status === 'failed') && step.startTime) {
        step.endTime = Date.now();
        step.duration = step.endTime - step.startTime;
      }
      
      step.events.push({ timestamp: Date.now(), status, data });
    }

    // Update workflow metrics
    this.updateWorkflowMetrics(workflow);
    
    // Check if workflow is complete
    const allStepsComplete = workflow.steps.every(
      s => s.status === 'completed' || s.status === 'failed'
    );
    
    if (allStepsComplete && workflow.status !== 'completed') {
      this.completeWorkflow(workflowId);
    }

    this.emit('workflow:step:updated', { workflowId, stepName, status, workflow });
    
    return workflow;
  }

  recordEvent(workflowId, event) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return;

    workflow.events.push({
      timestamp: Date.now(),
      event
    });
    
    workflow.metrics.totalEvents++;
    
    this.emit('workflow:event', { workflowId, event, workflow });
  }

  completeWorkflow(workflowId) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return;

    workflow.status = 'completed';
    workflow.endTime = Date.now();
    workflow.duration = workflow.endTime - workflow.startTime;
    
    // Calculate final metrics
    this.updateWorkflowMetrics(workflow);
    
    // Add to history
    this.workflowHistory.push({
      id: workflowId,
      name: workflow.name,
      startTime: workflow.startTime,
      endTime: workflow.endTime,
      duration: workflow.duration,
      metrics: workflow.metrics,
      status: workflow.status
    });
    
    // Keep only last 100 workflows in history
    if (this.workflowHistory.length > 100) {
      this.workflowHistory = this.workflowHistory.slice(-100);
    }
    
    this.saveStats();
    this.emit('workflow:completed', workflow);
    
    return workflow;
  }

  updateWorkflowMetrics(workflow) {
    const metrics = {
      totalEvents: workflow.events.length,
      successfulSteps: workflow.steps.filter(s => s.status === 'completed').length,
      failedSteps: workflow.steps.filter(s => s.status === 'failed').length,
      pendingSteps: workflow.steps.filter(s => s.status === 'pending').length,
      inProgressSteps: workflow.steps.filter(s => s.status === 'in_progress').length
    };

    // Calculate average step duration
    const completedSteps = workflow.steps.filter(s => s.duration !== null);
    if (completedSteps.length > 0) {
      const totalDuration = completedSteps.reduce((sum, s) => sum + s.duration, 0);
      metrics.averageStepDuration = totalDuration / completedSteps.length;
    }

    // Calculate success rate
    const totalCompleted = metrics.successfulSteps + metrics.failedSteps;
    metrics.successRate = totalCompleted > 0 
      ? (metrics.successfulSteps / totalCompleted) * 100 
      : 0;

    workflow.metrics = metrics;
    return metrics;
  }

  getWorkflow(workflowId) {
    return this.workflows.get(workflowId);
  }

  getActiveWorkflows() {
    return Array.from(this.workflows.values()).filter(w => w.status === 'active');
  }

  generateSummaryStats() {
    const stats = {
      totalWorkflows: this.workflowHistory.length,
      averageDuration: 0,
      successRate: 0,
      commonFailurePoints: [],
      peakHours: {}
    };

    if (this.workflowHistory.length === 0) return stats;

    // Calculate average duration
    const durations = this.workflowHistory.filter(w => w.duration).map(w => w.duration);
    if (durations.length > 0) {
      stats.averageDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
    }

    // Calculate overall success rate
    const successfulWorkflows = this.workflowHistory.filter(w => 
      w.metrics && w.metrics.failedSteps === 0
    ).length;
    stats.successRate = (successfulWorkflows / this.workflowHistory.length) * 100;

    // Analyze peak hours
    this.workflowHistory.forEach(w => {
      const hour = new Date(w.startTime).getHours();
      stats.peakHours[hour] = (stats.peakHours[hour] || 0) + 1;
    });

    return stats;
  }

  // Pattern detection for workflow optimization
  detectPatterns(workflowId) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return null;

    const patterns = {
      bottlenecks: [],
      frequentFailures: [],
      optimizationOpportunities: []
    };

    // Find bottlenecks (steps that take significantly longer)
    const stepDurations = workflow.steps
      .filter(s => s.duration)
      .map(s => ({ name: s.name, duration: s.duration }));
    
    if (stepDurations.length > 0) {
      const avgDuration = stepDurations.reduce((sum, s) => sum + s.duration, 0) / stepDurations.length;
      patterns.bottlenecks = stepDurations
        .filter(s => s.duration > avgDuration * 1.5)
        .map(s => s.name);
    }

    // Find frequently failing steps
    patterns.frequentFailures = workflow.steps
      .filter(s => s.status === 'failed' || (s.attempts > 1 && s.status !== 'completed'))
      .map(s => ({ name: s.name, attempts: s.attempts }));

    // Suggest optimization opportunities
    if (patterns.bottlenecks.length > 0) {
      patterns.optimizationOpportunities.push({
        type: 'parallelize',
        message: `Consider parallelizing steps: ${patterns.bottlenecks.join(', ')}`
      });
    }

    if (patterns.frequentFailures.length > 0) {
      patterns.optimizationOpportunities.push({
        type: 'improve_reliability',
        message: `Improve reliability for steps: ${patterns.frequentFailures.map(f => f.name).join(', ')}`
      });
    }

    return patterns;
  }

  // Generate workflow report
  async generateReport(workflowId) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return null;

    const patterns = this.detectPatterns(workflowId);
    
    const report = {
      workflow: {
        id: workflowId,
        name: workflow.name,
        status: workflow.status,
        duration: workflow.duration,
        startTime: new Date(workflow.startTime).toISOString(),
        endTime: workflow.endTime ? new Date(workflow.endTime).toISOString() : null
      },
      metrics: workflow.metrics,
      steps: workflow.steps.map(s => ({
        name: s.name,
        status: s.status,
        duration: s.duration,
        attempts: s.attempts
      })),
      patterns,
      recommendations: this.generateRecommendations(workflow, patterns)
    };

    return report;
  }

  generateRecommendations(workflow, patterns) {
    const recommendations = [];

    // Performance recommendations
    if (workflow.metrics.averageStepDuration > 5000) {
      recommendations.push({
        priority: 'medium',
        category: 'performance',
        message: 'Consider optimizing long-running steps or adding progress indicators'
      });
    }

    // Reliability recommendations
    if (workflow.metrics.successRate < 80) {
      recommendations.push({
        priority: 'high',
        category: 'reliability',
        message: 'Success rate is below 80%. Review error handling and retry logic.'
      });
    }

    // Pattern-based recommendations
    if (patterns.bottlenecks.length > 0) {
      recommendations.push({
        priority: 'medium',
        category: 'optimization',
        message: `Bottlenecks detected in: ${patterns.bottlenecks.join(', ')}`
      });
    }

    return recommendations;
  }
}

module.exports = WorkflowTracker;