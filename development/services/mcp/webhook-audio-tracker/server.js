const express = require('express');
const WebSocket = require('ws');
const bodyParser = require('body-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const AudioManager = require('./audioManager');
const WorkflowTracker = require('./workflowTracker');

// Initialize logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'webhook-events.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

class WebhookAudioServer {
  constructor(port = 3000, wsPort = 3001) {
    this.app = express();
    this.port = port;
    this.wsPort = wsPort;
    this.audioManager = new AudioManager();
    this.workflowTracker = new WorkflowTracker();
    this.webhookEndpoints = new Map();
    this.activeWorkflows = new Map();
    
    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocket();
  }

  setupMiddleware() {
    this.app.use(cors());
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.urlencoded({ extended: true }));
    
    // Request logging middleware
    this.app.use((req, res, next) => {
      const requestId = uuidv4();
      req.requestId = requestId;
      logger.info('Incoming request', {
        requestId,
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: req.body
      });
      next();
    });
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        uptime: process.uptime(),
        endpoints: Array.from(this.webhookEndpoints.keys()),
        activeWorkflows: this.activeWorkflows.size
      });
    });

    // Register a new webhook endpoint
    this.app.post('/webhook/register', (req, res) => {
      const { name, description, audioProfile, workflowId } = req.body;
      const endpointId = uuidv4();
      
      this.webhookEndpoints.set(endpointId, {
        name,
        description,
        audioProfile: audioProfile || 'default',
        workflowId,
        created: new Date(),
        eventCount: 0
      });

      logger.info('Webhook endpoint registered', { endpointId, name });
      
      res.json({
        endpointId,
        url: `http://localhost:${this.port}/webhook/${endpointId}`,
        wsUrl: `ws://localhost:${this.wsPort}`
      });
    });

    // Dynamic webhook endpoint handler
    this.app.all('/webhook/:endpointId', async (req, res) => {
      const { endpointId } = req.params;
      const endpoint = this.webhookEndpoints.get(endpointId);
      
      if (!endpoint) {
        return res.status(404).json({ error: 'Endpoint not found' });
      }

      const event = {
        id: uuidv4(),
        endpointId,
        timestamp: new Date(),
        method: req.method,
        headers: req.headers,
        query: req.query,
        body: req.body,
        ip: req.ip
      };

      // Process the webhook event
      await this.processWebhookEvent(event, endpoint);
      
      res.json({ 
        success: true, 
        eventId: event.id,
        message: 'Webhook received and processed'
      });
    });

    // Workflow management endpoints
    this.app.post('/workflow/start', (req, res) => {
      const { name, steps, audioProfile } = req.body;
      const workflowId = uuidv4();
      
      const workflow = {
        id: workflowId,
        name,
        steps: steps || [],
        currentStep: 0,
        audioProfile: audioProfile || 'workflow',
        status: 'active',
        started: new Date(),
        events: []
      };

      this.activeWorkflows.set(workflowId, workflow);
      this.workflowTracker.startWorkflow(workflow);
      
      // Play workflow start sound
      this.audioManager.playSound('workflow_start', audioProfile);
      
      res.json({ workflowId, workflow });
    });

    this.app.post('/workflow/:workflowId/step', (req, res) => {
      const { workflowId } = req.params;
      const { stepName, status, data } = req.body;
      
      const workflow = this.activeWorkflows.get(workflowId);
      if (!workflow) {
        return res.status(404).json({ error: 'Workflow not found' });
      }

      // Update workflow progress
      this.workflowTracker.updateStep(workflowId, stepName, status);
      
      // Play appropriate sound based on status
      const soundType = status === 'completed' ? 'step_complete' : 
                       status === 'failed' ? 'step_failed' : 'step_progress';
      this.audioManager.playSound(soundType, workflow.audioProfile);
      
      // Broadcast update to WebSocket clients
      this.broadcastUpdate({
        type: 'workflow_step',
        workflowId,
        stepName,
        status,
        data
      });

      res.json({ success: true });
    });

    // Audio configuration endpoint
    this.app.post('/audio/configure', (req, res) => {
      const { profile, sounds } = req.body;
      this.audioManager.configureProfile(profile, sounds);
      res.json({ success: true, profile });
    });

    // Get all active webhooks
    this.app.get('/webhooks', (req, res) => {
      const webhooks = Array.from(this.webhookEndpoints.entries()).map(([id, data]) => ({
        id,
        ...data
      }));
      res.json(webhooks);
    });

    // Get workflow history
    this.app.get('/workflows', (req, res) => {
      const workflows = Array.from(this.activeWorkflows.entries()).map(([id, data]) => ({
        id,
        ...data
      }));
      res.json(workflows);
    });

    // Serve dashboard
    this.app.use(express.static('public'));
  }

  setupWebSocket() {
    this.wss = new WebSocket.Server({ port: this.wsPort });
    
    this.wss.on('connection', (ws) => {
      logger.info('New WebSocket connection');
      
      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          this.handleWebSocketMessage(ws, data);
        } catch (error) {
          logger.error('Invalid WebSocket message', error);
        }
      });

      // Send initial state
      ws.send(JSON.stringify({
        type: 'initial_state',
        webhooks: Array.from(this.webhookEndpoints.entries()),
        workflows: Array.from(this.activeWorkflows.entries())
      }));
    });
  }

  async processWebhookEvent(event, endpoint) {
    endpoint.eventCount++;
    
    // Log the event
    logger.info('Processing webhook event', {
      eventId: event.id,
      endpointName: endpoint.name,
      audioProfile: endpoint.audioProfile
    });

    // Play audio cue based on the endpoint's audio profile
    await this.audioManager.playWebhookSound(event, endpoint.audioProfile);

    // Track in workflow if applicable
    if (endpoint.workflowId) {
      const workflow = this.activeWorkflows.get(endpoint.workflowId);
      if (workflow) {
        workflow.events.push(event);
        this.workflowTracker.recordEvent(endpoint.workflowId, event);
      }
    }

    // Broadcast to WebSocket clients
    this.broadcastUpdate({
      type: 'webhook_event',
      event,
      endpoint
    });
  }

  handleWebSocketMessage(ws, data) {
    switch (data.type) {
      case 'subscribe':
        // Handle subscription to specific webhook or workflow
        break;
      case 'test_audio':
        this.audioManager.playSound(data.soundType || 'test', data.profile || 'default');
        break;
      case 'mute':
        this.audioManager.setMuted(data.muted);
        break;
      default:
        logger.warn('Unknown WebSocket message type', data.type);
    }
  }

  broadcastUpdate(data) {
    const message = JSON.stringify(data);
    this.wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  start() {
    this.app.listen(this.port, () => {
      logger.info(`Webhook Audio Server listening on port ${this.port}`);
      logger.info(`WebSocket server listening on port ${this.wsPort}`);
    });
  }
}

// Start the server
const server = new WebhookAudioServer(
  process.env.PORT || 3000,
  process.env.WS_PORT || 3001
);
server.start();

module.exports = WebhookAudioServer;