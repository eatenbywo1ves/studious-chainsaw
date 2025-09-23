#!/usr/bin/env node
/**
 * Claude Code Bridge API Server
 * Provides REST API and WebSocket endpoints for Claude Code integration
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import ClaudeCodeAgent from './claude-agent.js';

class ClaudeCodeBridgeServer {
    constructor(options = {}) {
        this.config = {
            host: options.host || '0.0.0.0',
            port: options.port || 3003,
            logger: {
                level: 'info'
            },
            ...options
        };

        // Initialize Fastify
        this.fastify = Fastify(this.config);

        // Initialize Claude Code Agent
        this.claudeAgent = new ClaudeCodeAgent(options.agent || {});

        // WebSocket connections
        this.wsConnections = new Map();

        this.setupMiddleware();
        this.setupRoutes();
        this.setupWebSocket();
        this.setupAgentEventHandlers();
    }

    /**
     * Setup middleware
     */
    setupMiddleware() {
        // CORS
        this.fastify.register(cors, {
            origin: true,
            credentials: true
        });

        // WebSocket support
        this.fastify.register(websocket);
    }

    /**
     * Setup REST API routes
     */
    setupRoutes() {
        // Health check
        this.fastify.get('/health', async (request, reply) => {
            const status = this.claudeAgent.getStatus();
            return {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                agent: status
            };
        });

        // Agent status
        this.fastify.get('/agent/status', async (request, reply) => {
            return this.claudeAgent.getStatus();
        });

        // Submit task to agent ecosystem
        this.fastify.post('/tasks/submit', async (request, reply) => {
            const { taskType, taskData, priority = false } = request.body;

            if (!taskType || !taskData) {
                return reply.code(400).send({
                    error: 'Missing required fields: taskType, taskData'
                });
            }

            try {
                const taskId = await this.claudeAgent.submitTask(taskType, taskData, priority);

                return {
                    success: true,
                    taskId: taskId,
                    message: 'Task submitted successfully',
                    timestamp: new Date().toISOString()
                };
            } catch (error) {
                return reply.code(500).send({
                    error: 'Failed to submit task',
                    details: error.message
                });
            }
        });

        // Get task queue
        this.fastify.get('/tasks/queue', async (request, reply) => {
            return {
                queueLength: this.claudeAgent.taskQueue.length,
                tasks: this.claudeAgent.getTaskQueue()
            };
        });

        // Clean up task queue
        this.fastify.post('/tasks/queue/cleanup', async (request, reply) => {
            const removedTasks = this.claudeAgent.cleanupTaskQueue();
            return {
                success: true,
                message: `Cleaned up ${removedTasks} old tasks`,
                removedTasks,
                timestamp: new Date().toISOString()
            };
        });

        // Process next task (for Claude Code to pull tasks)
        this.fastify.post('/tasks/next', async (request, reply) => {
            const task = this.claudeAgent.getNextTask();

            if (!task) {
                return {
                    task: null,
                    message: 'No tasks available'
                };
            }

            return {
                task: task,
                message: 'Task retrieved successfully'
            };
        });

        // Complete task
        this.fastify.post('/tasks/:taskId/complete', async (request, reply) => {
            const { taskId } = request.params;
            const { result, error } = request.body;

            try {
                const status = error ? 'failed' : 'completed';
                await this.claudeAgent.sendTaskResponse(taskId, status, result, error);

                return {
                    success: true,
                    message: `Task ${taskId} marked as ${status}`,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to complete task',
                    details: err.message
                });
            }
        });

        // Send task progress update
        this.fastify.post('/tasks/:taskId/progress', async (request, reply) => {
            const { taskId } = request.params;
            const { progress, message } = request.body;

            if (progress === undefined || progress < 0 || progress > 100) {
                return reply.code(400).send({
                    error: 'Progress must be a number between 0 and 100'
                });
            }

            try {
                // Send progress to Observatory
                this.claudeAgent.sendEvent('task_progress', 'info',
                    message || `Task ${taskId} progress: ${progress}%`, {
                    taskId,
                    progress,
                    timestamp: new Date().toISOString()
                });

                return {
                    success: true,
                    message: `Progress updated for task ${taskId}`,
                    progress,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to update task progress',
                    details: err.message
                });
            }
        });

        // Get agent capabilities
        this.fastify.get('/agent/capabilities', async (request, reply) => {
            return {
                capabilities: this.claudeAgent.config.capabilities,
                agentType: this.claudeAgent.agentType,
                version: '1.0.0'
            };
        });

        // Test connection to Director Agent
        this.fastify.post('/agent/test-connection', async (request, reply) => {
            try {
                const testTaskId = await this.claudeAgent.submitTask('connection_test', {
                    message: 'Testing connection to Director Agent',
                    timestamp: new Date().toISOString()
                });

                return {
                    success: true,
                    message: 'Test task submitted to Director Agent',
                    testTaskId,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to test connection',
                    details: err.message
                });
            }
        });

        // Get system metrics
        this.fastify.get('/system/metrics', async (request, reply) => {
            const status = this.claudeAgent.getStatus();
            return {
                ...status,
                server: {
                    host: this.config.host,
                    port: this.config.port,
                    wsConnections: this.wsConnections.size
                },
                timestamp: new Date().toISOString()
            };
        });

        // Enhanced capability discovery endpoints
        this.fastify.get('/capabilities/info', async (request, reply) => {
            return this.claudeAgent.getCapabilityInfo();
        });

        // Query for agents with specific capability
        this.fastify.post('/capabilities/query', async (request, reply) => {
            const { capability, filters = {} } = request.body;

            if (!capability) {
                return reply.code(400).send({
                    error: 'Capability parameter is required'
                });
            }

            try {
                const queryId = await this.claudeAgent.queryCapability(capability, filters);

                return {
                    success: true,
                    queryId,
                    message: `Capability query submitted for '${capability}'`,
                    capability,
                    filters,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to query capability',
                    details: err.message
                });
            }
        });

        // Announce capability updates
        this.fastify.post('/capabilities/announce', async (request, reply) => {
            const { updateType = 'update', capabilities = null } = request.body;

            try {
                await this.claudeAgent.announceCapabilityUpdate(updateType, capabilities);

                return {
                    success: true,
                    message: `Capability ${updateType} announced`,
                    updateType,
                    capabilities: capabilities || this.claudeAgent.config.capabilities,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to announce capability update',
                    details: err.message
                });
            }
        });

        // Get capability discovery events
        this.fastify.get('/capabilities/events', async (request, reply) => {
            const events = {
                recent_queries: [], // TODO: Implement event storage
                recent_announcements: [], // TODO: Implement event storage
                discovery_stats: {
                    total_queries_sent: 0,
                    total_responses_received: 0,
                    total_announcements_received: 0
                }
            };

            return {
                events,
                timestamp: new Date().toISOString()
            };
        });

        // Send metrics
        this.fastify.post('/metrics', async (request, reply) => {
            const { metrics } = request.body;

            if (!metrics) {
                return reply.code(400).send({
                    error: 'Missing metrics data'
                });
            }

            this.claudeAgent.sendMetrics(metrics);

            return {
                success: true,
                message: 'Metrics sent successfully'
            };
        });

        // Send event
        this.fastify.post('/events', async (request, reply) => {
            const { eventType, severity, message, data } = request.body;

            if (!eventType || !severity || !message) {
                return reply.code(400).send({
                    error: 'Missing required fields: eventType, severity, message'
                });
            }

            this.claudeAgent.sendEvent(eventType, severity, message, data || {});

            return {
                success: true,
                message: 'Event sent successfully'
            };
        });

        // Code analysis endpoint
        this.fastify.post('/analyze/code', async (request, reply) => {
            const { code, language, analysisType } = request.body;

            if (!code) {
                return reply.code(400).send({
                    error: 'Missing code to analyze'
                });
            }

            // Submit code analysis task
            const taskId = await this.claudeAgent.submitTask('code_analysis', {
                code: code,
                language: language || 'javascript',
                analysisType: analysisType || 'quality',
                required_capabilities: ['code_analysis', 'static_analysis']
            });

            return {
                success: true,
                taskId: taskId,
                message: 'Code analysis task submitted',
                estimatedTime: '30-60 seconds'
            };
        });

        // Project coordination endpoint
        this.fastify.post('/projects/coordinate', async (request, reply) => {
            const { projectDescription, requirements, priority } = request.body;

            if (!projectDescription) {
                return reply.code(400).send({
                    error: 'Missing project description'
                });
            }

            const taskId = await this.claudeAgent.submitTask('project_coordination', {
                description: projectDescription,
                requirements: requirements || [],
                priority: priority || false,
                required_capabilities: ['project_management', 'task_coordination']
            });

            return {
                success: true,
                taskId: taskId,
                message: 'Project coordination task submitted'
            };
        });

        // Progress monitoring endpoints

        // Subscribe to task progress updates
        this.fastify.post('/tasks/:taskId/progress/subscribe', async (request, reply) => {
            const { taskId } = request.params;

            try {
                await this.claudeAgent.subscribeToTaskProgress(taskId);

                return {
                    success: true,
                    message: `Subscribed to progress updates for task ${taskId}`,
                    taskId,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to subscribe to task progress',
                    details: err.message
                });
            }
        });

        // Send detailed progress update with sub-tasks
        this.fastify.post('/tasks/:taskId/progress/detailed', async (request, reply) => {
            const { taskId } = request.params;
            const { progress, phase, subTasks, message } = request.body;

            if (progress === undefined || progress < 0 || progress > 100) {
                return reply.code(400).send({
                    error: 'Progress must be a number between 0 and 100'
                });
            }

            try {
                await this.claudeAgent.sendProgressUpdate(taskId, progress, phase, subTasks, message);

                return {
                    success: true,
                    message: `Detailed progress updated for task ${taskId}`,
                    progress,
                    phase,
                    subTasks,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to update detailed progress',
                    details: err.message
                });
            }
        });

        // Report task performance metrics
        this.fastify.post('/tasks/:taskId/metrics', async (request, reply) => {
            const { taskId } = request.params;
            const { metrics } = request.body;

            if (!metrics) {
                return reply.code(400).send({
                    error: 'Missing metrics data'
                });
            }

            try {
                await this.claudeAgent.reportTaskMetrics(taskId, metrics);

                return {
                    success: true,
                    message: `Metrics reported for task ${taskId}`,
                    taskId,
                    metrics,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to report task metrics',
                    details: err.message
                });
            }
        });

        // Report bottleneck or performance issue
        this.fastify.post('/tasks/:taskId/bottleneck', async (request, reply) => {
            const { taskId } = request.params;
            const { bottleneckType, severity, description, suggestedActions } = request.body;

            if (!bottleneckType || !severity || !description) {
                return reply.code(400).send({
                    error: 'Missing required fields: bottleneckType, severity, description'
                });
            }

            const validSeverities = ['low', 'medium', 'high', 'critical'];
            if (!validSeverities.includes(severity)) {
                return reply.code(400).send({
                    error: `Invalid severity. Must be one of: ${validSeverities.join(', ')}`
                });
            }

            try {
                await this.claudeAgent.reportBottleneck(
                    taskId, bottleneckType, severity, description, suggestedActions || []
                );

                return {
                    success: true,
                    message: `Bottleneck reported for task ${taskId}`,
                    taskId,
                    bottleneckType,
                    severity,
                    description,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to report bottleneck',
                    details: err.message
                });
            }
        });

        // Get comprehensive progress analytics
        this.fastify.get('/tasks/:taskId/analytics', async (request, reply) => {
            const { taskId } = request.params;

            try {
                // Request analytics from Director Agent
                const analyticsRequestId = await this.claudeAgent.submitTask('get_task_analytics', {
                    task_id: taskId,
                    include_metrics: true,
                    include_bottlenecks: true,
                    include_sub_tasks: true
                });

                return {
                    success: true,
                    message: `Analytics request submitted for task ${taskId}`,
                    analyticsRequestId,
                    taskId,
                    timestamp: new Date().toISOString()
                };
            } catch (err) {
                return reply.code(500).send({
                    error: 'Failed to request task analytics',
                    details: err.message
                });
            }
        });
    }

    /**
     * Setup WebSocket connections for real-time updates
     */
    setupWebSocket() {
        this.fastify.register(async (fastify) => {
            fastify.get('/ws', { websocket: true }, (connection, req) => {
                const connectionId = `ws-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

                console.log(`🔌 WebSocket connection established: ${connectionId}`);

                // Store connection
                this.wsConnections.set(connectionId, connection);

                // Send welcome message
                connection.send(JSON.stringify({
                    type: 'welcome',
                    connectionId: connectionId,
                    timestamp: new Date().toISOString(),
                    agent: this.claudeAgent.getStatus()
                }));

                // Handle messages from client
                connection.on('message', (message) => {
                    try {
                        const data = JSON.parse(message.toString());
                        this.handleWebSocketMessage(connectionId, data);
                    } catch (error) {
                        console.error(`❌ Invalid WebSocket message:`, error);
                        connection.send(JSON.stringify({
                            type: 'error',
                            error: 'Invalid message format'
                        }));
                    }
                });

                // Handle connection close
                connection.on('close', () => {
                    console.log(`🔌 WebSocket connection closed: ${connectionId}`);
                    this.wsConnections.delete(connectionId);
                });

                // Handle connection error
                connection.on('error', (error) => {
                    console.error(`❌ WebSocket error ${connectionId}:`, error);
                    this.wsConnections.delete(connectionId);
                });
            });
        });
    }

    /**
     * Handle WebSocket messages from clients
     */
    handleWebSocketMessage(connectionId, message) {
        console.log(`📨 WebSocket message from ${connectionId}:`, message.type);

        const connection = this.wsConnections.get(connectionId);
        if (!connection) return;

        switch (message.type) {
            case 'subscribe':
                // Subscribe to specific event types
                connection.subscriptions = message.events || [];
                connection.send(JSON.stringify({
                    type: 'subscribed',
                    events: connection.subscriptions
                }));
                break;

            case 'ping':
                connection.send(JSON.stringify({
                    type: 'pong',
                    timestamp: new Date().toISOString()
                }));
                break;

            case 'get_status':
                connection.send(JSON.stringify({
                    type: 'status',
                    data: this.claudeAgent.getStatus()
                }));
                break;

            default:
                connection.send(JSON.stringify({
                    type: 'error',
                    error: `Unknown message type: ${message.type}`
                }));
        }
    }

    /**
     * Broadcast message to all WebSocket connections
     */
    broadcastToWebSockets(message) {
        for (const [connectionId, connection] of this.wsConnections) {
            try {
                // Check if connection is subscribed to this event type
                if (!connection.subscriptions ||
                    connection.subscriptions.includes(message.type) ||
                    connection.subscriptions.includes('all')) {

                    connection.send(JSON.stringify(message));
                }
            } catch (error) {
                console.error(`❌ Error broadcasting to ${connectionId}:`, error);
                this.wsConnections.delete(connectionId);
            }
        }
    }

    /**
     * Setup event handlers for Claude Agent
     */
    setupAgentEventHandlers() {
        // Agent ready
        this.claudeAgent.on('ready', () => {
            console.log(`✅ Claude Code Agent is ready`);
            this.broadcastToWebSockets({
                type: 'agent_ready',
                timestamp: new Date().toISOString()
            });
        });

        // Task assigned
        this.claudeAgent.on('task_assigned', (task) => {
            console.log(`🎯 Task assigned: ${task?.type || 'unknown'}`);
            this.broadcastToWebSockets({
                type: 'task_assigned',
                task: {
                    id: task.id,
                    type: task.type,
                    timestamp: new Date().toISOString()
                }
            });
        });

        // Broadcast message received
        this.claudeAgent.on('broadcast_message', (message) => {
            this.broadcastToWebSockets({
                type: 'agent_broadcast',
                message: message,
                timestamp: new Date().toISOString()
            });
        });

        // Private message received
        this.claudeAgent.on('private_message', (message) => {
            this.broadcastToWebSockets({
                type: 'agent_message',
                message: message,
                timestamp: new Date().toISOString()
            });
        });

        // Observatory message
        this.claudeAgent.on('observatory_message', (message) => {
            this.broadcastToWebSockets({
                type: 'observatory_update',
                message: message,
                timestamp: new Date().toISOString()
            });
        });

        // Error events
        this.claudeAgent.on('error', (error) => {
            console.error(`❌ Claude Agent error:`, error);
            this.broadcastToWebSockets({
                type: 'agent_error',
                error: error.message,
                timestamp: new Date().toISOString()
            });
        });
    }

    /**
     * Start the server
     */
    async start() {
        try {
            console.log(`🚀 Starting Claude Code Bridge Server...`);

            // Initialize Claude Agent first
            const agentReady = await this.claudeAgent.initialize();
            if (!agentReady) {
                throw new Error('Failed to initialize Claude Code Agent');
            }

            // Start HTTP server
            const address = await this.fastify.listen({
                host: this.config.host,
                port: this.config.port
            });

            console.log(`✅ Claude Code Bridge Server running on ${address}`);
            console.log(`📡 WebSocket endpoint: ws://${this.config.host}:${this.config.port}/ws`);
            console.log(`🔍 Health check: http://${this.config.host}:${this.config.port}/health`);

            return address;

        } catch (error) {
            console.error(`❌ Failed to start server:`, error);
            process.exit(1);
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown() {
        console.log(`🛑 Shutting down Claude Code Bridge Server...`);

        // Close WebSocket connections
        for (const [connectionId, connection] of this.wsConnections) {
            try {
                connection.close();
            } catch (error) {
                console.error(`Error closing WebSocket ${connectionId}:`, error);
            }
        }

        // Shutdown Claude Agent
        await this.claudeAgent.shutdown();

        // Close Fastify server
        await this.fastify.close();

        console.log(`✅ Claude Code Bridge Server shutdown complete`);
    }
}

export default ClaudeCodeBridgeServer;