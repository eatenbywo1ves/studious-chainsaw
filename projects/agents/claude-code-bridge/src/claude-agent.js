#!/usr/bin/env node
/**
 * Claude Code Agent Adapter
 * Bridges Claude Code with the multi-agent ecosystem via Redis and WebSocket
 */

import redis from 'redis';
import WebSocket from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';

class ClaudeCodeAgent extends EventEmitter {
    constructor(options = {}) {
        super();

        this.agentId = options.agentId || `claude-code-${uuidv4().slice(0, 8)}`;
        this.agentType = 'claude-code';

        // Configuration
        this.config = {
            redis: {
                host: options.redisHost || 'localhost',
                port: options.redisPort || 6379,
                db: options.redisDb || 0
            },
            observatory: {
                url: options.observatoryUrl || 'ws://localhost:8090/ws',
                reconnectInterval: 5000,
                heartbeatInterval: 30000
            },
            capabilities: [
                'code_generation',
                'code_analysis',
                'documentation',
                'debugging',
                'testing',
                'project_orchestration'
            ],
            ...options
        };

        // State management
        this.isConnected = false;
        this.redisClient = null;
        this.redisSubscriber = null;
        this.observatoryWs = null;
        this.heartbeatTimer = null;
        this.reconnectTimer = null;

        // Message handlers
        this.messageHandlers = new Map();
        this.taskQueue = [];
        this.activeTasksId = uuidv4();

        this.setupMessageHandlers();
    }

    /**
     * Initialize the agent - connect to Redis and Observatory
     */
    async initialize() {
        console.log(`🚀 Initializing Claude Code Agent: ${this.agentId}`);

        try {
            // Connect to Redis
            await this.connectRedis();

            // Connect to Observatory
            await this.connectObservatory();

            // Register with the system
            await this.registerAgent();

            // Start heartbeat
            this.startHeartbeat();

            this.isConnected = true;
            console.log(`✅ Claude Code Agent initialized successfully`);

            this.emit('ready');
            return true;

        } catch (error) {
            console.error(`❌ Failed to initialize Claude Code Agent:`, error);
            this.emit('error', error);
            return false;
        }
    }

    /**
     * Connect to Redis for inter-agent communication
     */
    async connectRedis() {
        console.log(`🔌 Connecting to Redis at ${this.config.redis.host}:${this.config.redis.port}`);

        // Create Redis clients
        this.redisClient = redis.createClient({
            host: this.config.redis.host,
            port: this.config.redis.port,
            db: this.config.redis.db
        });

        this.redisSubscriber = redis.createClient({
            host: this.config.redis.host,
            port: this.config.redis.port,
            db: this.config.redis.db
        });

        // Handle Redis errors
        this.redisClient.on('error', (err) => {
            console.error('Redis Client Error:', err);
            this.emit('redis_error', err);
        });

        this.redisSubscriber.on('error', (err) => {
            console.error('Redis Subscriber Error:', err);
            this.emit('redis_error', err);
        });

        // Connect both clients
        await this.redisClient.connect();
        await this.redisSubscriber.connect();

        // Subscribe to channels
        await this.setupRedisSubscriptions();

        console.log(`✅ Connected to Redis successfully`);
    }

    /**
     * Set up Redis channel subscriptions
     */
    async setupRedisSubscriptions() {
        // Subscribe to broadcast channel
        await this.redisSubscriber.subscribe('agent:broadcast', (message) => {
            this.handleBroadcastMessage(JSON.parse(message));
        });

        // Subscribe to private channel
        await this.redisSubscriber.subscribe(`agent:${this.agentId}`, (message) => {
            this.handlePrivateMessage(JSON.parse(message));
        });

        // Subscribe to task assignments
        await this.redisSubscriber.subscribe(`tasks:${this.agentType}`, (message) => {
            this.handleTaskAssignment(JSON.parse(message));
        });

        // Subscribe to capability discovery channels
        await this.redisSubscriber.subscribe('capability:query', (message) => {
            this.handleCapabilityDiscoveryMessage(JSON.parse(message));
        });

        await this.redisSubscriber.subscribe('capability:announce', (message) => {
            this.handleCapabilityDiscoveryMessage(JSON.parse(message));
        });

        console.log(`📡 Subscribed to Redis channels including capability discovery`);
    }

    /**
     * Connect to Multi-Agent Observatory
     */
    async connectObservatory() {
        return new Promise((resolve, reject) => {
            console.log(`🔭 Connecting to Observatory at ${this.config.observatory.url}`);

            this.observatoryWs = new WebSocket(this.config.observatory.url);

            this.observatoryWs.on('open', () => {
                console.log(`✅ Connected to Observatory successfully`);

                // Register with observatory
                this.sendObservatoryMessage({
                    type: 'register',
                    agentName: this.agentId,
                    metadata: {
                        version: '1.0.0',
                        nodeVersion: process.version,
                        platform: process.platform,
                        arch: process.arch,
                        pid: process.pid,
                        startTime: new Date().toISOString(),
                        capabilities: this.config.capabilities,
                        capabilityInfo: this.getCapabilityInfo()
                    }
                });

                resolve();
            });

            this.observatoryWs.on('message', (data) => {
                try {
                    const message = JSON.parse(data.toString());
                    this.handleObservatoryMessage(message);
                } catch (error) {
                    console.error(`❌ Invalid Observatory message:`, error);
                }
            });

            this.observatoryWs.on('close', (code, reason) => {
                console.log(`🔌 Observatory disconnected: ${code} ${reason}`);
                this.scheduleObservatoryReconnect();
            });

            this.observatoryWs.on('error', (error) => {
                console.error(`❌ Observatory WebSocket error:`, error);
                reject(error);
            });

            // Timeout for connection
            setTimeout(() => {
                if (this.observatoryWs.readyState !== WebSocket.OPEN) {
                    reject(new Error('Observatory connection timeout'));
                }
            }, 10000);
        });
    }

    /**
     * Register agent with the Director Agent system
     */
    async registerAgent() {
        const registrationMessage = {
            id: uuidv4(),
            type: 'agent_register',
            sender: this.agentId,
            recipient: 'registry',
            payload: {
                agent_id: this.agentId,
                agent_type: this.agentType,
                capabilities: this.config.capabilities,
                metadata: {
                    version: '1.0.0',
                    language: 'javascript',
                    framework: 'claude-code-bridge',
                    supported_tasks: [
                        'code_generation',
                        'code_review',
                        'documentation_generation',
                        'testing_assistance',
                        'debugging_support',
                        'project_coordination'
                    ]
                }
            },
            timestamp: new Date().toISOString(),
            correlation_id: null
        };

        // Publish registration to Redis
        await this.redisClient.publish('agent:registry', JSON.stringify(registrationMessage));

        // Add to active agents set
        await this.redisClient.sAdd('active_agents', this.agentId);
        await this.redisClient.sAdd(`active_agents:${this.agentType}`, this.agentId);

        // Store enhanced agent info
        const capabilityInfo = this.getCapabilityInfo();
        await this.redisClient.hSet(`agent:${this.agentId}`, {
            id: this.agentId,
            type: this.agentType,
            status: 'online',
            capabilities: JSON.stringify(this.config.capabilities),
            capability_info: JSON.stringify(capabilityInfo),
            registered_at: new Date().toISOString(),
            last_heartbeat: new Date().toISOString()
        });

        console.log(`📝 Agent registered with enhanced capability system`);

        // Announce capabilities to the ecosystem
        setTimeout(() => {
            this.announceCapabilityUpdate('update');
        }, 1000); // Wait 1 second after registration
    }

    /**
     * Start heartbeat to maintain agent status
     */
    startHeartbeat() {
        this.heartbeatTimer = setInterval(async () => {
            try {
                // Clean up old tasks periodically
                this.cleanupTaskQueue();

                // Send heartbeat to Redis
                const heartbeatMessage = {
                    id: uuidv4(),
                    type: 'agent_heartbeat',
                    sender: this.agentId,
                    recipient: 'registry',
                    payload: {
                        agent_id: this.agentId,
                        capacity: 100, // Claude Code always has full capacity
                        status: 'online',
                        queued_tasks: this.taskQueue.length,
                        uptime: process.uptime()
                    },
                    timestamp: new Date().toISOString()
                };

                await this.redisClient.publish('agent:registry', JSON.stringify(heartbeatMessage));
                await this.redisClient.hSet(`agent:${this.agentId}`, 'last_heartbeat', new Date().toISOString());

                // Send heartbeat to Observatory with additional metrics
                if (this.observatoryWs && this.observatoryWs.readyState === WebSocket.OPEN) {
                    this.sendObservatoryMessage({
                        type: 'heartbeat',
                        agentName: this.agentId,
                        timestamp: new Date().toISOString()
                    });

                    // Send detailed metrics
                    this.sendMetrics({
                        queuedTasks: this.taskQueue.length,
                        uptime: process.uptime(),
                        memoryUsage: process.memoryUsage(),
                        isConnected: this.isConnected
                    });
                }

            } catch (error) {
                console.error(`❌ Heartbeat error:`, error);
            }
        }, this.config.observatory.heartbeatInterval);
    }

    /**
     * Set up message handlers for different message types
     */
    setupMessageHandlers() {
        this.messageHandlers.set('task_assignment', this.handleTaskAssignment.bind(this));
        this.messageHandlers.set('task_acknowledged', this.handleTaskAcknowledged.bind(this));
        this.messageHandlers.set('task_complete', this.handleTaskComplete.bind(this));
        this.messageHandlers.set('task_failed', this.handleTaskFailed.bind(this));
        this.messageHandlers.set('task_progress', this.handleTaskProgress.bind(this));
        this.messageHandlers.set('agent_welcome', this.handleAgentWelcome.bind(this));
        this.messageHandlers.set('capability_update', this.handleCapabilityUpdate.bind(this));
        this.messageHandlers.set('capability_query_response', this.handleCapabilityQueryResponse.bind(this));
        this.messageHandlers.set('capability_announce', this.handleCapabilityAnnouncement.bind(this));
        this.messageHandlers.set('project_update', this.handleProjectUpdate.bind(this));
        this.messageHandlers.set('agent_status', this.handleAgentStatus.bind(this));
        this.messageHandlers.set('resource_request', this.handleResourceRequest.bind(this));
    }

    /**
     * Handle broadcast messages from other agents
     */
    handleBroadcastMessage(message) {
        console.log(`📢 Broadcast message:`, message.type);

        const handler = this.messageHandlers.get(message.type);
        if (handler) {
            handler(message);
        }

        this.emit('broadcast_message', message);
    }

    /**
     * Handle private messages directed to this agent
     */
    handlePrivateMessage(message) {
        console.log(`📩 Private message from ${message.sender}:`, message.type);

        const handler = this.messageHandlers.get(message.type);
        if (handler) {
            handler(message);
        }

        this.emit('private_message', message);
    }

    /**
     * Handle task assignments from Director Agent
     */
    handleTaskAssignment(message) {
        console.log(`🎯 Task assignment:`, message.payload?.task?.type || 'unknown');

        // Add task to queue
        this.taskQueue.push({
            id: message.payload?.task?.id || uuidv4(),
            type: message.payload?.task?.type,
            data: message.payload?.task,
            receivedAt: new Date().toISOString()
        });

        this.emit('task_assigned', message.payload?.task);

        // Send acknowledgment
        this.sendTaskResponse(message.payload?.task?.id, 'acknowledged', 'Task received and queued');
    }

    /**
     * Handle Observatory messages
     */
    handleObservatoryMessage(message) {
        switch (message.type) {
            case 'welcome':
                console.log(`👋 Observatory welcome: ${message.message}`);
                break;
            case 'registered':
                console.log(`✅ Observatory registration confirmed`);
                break;
            case 'heartbeat_ack':
                // Heartbeat acknowledged
                break;
            default:
                console.log(`📨 Observatory message:`, message.type);
        }

        this.emit('observatory_message', message);
    }

    /**
     * Send message to Observatory
     */
    sendObservatoryMessage(message) {
        if (this.observatoryWs && this.observatoryWs.readyState === WebSocket.OPEN) {
            this.observatoryWs.send(JSON.stringify(message));
        }
    }

    /**
     * Send metrics to Observatory
     */
    sendMetrics(metrics) {
        this.sendObservatoryMessage({
            type: 'metrics',
            agentName: this.agentId,
            metrics: metrics,
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Send event to Observatory
     */
    sendEvent(eventType, severity, message, data = {}) {
        this.sendObservatoryMessage({
            type: 'event',
            agentName: this.agentId,
            eventType: eventType,
            severity: severity,
            message: message,
            data: data,
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Send task response back to the system
     */
    async sendTaskResponse(taskId, status, result, error = null) {
        const responseMessage = {
            id: uuidv4(),
            type: status === 'completed' ? 'task_complete' : 'task_failed',
            sender: this.agentId,
            recipient: 'director',
            payload: {
                task_id: taskId,
                agent_id: this.agentId,
                status: status,
                result: result,
                error: error,
                completed_at: new Date().toISOString()
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('agent:director', JSON.stringify(responseMessage));

        // Also send to Observatory for monitoring
        this.sendEvent('task_' + status, status === 'completed' ? 'info' : 'error',
                      `Task ${taskId} ${status}`, { taskId, result, error });
    }

    /**
     * Send progress update for a task
     */
    async sendProgressUpdate(taskId, progress, phase = null, subTasks = {}, message = null) {
        const progressMessage = {
            id: uuidv4(),
            type: 'progress_update',
            sender: this.agentId,
            recipient: 'director',
            payload: {
                task_id: taskId,
                agent_id: this.agentId,
                progress: Math.min(100, Math.max(0, progress)), // Clamp between 0-100
                current_phase: phase,
                sub_tasks: subTasks,
                message: message,
                timestamp: new Date().toISOString()
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('agent:director', JSON.stringify(progressMessage));

        // Send to Observatory
        this.sendEvent('task_progress', 'info',
                      message || `Task ${taskId} progress: ${progress}%`,
                      { taskId, progress, phase, subTasks });
    }

    /**
     * Report performance metrics for a task
     */
    async reportTaskMetrics(taskId, metrics) {
        const metricsMessage = {
            id: uuidv4(),
            type: 'task_metrics',
            sender: this.agentId,
            recipient: 'director',
            payload: {
                task_id: taskId,
                agent_id: this.agentId,
                metrics: {
                    execution_time: metrics.executionTime || 0,
                    memory_usage: metrics.memoryUsage || 0,
                    cpu_usage: metrics.cpuUsage || 0,
                    error_count: metrics.errorCount || 0,
                    retry_count: metrics.retryCount || 0,
                    quality_score: metrics.qualityScore || 100,
                    ...metrics
                },
                timestamp: new Date().toISOString()
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('agent:director', JSON.stringify(metricsMessage));

        // Send to Observatory
        this.sendMetrics({
            taskId: taskId,
            ...metrics,
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Subscribe to progress updates for a specific task
     */
    async subscribeToTaskProgress(taskId) {
        const subscriptionMessage = {
            id: uuidv4(),
            type: 'progress_subscribe',
            sender: this.agentId,
            recipient: 'director',
            payload: {
                task_id: taskId,
                subscriber: this.agentId
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('agent:director', JSON.stringify(subscriptionMessage));
    }

    /**
     * Report a bottleneck or performance issue
     */
    async reportBottleneck(taskId, bottleneckType, severity, description, suggestedActions = []) {
        const bottleneckMessage = {
            id: uuidv4(),
            type: 'bottleneck_report',
            sender: this.agentId,
            recipient: 'director',
            payload: {
                task_id: taskId,
                agent_id: this.agentId,
                bottleneck_type: bottleneckType, // 'resource', 'dependency', 'capacity', 'external'
                severity: severity, // 'low', 'medium', 'high', 'critical'
                description: description,
                suggested_actions: suggestedActions,
                reported_at: new Date().toISOString()
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('agent:director', JSON.stringify(bottleneckMessage));

        // Send critical bottlenecks to Observatory
        if (severity === 'high' || severity === 'critical') {
            this.sendEvent('bottleneck_detected', 'warning',
                          `${severity.toUpperCase()} bottleneck in task ${taskId}: ${description}`,
                          { taskId, bottleneckType, severity, suggestedActions });
        }
    }

    /**
     * Submit a task to the Director Agent for orchestration
     */
    async submitTask(taskType, taskData, priority = false) {
        const taskId = uuidv4();
        const task = {
            id: taskId,
            type: taskType,
            requester: this.agentId,
            data: taskData,
            priority: priority,
            created_at: new Date().toISOString()
        };

        const message = {
            id: uuidv4(),
            type: 'task_assignment',
            sender: this.agentId,
            recipient: 'director',
            payload: {
                task: task,
                required_capabilities: taskData.required_capabilities || []
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('agent:director', JSON.stringify(message));

        console.log(`📤 Submitted task ${taskId} (${taskType}) to Director Agent`);

        // Send submission event to Observatory
        this.sendEvent('task_submission', 'info', `Task ${taskId} submitted for ${taskType}`, {
            taskId,
            taskType,
            taskData,
            priority
        });

        return taskId;
    }

    /**
     * Query for agents with specific capabilities
     */
    async queryCapability(capability, filters = {}) {
        const queryId = uuidv4();
        const queryMessage = {
            id: queryId,
            type: 'capability_query',
            sender: this.agentId,
            recipient: 'director',
            payload: {
                capability: capability,
                filters: filters,
                query_timestamp: new Date().toISOString()
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('capability:query', JSON.stringify(queryMessage));

        console.log(`🔍 Queried for capability: ${capability} with filters:`, filters);

        // Send query event to Observatory
        this.sendEvent('capability_query', 'info', `Querying for capability: ${capability}`, {
            queryId,
            capability,
            filters
        });

        return queryId;
    }

    /**
     * Announce capability updates
     */
    async announceCapabilityUpdate(updateType = 'update', specificCapabilities = null) {
        const capabilities = specificCapabilities || this.config.capabilities;
        const announcementMessage = {
            id: uuidv4(),
            type: 'capability_announce',
            sender: this.agentId,
            recipient: 'all',
            payload: {
                update_type: updateType, // 'update', 'add', 'remove'
                capabilities: capabilities,
                metadata: {
                    version: '1.0.0',
                    language: 'javascript',
                    framework: 'claude-code-bridge',
                    max_concurrent_tasks: 5,
                    last_updated: new Date().toISOString()
                }
            },
            timestamp: new Date().toISOString()
        };

        await this.redisClient.publish('capability:announce', JSON.stringify(announcementMessage));

        console.log(`📢 Announced capability ${updateType}:`, capabilities);

        // Send announcement event to Observatory
        this.sendEvent('capability_announcement', 'info', `Capability ${updateType}: ${capabilities.join(', ')}`, {
            updateType,
            capabilities
        });
    }

    /**
     * Get enhanced capability information
     */
    getCapabilityInfo() {
        return {
            capabilities: this.config.capabilities,
            capability_details: this.config.capabilities.map(cap => ({
                name: cap,
                version: '1.0.0',
                supported_languages: this._getSupportedLanguages(cap),
                estimated_time: this._getEstimatedTime(cap),
                complexity_level: 'advanced'
            })),
            discovery_metadata: {
                agent_version: '1.0.0',
                language: 'javascript',
                framework: 'claude-code-bridge',
                supported_protocols: ['redis', 'websocket'],
                max_concurrent_tasks: 5,
                last_updated: new Date().toISOString()
            }
        };
    }

    /**
     * Get supported languages for a capability
     */
    _getSupportedLanguages(capability) {
        const baseLanguages = ['javascript', 'typescript', 'python'];

        switch (capability) {
            case 'code_generation':
                return [...baseLanguages, 'java', 'go', 'rust', 'c++'];
            case 'code_analysis':
                return [...baseLanguages, 'java', 'go', 'c++', 'php'];
            case 'documentation':
                return ['markdown', 'html', 'latex', 'restructuredtext'];
            default:
                return baseLanguages;
        }
    }

    /**
     * Get estimated execution time for a capability
     */
    _getEstimatedTime(capability) {
        const timeEstimates = {
            'code_generation': { min: 2, avg: 5, max: 15 },
            'code_analysis': { min: 1, avg: 3, max: 10 },
            'documentation': { min: 3, avg: 8, max: 20 },
            'debugging': { min: 5, avg: 12, max: 30 },
            'testing': { min: 2, avg: 6, max: 15 },
            'project_orchestration': { min: 10, avg: 25, max: 60 }
        };
        return timeEstimates[capability] || { min: 1, avg: 5, max: 15 };
    }

    /**
     * Get next task from queue
     */
    getNextTask() {
        return this.taskQueue.shift();
    }

    /**
     * Get current agent status
     */
    getStatus() {
        return {
            agentId: this.agentId,
            agentType: this.agentType,
            isConnected: this.isConnected,
            queuedTasks: this.taskQueue.length,
            capabilities: this.config.capabilities,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage(),
            redisConnected: this.redisClient?.isReady || false,
            observatoryConnected: this.observatoryWs?.readyState === 1
        };
    }

    /**
     * Get task queue information
     */
    getTaskQueue() {
        return this.taskQueue.map(task => ({
            id: task.id,
            type: task.type,
            receivedAt: task.receivedAt,
            dataSize: JSON.stringify(task.data).length
        }));
    }

    /**
     * Clear completed tasks and clean up queue
     */
    cleanupTaskQueue() {
        const originalLength = this.taskQueue.length;
        // Keep only tasks from the last hour
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        this.taskQueue = this.taskQueue.filter(task =>
            new Date(task.receivedAt) > oneHourAgo
        );

        const removedTasks = originalLength - this.taskQueue.length;
        if (removedTasks > 0) {
            console.log(`🧹 Cleaned up ${removedTasks} old tasks from queue`);
        }

        return removedTasks;
    }

    /**
     * Handle project update messages
     */
    handleProjectUpdate(message) {
        console.log(`📊 Project update:`, message.payload?.project_id || 'unknown');
        this.emit('project_update', message.payload);
    }

    /**
     * Handle agent status messages
     */
    handleAgentStatus(message) {
        console.log(`📡 Agent status update:`, message.sender);
        this.emit('agent_status_update', message.payload);
    }

    /**
     * Handle resource request messages
     */
    handleResourceRequest(message) {
        console.log(`🔧 Resource request:`, message.payload?.resource_type || 'unknown');
        this.emit('resource_request', message.payload);
    }

    /**
     * Handle task acknowledgment messages
     */
    handleTaskAcknowledged(message) {
        const taskId = message.payload?.task_id;
        console.log(`✅ Task acknowledged: ${taskId}`);
        this.emit('task_acknowledged', message.payload);
    }

    /**
     * Handle task completion messages
     */
    handleTaskComplete(message) {
        const taskId = message.payload?.task_id;
        const result = message.payload?.result;
        console.log(`🎉 Task completed: ${taskId}`);
        console.log(`📊 Result:`, result);

        // Send completion event to Observatory
        this.sendEvent('task_completion', 'info', `Task ${taskId} completed successfully`, {
            taskId,
            result,
            completedAt: message.payload?.completed_at
        });

        this.emit('task_completed', message.payload);
    }

    /**
     * Handle task failure messages
     */
    handleTaskFailed(message) {
        const taskId = message.payload?.task_id;
        const error = message.payload?.error;
        console.log(`❌ Task failed: ${taskId} - ${error}`);

        // Send failure event to Observatory
        this.sendEvent('task_failure', 'error', `Task ${taskId} failed: ${error}`, {
            taskId,
            error,
            failedAt: message.payload?.failed_at
        });

        this.emit('task_failed', message.payload);
    }

    /**
     * Handle task progress messages
     */
    handleTaskProgress(message) {
        const taskId = message.payload?.task_id;
        const progress = message.payload?.progress;
        const agentId = message.payload?.agent_id;
        console.log(`📈 Task progress: ${taskId} - ${progress}% (by ${agentId})`);

        // Send progress event to Observatory
        this.sendEvent('task_progress', 'info', `Task ${taskId} progress: ${progress}%`, {
            taskId,
            progress,
            agentId
        });

        this.emit('task_progress', message.payload);
    }

    /**
     * Handle agent welcome messages
     */
    handleAgentWelcome(message) {
        const welcomeMessage = message.payload?.message;
        const systemStatus = message.payload?.system_status;
        console.log(`👋 Welcome message: ${welcomeMessage}`);
        console.log(`🌐 System status:`, systemStatus);

        this.emit('agent_welcome', message.payload);
    }

    /**
     * Handle capability update messages
     */
    handleCapabilityUpdate(message) {
        const agentId = message.payload?.agent_id;
        const updateType = message.payload?.update_type;
        const capabilities = message.payload?.capabilities || [];
        console.log(`🔄 Capability update from ${agentId}: ${updateType} - ${capabilities.join(', ')}`);

        // Send capability update event to Observatory
        this.sendEvent('capability_update', 'info', `Agent ${agentId} capability update: ${updateType}`, {
            agentId,
            updateType,
            capabilities,
            discoveryMetadata: message.payload?.discovery_metadata
        });

        this.emit('capability_update', message.payload);
    }

    /**
     * Handle capability query responses
     */
    handleCapabilityQueryResponse(message) {
        const queryId = message.payload?.query_id;
        const capability = message.payload?.capability;
        const matchingAgents = message.payload?.matching_agents || [];
        const totalFound = message.payload?.total_found || 0;

        console.log(`🔍 Capability query response: found ${totalFound} agents for '${capability}'`);
        console.log(`📋 Matching agents:`, matchingAgents.map(a => `${a.agent_id} (${a.agent_type})`));

        // Send discovery event to Observatory
        this.sendEvent('capability_discovery', 'info', `Found ${totalFound} agents for capability '${capability}'`, {
            queryId,
            capability,
            totalFound,
            matchingAgents: matchingAgents.map(a => ({
                agentId: a.agent_id,
                agentType: a.agent_type,
                currentLoad: a.current_load,
                reliability: a.performance?.success_rate || 1.0
            }))
        });

        this.emit('capability_query_response', message.payload);
    }

    /**
     * Handle capability discovery messages
     */
    handleCapabilityDiscoveryMessage(message) {
        const messageType = message.type;
        console.log(`🔍 Capability discovery message: ${messageType}`);

        if (messageType === 'capability_query') {
            // Handle capability queries from other agents
            const requiredCapability = message.payload?.capability;
            const canProvide = this.config.capabilities.includes(requiredCapability);

            if (canProvide) {
                console.log(`✅ Can provide capability: ${requiredCapability}`);
                // The Director will handle the response, we just log it
            }
        }

        this.emit('capability_discovery', message);
    }

    /**
     * Handle capability announcements from other agents
     */
    handleCapabilityAnnouncement(message) {
        const senderId = message.sender;
        const updateType = message.payload?.update_type;
        const capabilities = message.payload?.capabilities || [];

        // Ignore our own announcements
        if (senderId === this.agentId) {
            return;
        }

        console.log(`📢 Capability announcement from ${senderId}: ${updateType} - ${capabilities.join(', ')}`);

        // Send announcement event to Observatory
        this.sendEvent('capability_announcement_received', 'info',
            `Received capability ${updateType} from ${senderId}`, {
            senderId,
            updateType,
            capabilities,
            metadata: message.payload?.metadata
        });

        this.emit('capability_announcement', message.payload);
    }

    /**
     * Schedule Observatory reconnection
     */
    scheduleObservatoryReconnect() {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
        }

        this.reconnectTimer = setTimeout(() => {
            console.log(`🔄 Attempting Observatory reconnection...`);
            this.connectObservatory().catch(error => {
                console.error(`❌ Observatory reconnection failed:`, error);
                this.scheduleObservatoryReconnect();
            });
        }, this.config.observatory.reconnectInterval);
    }

    /**
     * Graceful shutdown
     */
    async shutdown() {
        console.log(`🛑 Shutting down Claude Code Agent...`);

        // Clear timers
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
        }
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
        }

        // Disconnect from Observatory
        if (this.observatoryWs) {
            this.observatoryWs.close();
        }

        // Disconnect from Redis
        if (this.redisClient) {
            await this.redisClient.quit();
        }
        if (this.redisSubscriber) {
            await this.redisSubscriber.quit();
        }

        console.log(`✅ Claude Code Agent shutdown complete`);
    }
}

export default ClaudeCodeAgent;