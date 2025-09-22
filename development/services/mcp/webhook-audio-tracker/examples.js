/**
 * Example integrations for the Webhook Audio Tracker
 * These examples demonstrate how to integrate with various services
 */

const axios = require('axios');

const WEBHOOK_SERVER = 'http://localhost:3000';

class WebhookIntegrations {
    constructor() {
        this.endpoints = new Map();
    }

    async registerEndpoint(name, audioProfile = 'default') {
        try {
            const response = await axios.post(`${WEBHOOK_SERVER}/webhook/register`, {
                name,
                description: `Integration for ${name}`,
                audioProfile
            });
            
            this.endpoints.set(name, response.data);
            console.log(`✅ Registered webhook for ${name}:`, response.data.url);
            return response.data;
        } catch (error) {
            console.error(`❌ Failed to register ${name}:`, error.message);
            throw error;
        }
    }

    // GitHub Integration - Webhook events for repository activity
    async setupGitHubIntegration() {
        const endpoint = await this.registerEndpoint('GitHub', 'development');
        
        // Simulate GitHub webhook events
        const githubEvents = {
            push: async (branch, commits) => {
                await axios.post(endpoint.url, {
                    type: 'git_push',
                    event: 'push',
                    branch,
                    commits,
                    timestamp: new Date().toISOString()
                });
            },
            
            pullRequest: async (action, pr) => {
                const eventType = action === 'opened' ? 'pr_opened' : 
                                 action === 'merged' ? 'pr_merged' : 'pr_updated';
                await axios.post(endpoint.url, {
                    type: eventType,
                    event: 'pull_request',
                    action,
                    pr,
                    timestamp: new Date().toISOString()
                });
            },
            
            issue: async (action, issue) => {
                await axios.post(endpoint.url, {
                    type: 'issue',
                    event: 'issues',
                    action,
                    issue,
                    timestamp: new Date().toISOString()
                });
            },
            
            workflow: async (status, workflowName) => {
                const eventType = status === 'completed' ? 'build_success' :
                                 status === 'failed' ? 'build_failed' : 'build_start';
                await axios.post(endpoint.url, {
                    type: eventType,
                    event: 'workflow_run',
                    status,
                    workflow: workflowName,
                    timestamp: new Date().toISOString()
                });
            }
        };

        return githubEvents;
    }

    // CI/CD Pipeline Integration
    async setupCICDIntegration() {
        const endpoint = await this.registerEndpoint('CI/CD Pipeline', 'development');
        
        // Create a workflow for the build process
        const workflowResponse = await axios.post(`${WEBHOOK_SERVER}/workflow/start`, {
            name: 'Build & Deploy Pipeline',
            steps: ['Checkout', 'Install Dependencies', 'Run Tests', 'Build', 'Deploy', 'Verify'],
            audioProfile: 'development'
        });
        
        const workflowId = workflowResponse.data.workflowId;
        
        const pipeline = {
            startBuild: async () => {
                await axios.post(endpoint.url, {
                    type: 'build_start',
                    event: 'pipeline_start',
                    timestamp: new Date().toISOString()
                });
                
                // Update workflow step
                await axios.post(`${WEBHOOK_SERVER}/workflow/${workflowId}/step`, {
                    stepName: 'Checkout',
                    status: 'in_progress'
                });
            },
            
            updateStep: async (stepName, status, details = {}) => {
                await axios.post(`${WEBHOOK_SERVER}/workflow/${workflowId}/step`, {
                    stepName,
                    status,
                    data: details
                });
                
                // Send webhook for specific events
                if (stepName === 'Run Tests') {
                    const eventType = status === 'completed' ? 'test_pass' : 'test_fail';
                    await axios.post(endpoint.url, {
                        type: eventType,
                        event: 'test_results',
                        ...details,
                        timestamp: new Date().toISOString()
                    });
                }
            },
            
            completeBuild: async (success) => {
                await axios.post(endpoint.url, {
                    type: success ? 'build_success' : 'build_failed',
                    event: 'pipeline_complete',
                    success,
                    timestamp: new Date().toISOString()
                });
            },
            
            deploy: async (environment, version) => {
                await axios.post(endpoint.url, {
                    type: 'deploy_start',
                    event: 'deployment',
                    environment,
                    version,
                    timestamp: new Date().toISOString()
                });
            }
        };

        return { pipeline, workflowId };
    }

    // Monitoring & Alerting Integration
    async setupMonitoringIntegration() {
        const endpoint = await this.registerEndpoint('Monitoring', 'monitoring');
        
        const monitoring = {
            healthCheck: async (service, status) => {
                await axios.post(endpoint.url, {
                    type: 'health_check',
                    service,
                    status,
                    timestamp: new Date().toISOString()
                });
            },
            
            metricAlert: async (metric, value, threshold) => {
                const severity = value > threshold * 2 ? 'critical' :
                               value > threshold * 1.5 ? 'warning' : 'info';
                
                await axios.post(endpoint.url, {
                    type: 'metric_threshold',
                    metric,
                    value,
                    threshold,
                    severity,
                    timestamp: new Date().toISOString()
                });
            },
            
            errorSpike: async (service, errorCount, timeWindow) => {
                await axios.post(endpoint.url, {
                    type: 'error_spike',
                    service,
                    errorCount,
                    timeWindow,
                    timestamp: new Date().toISOString()
                });
            },
            
            latencyWarning: async (endpoint, latency) => {
                await axios.post(endpoint.url, {
                    type: 'latency_warning',
                    endpoint,
                    latency,
                    timestamp: new Date().toISOString()
                });
            },
            
            trafficSurge: async (requests, normal) => {
                await axios.post(endpoint.url, {
                    type: 'traffic_surge',
                    requests,
                    normal,
                    increase: ((requests - normal) / normal * 100).toFixed(2) + '%',
                    timestamp: new Date().toISOString()
                });
            }
        };

        return monitoring;
    }

    // Communication Integration (Slack, Discord, etc.)
    async setupCommunicationIntegration() {
        const endpoint = await this.registerEndpoint('Communication', 'communication');
        
        const communication = {
            message: async (channel, user, message) => {
                await axios.post(endpoint.url, {
                    type: 'message_received',
                    channel,
                    user,
                    message,
                    timestamp: new Date().toISOString()
                });
            },
            
            mention: async (channel, mentionedBy, message) => {
                await axios.post(endpoint.url, {
                    type: 'mention',
                    channel,
                    mentionedBy,
                    message,
                    timestamp: new Date().toISOString()
                });
            },
            
            directMessage: async (from, message) => {
                await axios.post(endpoint.url, {
                    type: 'dm_received',
                    from,
                    message,
                    timestamp: new Date().toISOString()
                });
            },
            
            userActivity: async (user, action) => {
                const eventType = action === 'joined' ? 'user_joined' : 'user_left';
                await axios.post(endpoint.url, {
                    type: eventType,
                    user,
                    action,
                    timestamp: new Date().toISOString()
                });
            }
        };

        return communication;
    }

    // E-commerce Integration
    async setupEcommerceIntegration() {
        const endpoint = await this.registerEndpoint('E-commerce', 'workflow');
        
        // Create order processing workflow
        const workflowResponse = await axios.post(`${WEBHOOK_SERVER}/workflow/start`, {
            name: 'Order Processing',
            steps: ['Order Received', 'Payment Processing', 'Inventory Check', 'Shipping', 'Delivered'],
            audioProfile: 'workflow'
        });
        
        const workflowId = workflowResponse.data.workflowId;
        
        const ecommerce = {
            newOrder: async (orderId, amount) => {
                await axios.post(endpoint.url, {
                    type: 'order_received',
                    orderId,
                    amount,
                    timestamp: new Date().toISOString()
                });
                
                await axios.post(`${WEBHOOK_SERVER}/workflow/${workflowId}/step`, {
                    stepName: 'Order Received',
                    status: 'completed',
                    data: { orderId, amount }
                });
            },
            
            paymentStatus: async (orderId, status) => {
                await axios.post(endpoint.url, {
                    type: status === 'success' ? 'payment_success' : 'payment_failed',
                    orderId,
                    status,
                    timestamp: new Date().toISOString()
                });
                
                await axios.post(`${WEBHOOK_SERVER}/workflow/${workflowId}/step`, {
                    stepName: 'Payment Processing',
                    status: status === 'success' ? 'completed' : 'failed',
                    data: { orderId, status }
                });
            },
            
            inventoryUpdate: async (productId, quantity) => {
                await axios.post(endpoint.url, {
                    type: quantity < 10 ? 'low_inventory' : 'inventory_updated',
                    productId,
                    quantity,
                    timestamp: new Date().toISOString()
                });
            },
            
            shipmentUpdate: async (orderId, status, trackingNumber) => {
                await axios.post(endpoint.url, {
                    type: 'shipment_update',
                    orderId,
                    status,
                    trackingNumber,
                    timestamp: new Date().toISOString()
                });
                
                const stepName = status === 'shipped' ? 'Shipping' : 'Delivered';
                await axios.post(`${WEBHOOK_SERVER}/workflow/${workflowId}/step`, {
                    stepName,
                    status: 'completed',
                    data: { orderId, trackingNumber }
                });
            }
        };

        return { ecommerce, workflowId };
    }

    // Database Operations Integration
    async setupDatabaseIntegration() {
        const endpoint = await this.registerEndpoint('Database', 'alert');
        
        const database = {
            backup: async (status, database, size) => {
                await axios.post(endpoint.url, {
                    type: status === 'completed' ? 'backup_success' : 'backup_failed',
                    database,
                    size,
                    status,
                    timestamp: new Date().toISOString()
                });
            },
            
            replication: async (status, lag) => {
                await axios.post(endpoint.url, {
                    type: lag > 1000 ? 'replication_lag' : 'replication_status',
                    status,
                    lag,
                    timestamp: new Date().toISOString()
                });
            },
            
            connectionPool: async (active, available, maxSize) => {
                const utilizationPercent = (active / maxSize) * 100;
                const eventType = utilizationPercent > 80 ? 'connection_pool_critical' :
                                 utilizationPercent > 60 ? 'connection_pool_warning' :
                                 'connection_pool_status';
                
                await axios.post(endpoint.url, {
                    type: eventType,
                    active,
                    available,
                    maxSize,
                    utilizationPercent,
                    timestamp: new Date().toISOString()
                });
            },
            
            query: async (type, duration, query) => {
                if (duration > 5000) {
                    await axios.post(endpoint.url, {
                        type: 'slow_query',
                        queryType: type,
                        duration,
                        query: query.substring(0, 100),
                        timestamp: new Date().toISOString()
                    });
                }
            }
        };

        return database;
    }
}

// Demo script to test integrations
async function runDemo() {
    console.log('🎵 Webhook Audio Tracker - Integration Examples\n');
    console.log('Starting demo in 3 seconds...\n');
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const integrations = new WebhookIntegrations();
    
    try {
        // Setup GitHub integration
        console.log('📦 Setting up GitHub integration...');
        const github = await integrations.setupGitHubIntegration();
        
        // Simulate GitHub events
        await github.push('main', 3);
        console.log('  ✓ Simulated git push');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await github.pullRequest('opened', { number: 42, title: 'Add new feature' });
        console.log('  ✓ Simulated PR opened');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Setup CI/CD integration
        console.log('\n🔨 Setting up CI/CD pipeline...');
        const { pipeline } = await integrations.setupCICDIntegration();
        
        await pipeline.startBuild();
        console.log('  ✓ Build started');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await pipeline.updateStep('Run Tests', 'completed', { passed: 42, failed: 0 });
        console.log('  ✓ Tests passed');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await pipeline.completeBuild(true);
        console.log('  ✓ Build completed successfully');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Setup Monitoring integration
        console.log('\n📊 Setting up monitoring...');
        const monitoring = await integrations.setupMonitoringIntegration();
        
        await monitoring.healthCheck('api-gateway', 'healthy');
        console.log('  ✓ Health check performed');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await monitoring.metricAlert('cpu_usage', 75, 70);
        console.log('  ✓ CPU usage alert triggered');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Setup Communication integration
        console.log('\n💬 Setting up communication integration...');
        const communication = await integrations.setupCommunicationIntegration();
        
        await communication.message('#general', 'alice', 'Build completed successfully!');
        console.log('  ✓ Message received');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await communication.mention('#dev', 'bob', '@team The new feature is ready for review');
        console.log('  ✓ Mention detected');
        
        console.log('\n✅ Demo completed! Check the dashboard for audio feedback.');
        console.log('🌐 Dashboard: http://localhost:3000/');
        
    } catch (error) {
        console.error('❌ Demo failed:', error.message);
        console.log('\nMake sure the webhook server is running:');
        console.log('  npm install');
        console.log('  npm start');
    }
}

// Export for use in other projects
module.exports = WebhookIntegrations;

// Run demo if executed directly
if (require.main === module) {
    runDemo();
}