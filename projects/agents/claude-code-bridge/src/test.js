#!/usr/bin/env node
/**
 * Claude Code Bridge - Test Suite
 * Tests the functionality of the bridge system
 */

import ClaudeCodeAgent from './claude-agent.js';
import ClaudeCodeBridgeServer from './api-server.js';

class BridgeTestSuite {
    constructor() {
        this.tests = [];
        this.results = {
            passed: 0,
            failed: 0,
            total: 0
        };
    }

    /**
     * Add a test to the suite
     */
    addTest(name, testFn) {
        this.tests.push({ name, testFn });
    }

    /**
     * Run all tests
     */
    async runTests() {
        console.log(`🧪 Starting Claude Code Bridge Test Suite`);
        console.log(`📋 Running ${this.tests.length} tests...\\n`);

        for (const test of this.tests) {
            try {
                console.log(`🔍 Testing: ${test.name}`);
                await test.testFn();
                console.log(`✅ PASSED: ${test.name}\\n`);
                this.results.passed++;
            } catch (error) {
                console.error(`❌ FAILED: ${test.name}`);
                console.error(`   Error: ${error.message}\\n`);
                this.results.failed++;
            }
            this.results.total++;
        }

        this.printResults();
    }

    /**
     * Print test results
     */
    printResults() {
        console.log(`\\n📊 Test Results:`);
        console.log(`   Total: ${this.results.total}`);
        console.log(`   Passed: ${this.results.passed}`);
        console.log(`   Failed: ${this.results.failed}`);
        console.log(`   Success Rate: ${((this.results.passed / this.results.total) * 100).toFixed(1)}%`);

        if (this.results.failed === 0) {
            console.log(`\\n🎉 All tests passed!`);
        } else {
            console.log(`\\n⚠️  Some tests failed. Check the output above for details.`);
        }
    }

    /**
     * Assert helper
     */
    assert(condition, message) {
        if (!condition) {
            throw new Error(message || 'Assertion failed');
        }
    }

    /**
     * Sleep helper
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Create test suite
const testSuite = new BridgeTestSuite();

// Test 1: Agent Creation
testSuite.addTest('Agent Creation', async () => {
    const agent = new ClaudeCodeAgent({
        agentId: 'test-agent-' + Date.now()
    });

    testSuite.assert(agent.agentId.startsWith('test-agent-'), 'Agent ID should be set correctly');
    testSuite.assert(agent.agentType === 'claude-code', 'Agent type should be claude-code');
    testSuite.assert(Array.isArray(agent.config.capabilities), 'Capabilities should be an array');
    testSuite.assert(agent.config.capabilities.length > 0, 'Should have capabilities defined');
});

// Test 2: Agent Status
testSuite.addTest('Agent Status', async () => {
    const agent = new ClaudeCodeAgent({
        agentId: 'test-status-agent'
    });

    const status = agent.getStatus();

    testSuite.assert(typeof status === 'object', 'Status should return an object');
    testSuite.assert(status.agentId === 'test-status-agent', 'Status should include agent ID');
    testSuite.assert(status.agentType === 'claude-code', 'Status should include agent type');
    testSuite.assert(typeof status.uptime === 'number', 'Status should include uptime');
    testSuite.assert(typeof status.memoryUsage === 'object', 'Status should include memory usage');
});

// Test 3: Server Creation
testSuite.addTest('Server Creation', async () => {
    const server = new ClaudeCodeBridgeServer({
        port: 3004, // Use different port to avoid conflicts
        agent: {
            agentId: 'test-server-agent'
        }
    });

    testSuite.assert(server.config.port === 3004, 'Server port should be set correctly');
    testSuite.assert(server.claudeAgent instanceof ClaudeCodeAgent, 'Server should have Claude agent');
    testSuite.assert(server.fastify, 'Server should have Fastify instance');
});

// Test 4: Message Handling
testSuite.addTest('Message Handling', async () => {
    const agent = new ClaudeCodeAgent({
        agentId: 'test-message-agent'
    });

    // Test message handler setup
    testSuite.assert(agent.messageHandlers.size > 0, 'Should have message handlers');
    testSuite.assert(agent.messageHandlers.has('task_assignment'), 'Should handle task assignments');

    // Test task queue
    const initialQueueLength = agent.taskQueue.length;

    // Simulate task assignment
    const mockTask = {
        id: 'test-task-123',
        type: 'test_task',
        data: { test: true },
        receivedAt: new Date().toISOString()
    };

    agent.taskQueue.push(mockTask);

    testSuite.assert(agent.taskQueue.length === initialQueueLength + 1, 'Task should be added to queue');

    // Test getting next task
    const nextTask = agent.getNextTask();
    testSuite.assert(nextTask.id === 'test-task-123', 'Should retrieve correct task');
    testSuite.assert(agent.taskQueue.length === initialQueueLength, 'Task should be removed from queue');
});

// Test 5: Configuration Validation
testSuite.addTest('Configuration Validation', async () => {
    const customConfig = {
        redisHost: 'custom-redis',
        redisPort: 6380,
        observatoryUrl: 'ws://custom-observatory:8091/ws',
        capabilities: ['custom_capability']
    };

    const agent = new ClaudeCodeAgent(customConfig);

    testSuite.assert(agent.config.redis.host === 'custom-redis', 'Custom Redis host should be set');
    testSuite.assert(agent.config.redis.port === 6380, 'Custom Redis port should be set');
    testSuite.assert(agent.config.observatory.url === 'ws://custom-observatory:8091/ws', 'Custom Observatory URL should be set');
    testSuite.assert(agent.config.capabilities.includes('custom_capability'), 'Custom capabilities should be included');
});

// Test 6: API Endpoints Structure
testSuite.addTest('API Endpoints Structure', async () => {
    const server = new ClaudeCodeBridgeServer({
        port: 3005,
        agent: { agentId: 'test-api-agent' }
    });

    // Check if routes are registered (we can't easily test without starting server)
    testSuite.assert(server.fastify, 'Fastify instance should exist');
    testSuite.assert(server.claudeAgent, 'Claude agent should be attached');
    testSuite.assert(server.wsConnections instanceof Map, 'WebSocket connections should be tracked');
});

// Test 7: Integration Test (without actual connections)
testSuite.addTest('Integration Components', async () => {
    const server = new ClaudeCodeBridgeServer({
        port: 3006,
        agent: {
            agentId: 'test-integration-agent',
            // Configure to not actually connect for testing
            redisHost: 'localhost',
            redisPort: 6379
        }
    });

    // Test that all components are properly integrated
    testSuite.assert(server.claudeAgent.agentId === 'test-integration-agent', 'Agent ID should propagate');
    testSuite.assert(typeof server.handleWebSocketMessage === 'function', 'WebSocket handler should exist');
    testSuite.assert(typeof server.broadcastToWebSockets === 'function', 'Broadcast function should exist');

    // Test agent event handlers are set up
    const listeners = server.claudeAgent.listenerCount('ready');
    testSuite.assert(listeners > 0, 'Should have event listeners registered');
});

// Run the tests
if (import.meta.url === `file://${process.argv[1]}`) {
    testSuite.runTests().then(() => {
        const exitCode = testSuite.results.failed > 0 ? 1 : 0;
        process.exit(exitCode);
    }).catch(error => {
        console.error(`❌ Test suite failed:`, error);
        process.exit(1);
    });
}

export default BridgeTestSuite;