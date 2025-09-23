#!/usr/bin/env node
/**
 * Claude Code Bridge - Main Entry Point
 * Starts the bridge server and agent
 */

import ClaudeCodeBridgeServer from './api-server.js';

// Configuration
const config = {
    host: process.env.HOST || '0.0.0.0',
    port: parseInt(process.env.PORT) || 3003,
    agent: {
        redisHost: process.env.REDIS_HOST || 'localhost',
        redisPort: parseInt(process.env.REDIS_PORT) || 6379,
        observatoryUrl: process.env.OBSERVATORY_URL || 'ws://localhost:8090/ws',
        agentId: process.env.AGENT_ID || null
    }
};

// Create and start server
const server = new ClaudeCodeBridgeServer(config);

// Graceful shutdown handling
process.on('SIGINT', async () => {
    console.log(`\\n🛑 Received SIGINT, shutting down gracefully...`);
    await server.shutdown();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log(`\\n🛑 Received SIGTERM, shutting down gracefully...`);
    await server.shutdown();
    process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', async (error) => {
    console.error(`❌ Uncaught Exception:`, error);
    await server.shutdown();
    process.exit(1);
});

process.on('unhandledRejection', async (reason, promise) => {
    console.error(`❌ Unhandled Rejection at:`, promise, 'reason:', reason);
    await server.shutdown();
    process.exit(1);
});

// Start the server
console.log(`🚀 Claude Code Bridge initializing...`);
console.log(`📡 Redis: ${config.agent.redisHost}:${config.agent.redisPort}`);
console.log(`🔭 Observatory: ${config.agent.observatoryUrl}`);
console.log(`🌐 Server: ${config.host}:${config.port}`);

server.start().catch(error => {
    console.error(`❌ Failed to start Claude Code Bridge:`, error);
    process.exit(1);
});