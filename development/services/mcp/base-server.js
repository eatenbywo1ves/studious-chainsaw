#!/usr/bin/env node
/**
 * Base MCP Server Implementation
 * Provides core MCP protocol functionality
 */

const readline = require('readline');
const { EventEmitter } = require('events');

class MCPServer extends EventEmitter {
    constructor(name, version = '1.0.0') {
        super();
        this.name = name;
        this.version = version;
        this.methods = new Map();
        this.running = false;

        // Register default methods
        this.registerMethod('initialize', this.handleInitialize.bind(this));
        this.registerMethod('ping', this.handlePing.bind(this));
        this.registerMethod('list_tools', this.handleListTools.bind(this));
        this.registerMethod('shutdown', this.handleShutdown.bind(this));
    }

    registerMethod(name, handler) {
        this.methods.set(name, handler);
    }

    async handleInitialize(params) {
        return {
            protocolVersion: '2024.11',
            capabilities: {
                tools: {},
                prompts: {},
                resources: {}
            },
            serverInfo: {
                name: this.name,
                version: this.version
            }
        };
    }

    async handlePing() {
        return { pong: true, timestamp: new Date().toISOString() };
    }

    async handleListTools() {
        return { tools: [] };
    }

    async handleShutdown() {
        this.running = false;
        process.exit(0);
    }

    async handleRequest(request) {
        try {
            const { method, params = {}, id } = request;

            if (!this.methods.has(method)) {
                return {
                    jsonrpc: '2.0',
                    error: {
                        code: -32601,
                        message: `Method not found: ${method}`
                    },
                    id
                };
            }

            const result = await this.methods.get(method)(params);

            return {
                jsonrpc: '2.0',
                result,
                id
            };
        } catch (error) {
            return {
                jsonrpc: '2.0',
                error: {
                    code: -32603,
                    message: error.message
                },
                id: request.id
            };
        }
    }

    start() {
        this.running = true;

        // Set up stdio for JSON-RPC communication
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            terminal: false
        });

        // Log to stderr to avoid interfering with JSON-RPC
        console.error(`[${this.name}] Server starting...`);

        rl.on('line', async (line) => {
            try {
                const request = JSON.parse(line);
                const response = await this.handleRequest(request);
                process.stdout.write(JSON.stringify(response) + '\n');
            } catch (error) {
                console.error(`[${this.name}] Error processing request:`, error);
                process.stdout.write(JSON.stringify({
                    jsonrpc: '2.0',
                    error: {
                        code: -32700,
                        message: 'Parse error'
                    }
                }) + '\n');
            }
        });

        rl.on('close', () => {
            console.error(`[${this.name}] Server shutting down...`);
            process.exit(0);
        });

        // Send initialization notification
        process.stdout.write(JSON.stringify({
            jsonrpc: '2.0',
            method: 'initialized',
            params: {
                serverInfo: {
                    name: this.name,
                    version: this.version
                }
            }
        }) + '\n');

        console.error(`[${this.name}] Server ready`);
    }
}

module.exports = MCPServer;