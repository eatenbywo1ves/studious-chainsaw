#!/usr/bin/env node

/**
 * Basic MCP Server Template
 * 
 * This template provides a foundation for creating MCP (Model Context Protocol) servers.
 * Replace the example tools with your own functionality.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

class BasicMCPServer {
  constructor() {
    this.server = new Server({
      name: 'my-mcp-server',
      version: '1.0.0',
    }, {
      capabilities: {
        tools: {},
      },
    });

    this.setupToolHandlers();
  }

  setupToolHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'hello',
            description: 'Say hello with an optional name',
            inputSchema: {
              type: 'object',
              properties: {
                name: {
                  type: 'string',
                  description: 'Name to greet (optional)',
                },
              },
              additionalProperties: false,
            },
          },
          {
            name: 'calculate',
            description: 'Perform basic mathematical operations',
            inputSchema: {
              type: 'object',
              properties: {
                operation: {
                  type: 'string',
                  enum: ['add', 'subtract', 'multiply', 'divide'],
                  description: 'Mathematical operation to perform',
                },
                a: {
                  type: 'number',
                  description: 'First number',
                },
                b: {
                  type: 'number', 
                  description: 'Second number',
                },
              },
              required: ['operation', 'a', 'b'],
              additionalProperties: false,
            },
          },
        ],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'hello':
            return await this.handleHello(args);
          
          case 'calculate':
            return await this.handleCalculate(args);

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Tool "${name}" not found`
            );
        }
      } catch (error) {
        if (error instanceof McpError) {
          throw error;
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Error executing tool "${name}": ${error.message}`
        );
      }
    });
  }

  async handleHello(args) {
    const name = args?.name || 'World';
    return {
      content: [
        {
          type: 'text',
          text: `Hello, ${name}! 👋`,
        },
      ],
    };
  }

  async handleCalculate(args) {
    const { operation, a, b } = args;

    let result;
    switch (operation) {
      case 'add':
        result = a + b;
        break;
      case 'subtract':
        result = a - b;
        break;
      case 'multiply':
        result = a * b;
        break;
      case 'divide':
        if (b === 0) {
          throw new McpError(
            ErrorCode.InvalidParams,
            'Division by zero is not allowed'
          );
        }
        result = a / b;
        break;
      default:
        throw new McpError(
          ErrorCode.InvalidParams,
          `Unknown operation: ${operation}`
        );
    }

    return {
      content: [
        {
          type: 'text',
          text: `${a} ${operation} ${b} = ${result}`,
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Basic MCP Server running on stdio');
  }
}

// Start the server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new BasicMCPServer();
  server.run().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
  });
}