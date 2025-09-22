#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Worker } from 'worker_threads';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Create the MCP server
const server = new Server(
  {
    name: 'js-executor',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Function to execute JavaScript code in a worker thread
async function executeJavaScript(code, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const workerCode = `
      const { parentPort } = require('worker_threads');
      const { performance } = require('perf_hooks');
      
      const startTime = performance.now();
      const logs = [];
      
      // Override console methods to capture output
      const originalConsole = { ...console };
      console.log = (...args) => logs.push({ type: 'log', message: args.join(' ') });
      console.error = (...args) => logs.push({ type: 'error', message: args.join(' ') });
      console.warn = (...args) => logs.push({ type: 'warn', message: args.join(' ') });
      console.info = (...args) => logs.push({ type: 'info', message: args.join(' ') });
      
      let result = undefined;
      let error = null;
      
      try {
        // Execute the user's code
        result = eval(${JSON.stringify(code)});
      } catch (e) {
        error = {
          name: e.name,
          message: e.message,
          stack: e.stack
        };
      }
      
      const executionTime = performance.now() - startTime;
      
      parentPort.postMessage({
        result: result !== undefined ? String(result) : undefined,
        logs,
        error,
        executionTime
      });
    `;

    // Create a worker thread
    const worker = new Worker(workerCode, { eval: true });
    
    // Set timeout for execution
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error(`Code execution timed out after ${timeout}ms`));
    }, timeout);
    
    // Handle worker messages
    worker.on('message', (data) => {
      clearTimeout(timer);
      worker.terminate();
      resolve(data);
    });
    
    // Handle worker errors
    worker.on('error', (error) => {
      clearTimeout(timer);
      worker.terminate();
      reject(error);
    });
  });
}

// Register the execute_javascript tool
server.setRequestHandler('tools/list', async () => {
  return {
    tools: [
      {
        name: 'execute_javascript',
        description: 'Execute JavaScript code in a sandboxed environment using Node.js worker threads',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'The JavaScript code to execute'
            },
            timeout: {
              type: 'number',
              description: 'Execution timeout in milliseconds (default: 5000, max: 30000)',
              minimum: 100,
              maximum: 30000
            }
          },
          required: ['code']
        }
      }
    ]
  };
});

// Handle tool calls
server.setRequestHandler('tools/call', async (request) => {
  const { name, arguments: args } = request.params;
  
  if (name === 'execute_javascript') {
    try {
      const timeout = Math.min(args.timeout || 5000, 30000);
      const result = await executeJavaScript(args.code, timeout);
      
      // Format output
      let output = [];
      
      // Add console logs
      if (result.logs && result.logs.length > 0) {
        output.push('=== Console Output ===');
        result.logs.forEach(log => {
          output.push(`[${log.type.toUpperCase()}] ${log.message}`);
        });
        output.push('');
      }
      
      // Add result if any
      if (result.result !== undefined) {
        output.push('=== Result ===');
        output.push(result.result);
        output.push('');
      }
      
      // Add error if any
      if (result.error) {
        output.push('=== Error ===');
        output.push(`${result.error.name}: ${result.error.message}`);
        if (result.error.stack) {
          output.push('Stack trace:');
          output.push(result.error.stack);
        }
        output.push('');
      }
      
      // Add execution time
      output.push(`Execution time: ${result.executionTime.toFixed(2)}ms`);
      
      return {
        content: [
          {
            type: 'text',
            text: output.join('\n')
          }
        ]
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Failed to execute JavaScript: ${error.message}`
          }
        ],
        isError: true
      };
    }
  }
  
  throw new Error(`Unknown tool: ${name}`);
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('JavaScript Executor MCP server running...');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});