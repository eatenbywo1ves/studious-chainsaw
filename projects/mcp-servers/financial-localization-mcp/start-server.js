#!/usr/bin/env node

/**
 * Financial Localization MCP Server Production Startup Script
 * 
 * This script provides production-ready startup with proper error handling,
 * logging, and process management for the Financial Localization MCP Server.
 */

import { spawn } from 'child_process';
import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class MCPServerManager {
  constructor() {
    this.logDir = join(__dirname, 'logs');
    this.serverPath = join(__dirname, 'src', 'index.js');
    this.pidFile = join(__dirname, 'server.pid');
    
    // Ensure logs directory exists
    if (!existsSync(this.logDir)) {
      mkdirSync(this.logDir, { recursive: true });
    }
  }

  log(message, level = 'INFO') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level}] ${message}\\n`;
    
    // Log to console
    if (level === 'ERROR') {
      console.error(logMessage.trim());
    } else {
      console.log(logMessage.trim());
    }

    // Log to file
    const logFile = join(this.logDir, `mcp-server-${new Date().toISOString().split('T')[0]}.log`);
    try {
      writeFileSync(logFile, logMessage, { flag: 'a' });
    } catch (error) {
      console.error(`Failed to write to log file: ${error.message}`);
    }
  }

  async start() {
    this.log('Starting Financial Localization MCP Server...');

    try {
      // Check if server file exists
      if (!existsSync(this.serverPath)) {
        throw new Error(`Server file not found: ${this.serverPath}`);
      }

      // Start the server process
      const serverProcess = spawn('node', [this.serverPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          NODE_ENV: 'production',
          MCP_SERVER_NAME: 'financial-localization',
          MCP_SERVER_VERSION: '1.0.0'
        }
      });

      // Save process ID
      writeFileSync(this.pidFile, serverProcess.pid.toString());
      this.log(`Server started with PID: ${serverProcess.pid}`);

      // Handle server output
      serverProcess.stdout.on('data', (data) => {
        const output = data.toString().trim();
        if (output) {
          this.log(`STDOUT: ${output}`);
        }
      });

      serverProcess.stderr.on('data', (data) => {
        const output = data.toString().trim();
        if (output) {
          this.log(`STDERR: ${output}`);
        }
      });

      // Handle server exit
      serverProcess.on('exit', (code, signal) => {
        const message = signal ? 
          `Server exited with signal: ${signal}` : 
          `Server exited with code: ${code}`;
        
        this.log(message, code === 0 ? 'INFO' : 'ERROR');

        // Clean up PID file
        try {
          if (existsSync(this.pidFile)) {
            const fs = await import('fs/promises');
            await fs.unlink(this.pidFile);
          }
        } catch (error) {
          this.log(`Failed to clean up PID file: ${error.message}`, 'WARN');
        }
      });

      // Handle process errors
      serverProcess.on('error', (error) => {
        this.log(`Server process error: ${error.message}`, 'ERROR');
        process.exit(1);
      });

      // Handle graceful shutdown
      const gracefulShutdown = (signal) => {
        this.log(`Received ${signal}. Shutting down gracefully...`);
        serverProcess.kill('SIGTERM');
        
        setTimeout(() => {
          this.log('Force killing server process');
          serverProcess.kill('SIGKILL');
          process.exit(1);
        }, 5000);
      };

      process.on('SIGINT', gracefulShutdown);
      process.on('SIGTERM', gracefulShutdown);

      // Wait for initial startup
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Server startup timeout'));
        }, 10000);

        const checkStartup = (data) => {
          if (data.toString().includes('Financial Localization MCP server running')) {
            clearTimeout(timeout);
            serverProcess.stderr.off('data', checkStartup);
            resolve();
          }
        };

        serverProcess.stderr.on('data', checkStartup);
      });

      this.log('Financial Localization MCP Server is running and ready to accept connections');
      
      // Keep the process running
      await new Promise(() => {});

    } catch (error) {
      this.log(`Failed to start server: ${error.message}`, 'ERROR');
      process.exit(1);
    }
  }

  async stop() {
    this.log('Stopping Financial Localization MCP Server...');

    try {
      if (existsSync(this.pidFile)) {
        const fs = await import('fs/promises');
        const pid = parseInt(await fs.readFile(this.pidFile, 'utf-8'));
        
        process.kill(pid, 'SIGTERM');
        this.log(`Sent SIGTERM to process ${pid}`);
        
        // Wait for graceful shutdown
        setTimeout(() => {
          try {
            process.kill(pid, 'SIGKILL');
            this.log(`Force killed process ${pid}`);
          } catch (error) {
            // Process likely already dead
          }
        }, 5000);

      } else {
        this.log('No PID file found. Server may not be running.');
      }
    } catch (error) {
      this.log(`Error stopping server: ${error.message}`, 'ERROR');
    }
  }

  async status() {
    try {
      if (existsSync(this.pidFile)) {
        const fs = await import('fs/promises');
        const pid = parseInt(await fs.readFile(this.pidFile, 'utf-8'));
        
        try {
          process.kill(pid, 0); // Check if process exists
          this.log(`Server is running with PID: ${pid}`);
          return true;
        } catch (error) {
          this.log('Server is not running (stale PID file)');
          await fs.unlink(this.pidFile);
          return false;
        }
      } else {
        this.log('Server is not running');
        return false;
      }
    } catch (error) {
      this.log(`Error checking server status: ${error.message}`, 'ERROR');
      return false;
    }
  }
}

// Handle command line arguments
async function main() {
  const manager = new MCPServerManager();
  const command = process.argv[2] || 'start';

  switch (command) {
    case 'start':
      await manager.start();
      break;
    case 'stop':
      await manager.stop();
      break;
    case 'restart':
      await manager.stop();
      // Wait a moment for cleanup
      setTimeout(async () => {
        await manager.start();
      }, 2000);
      break;
    case 'status':
      await manager.status();
      break;
    default:
      console.log(`
Financial Localization MCP Server Manager

Usage:
  node start-server.js [command]

Commands:
  start     Start the server (default)
  stop      Stop the server
  restart   Restart the server
  status    Check server status

Examples:
  node start-server.js          # Start server
  node start-server.js start    # Start server
  node start-server.js stop     # Stop server
  node start-server.js status   # Check status
      `);
      break;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export default MCPServerManager;