#!/usr/bin/env node

import { spawn } from 'child_process';
import readline from 'readline';

const services = [
  {
    name: 'Director Agent',
    command: 'docker-compose',
    args: ['up', 'director-agent'],
    color: '\x1b[31m'
  },
  {
    name: 'UI/UX Agent',
    command: 'docker-compose',
    args: ['up', 'ui-ux-agent'],
    color: '\x1b[32m'
  },
  {
    name: 'Observatory Server',
    command: 'npm',
    args: ['run', 'start:server'],
    cwd: './agents/multi-agent-observatory',
    color: '\x1b[33m'
  },
  {
    name: 'Financial MCP',
    command: 'npm',
    args: ['run', 'start'],
    cwd: './mcp-servers/financial-stochastic-mcp',
    color: '\x1b[34m'
  },
  {
    name: 'Random Walk MCP',
    command: 'npm',
    args: ['run', 'start'],
    cwd: './mcp-servers/random-walk-mcp',
    color: '\x1b[35m'
  }
];

const reset = '\x1b[0m';
const processes = [];

function formatOutput(serviceName, data, color) {
  const lines = data.toString().split('\n');
  return lines
    .filter(line => line.trim())
    .map(line => `${color}[${serviceName}]${reset} ${line}`)
    .join('\n');
}

function startService(service) {
  console.log(`Starting ${service.name}...`);

  const child = spawn(service.command, service.args, {
    cwd: service.cwd || '.',
    shell: true,
    env: { ...process.env, FORCE_COLOR: '1' }
  });

  child.stdout.on('data', (data) => {
    console.log(formatOutput(service.name, data, service.color));
  });

  child.stderr.on('data', (data) => {
    console.error(formatOutput(service.name, data, service.color));
  });

  child.on('exit', (code) => {
    console.log(`${service.color}[${service.name}]${reset} Exited with code ${code}`);
  });

  processes.push(child);
  return child;
}

async function main() {
  console.log('Starting all services in parallel...\n');

  // Start all services
  services.forEach(service => startService(service));

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n\nShutting down all services...');
    processes.forEach(child => {
      child.kill('SIGTERM');
    });
    setTimeout(() => {
      processes.forEach(child => {
        if (!child.killed) {
          child.kill('SIGKILL');
        }
      });
      process.exit(0);
    }, 5000);
  });

  // Keep the main process alive
  await new Promise(() => {});
}

main().catch(console.error);