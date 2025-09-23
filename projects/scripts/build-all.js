#!/usr/bin/env node

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';

const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

async function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      shell: true,
      stdio: 'inherit'
    });

    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Command failed with code ${code}`));
      }
    });
  });
}

async function buildWorkspace(workspacePath, name) {
  try {
    log(`Building ${name}...`, 'cyan');
    const packageJson = JSON.parse(
      await fs.readFile(path.join(workspacePath, 'package.json'), 'utf8')
    );

    if (packageJson.scripts?.build) {
      await runCommand('npm', ['run', 'build'], workspacePath);
      log(`✓ ${name} built successfully`, 'green');
    } else {
      log(`⊘ ${name} has no build script`, 'yellow');
    }
  } catch (error) {
    log(`✗ Failed to build ${name}: ${error.message}`, 'red');
    throw error;
  }
}

async function main() {
  log('Starting parallel build process...', 'magenta');

  const workspaces = [
    { path: './packages/shared', name: 'Shared Utilities' },
    { path: './packages/stochastic-components', name: 'Stochastic Components' },
    { path: './packages/random-walk-components', name: 'Random Walk Components' },
    { path: './mcp-servers/financial-stochastic-mcp', name: 'Financial Stochastic MCP' },
    { path: './mcp-servers/multidimensional-stochastic-mcp', name: 'Multidimensional MCP' },
    { path: './mcp-servers/random-walk-mcp', name: 'Random Walk MCP' },
    { path: './financial-apps/financial-simulator', name: 'Financial Simulator' }
  ];

  // Build shared utilities first
  await buildWorkspace(workspaces[0].path, workspaces[0].name);

  // Build rest in parallel
  const buildPromises = workspaces.slice(1).map(ws =>
    buildWorkspace(ws.path, ws.name)
  );

  try {
    await Promise.all(buildPromises);
    log('\n✓ All builds completed successfully!', 'green');
  } catch (error) {
    log('\n✗ Build process failed', 'red');
    process.exit(1);
  }
}

main().catch(console.error);