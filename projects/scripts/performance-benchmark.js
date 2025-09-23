#!/usr/bin/env node

import { spawn } from 'child_process';
import { performance } from 'perf_hooks';

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

async function runCommand(command, args, cwd = process.cwd()) {
  return new Promise((resolve, reject) => {
    const startTime = performance.now();
    const child = spawn(command, args, {
      cwd,
      shell: true,
      stdio: 'pipe'
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('exit', (code) => {
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);

      if (code === 0) {
        resolve({ success: true, duration, stdout, stderr });
      } else {
        resolve({ success: false, duration, stdout, stderr, exitCode: code });
      }
    });
  });
}

async function benchmarkBuild(buildCommand, label) {
  log(`\\n🔥 Testing ${label}...`, 'cyan');

  // Clear cache first
  await runCommand('rm', ['-rf', '.build-cache', 'node_modules/.cache']);

  const result = await runCommand('npm', ['run', buildCommand]);

  if (result.success) {
    log(`✓ ${label}: ${result.duration}ms`, 'green');
  } else {
    log(`✗ ${label}: Failed after ${result.duration}ms`, 'red');
  }

  return result;
}

async function main() {
  log('🚀 Build System Performance Benchmark', 'magenta');
  log('=====================================', 'magenta');

  const results = [];

  // Test original build
  try {
    const originalResult = await benchmarkBuild('build:parallel', 'Original Build (build:parallel)');
    results.push({ name: 'Original Build', ...originalResult });
  } catch (error) {
    log('Original build failed', 'red');
  }

  // Test fast build (with caching)
  try {
    const fastResult = await benchmarkBuild('build:fast', 'Optimized Build (build:fast)');
    results.push({ name: 'Optimized Build', ...fastResult });
  } catch (error) {
    log('Optimized build failed', 'red');
  }

  // Test cached build
  log('\\n🔥 Testing Cached Build Performance...', 'cyan');
  const cachedResult = await runCommand('npm', ['run', 'build:fast']);
  if (cachedResult.success) {
    log(`✓ Cached Build: ${cachedResult.duration}ms`, 'green');
    results.push({ name: 'Cached Build', ...cachedResult });
  }

  // Generate report
  log('\\n📊 Performance Comparison Report', 'magenta');
  log('=================================', 'magenta');

  for (const result of results) {
    const status = result.success ? '✓' : '✗';
    const timeStr = `${result.duration}ms`;
    log(`${status} ${result.name.padEnd(20)}: ${timeStr}`, result.success ? 'green' : 'red');
  }

  if (results.length >= 2) {
    const original = results.find(r => r.name === 'Original Build');
    const optimized = results.find(r => r.name === 'Optimized Build');
    const cached = results.find(r => r.name === 'Cached Build');

    if (original && optimized && both.success) {
      const improvement = Math.round(((original.duration - optimized.duration) / original.duration) * 100);
      log(`\\n🎯 Performance Improvement: ${improvement}%`, 'cyan');
    }

    if (cached && cached.success) {
      const cacheSpeedup = Math.round(((original?.duration || 10000) / cached.duration));
      log(`🚀 Cache Speedup: ${cacheSpeedup}x faster`, 'cyan');
    }
  }
}

main().catch(console.error);