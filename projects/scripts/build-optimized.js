#!/usr/bin/env node

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import { performance } from 'perf_hooks';
import crypto from 'crypto';

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

// Build cache management
const CACHE_DIR = '.build-cache';
const CACHE_FILE = path.join(CACHE_DIR, 'cache.json');

async function ensureCacheDir() {
  try {
    await fs.mkdir(CACHE_DIR, { recursive: true });
  } catch (error) {
    // Directory might already exist
  }
}

async function loadCache() {
  try {
    const cacheData = await fs.readFile(CACHE_FILE, 'utf8');
    return JSON.parse(cacheData);
  } catch (error) {
    return {};
  }
}

async function saveCache(cache) {
  await ensureCacheDir();
  await fs.writeFile(CACHE_FILE, JSON.stringify(cache, null, 2));
}

async function getFileHash(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    return crypto.createHash('md5').update(content).digest('hex');
  } catch (error) {
    return null;
  }
}

async function shouldSkipBuild(workspacePath, cache) {
  const packageJsonPath = path.join(workspacePath, 'package.json');
  const tsConfigPath = path.join(workspacePath, 'tsconfig.json');

  const packageHash = await getFileHash(packageJsonPath);
  const tsConfigHash = await getFileHash(tsConfigPath);

  const cacheKey = workspacePath;
  const cachedEntry = cache[cacheKey];

  if (!cachedEntry) return false;

  return (
    cachedEntry.packageHash === packageHash &&
    cachedEntry.tsConfigHash === tsConfigHash &&
    cachedEntry.buildSuccess === true
  );
}

async function updateCache(workspacePath, cache, success) {
  const packageJsonPath = path.join(workspacePath, 'package.json');
  const tsConfigPath = path.join(workspacePath, 'tsconfig.json');

  const packageHash = await getFileHash(packageJsonPath);
  const tsConfigHash = await getFileHash(tsConfigPath);

  cache[workspacePath] = {
    packageHash,
    tsConfigHash,
    buildSuccess: success,
    timestamp: Date.now()
  };
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

async function buildWorkspace(workspacePath, name, cache, buildMetrics) {
  const startTime = performance.now();

  try {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(workspacePath, 'package.json'), 'utf8')
    );

    if (!packageJson.scripts?.build) {
      log(`⊘ ${name} has no build script`, 'yellow');
      buildMetrics[name] = { skipped: true, reason: 'no build script' };
      return;
    }

    // Check cache
    if (await shouldSkipBuild(workspacePath, cache)) {
      const endTime = performance.now();
      const duration = endTime - startTime;
      log(`⚡ ${name} skipped (cached)`, 'blue');
      buildMetrics[name] = { cached: true, duration: Math.round(duration) };
      return;
    }

    log(`Building ${name}...`, 'cyan');

    // Try esbuild first for TypeScript projects
    const useEsbuild = packageJson.scripts.build?.includes('tsc') &&
                      await fs.access(path.join(workspacePath, 'tsconfig.json')).then(() => true).catch(() => false);

    if (useEsbuild) {
      try {
        await runCommand('npx', ['esbuild', '--bundle', '--platform=node', '--format=esm', '--outdir=dist', 'src/index.ts'], workspacePath);
        log(`⚡ ${name} built with esbuild`, 'green');
      } catch (esbuildError) {
        log(`Esbuild failed for ${name}, falling back to npm build`, 'yellow');
        await runCommand('npm', ['run', 'build'], workspacePath);
        log(`✓ ${name} built successfully`, 'green');
      }
    } else {
      await runCommand('npm', ['run', 'build'], workspacePath);
      log(`✓ ${name} built successfully`, 'green');
    }

    await updateCache(workspacePath, cache, true);

    const endTime = performance.now();
    const duration = endTime - startTime;
    buildMetrics[name] = { success: true, duration: Math.round(duration), useEsbuild };

  } catch (error) {
    const endTime = performance.now();
    const duration = endTime - startTime;
    log(`✗ Failed to build ${name}: ${error.message}`, 'red');
    await updateCache(workspacePath, cache, false);
    buildMetrics[name] = { success: false, duration: Math.round(duration), error: error.message };
    throw error;
  }
}

async function analyzeBundleSizes() {
  log('\\nAnalyzing bundle sizes...', 'magenta');

  const bundleAnalysis = {};
  const workspaces = [
    './packages/shared',
    './packages/stochastic-components',
    './packages/random-walk-components',
    './financial-apps/financial-simulator'
  ];

  for (const workspace of workspaces) {
    try {
      const distPath = path.join(workspace, 'dist');
      const stats = await fs.stat(distPath).catch(() => null);

      if (stats) {
        const files = await fs.readdir(distPath, { withFileTypes: true });
        let totalSize = 0;

        for (const file of files) {
          if (file.isFile()) {
            const filePath = path.join(distPath, file.name);
            const fileStats = await fs.stat(filePath);
            totalSize += fileStats.size;
          }
        }

        bundleAnalysis[workspace] = {
          totalSize: Math.round(totalSize / 1024), // KB
          fileCount: files.filter(f => f.isFile()).length
        };
      }
    } catch (error) {
      // Skip analysis for this workspace
    }
  }

  return bundleAnalysis;
}

async function main() {
  const totalStartTime = performance.now();
  log('🚀 Starting optimized parallel build process...', 'magenta');

  await ensureCacheDir();
  const cache = await loadCache();
  const buildMetrics = {};

  const workspaces = [
    { path: './packages/shared', name: 'Shared Utilities' },
    { path: './packages/stochastic-components', name: 'Stochastic Components' },
    { path: './packages/random-walk-components', name: 'Random Walk Components' },
    { path: './mcp-servers/financial-stochastic-mcp', name: 'Financial Stochastic MCP' },
    { path: './mcp-servers/multidimensional-stochastic-mcp', name: 'Multidimensional MCP' },
    { path: './mcp-servers/random-walk-mcp', name: 'Random Walk MCP' },
    { path: './financial-apps/financial-simulator', name: 'Financial Simulator' },
    { path: './platform/mcp-sdk', name: 'MCP SDK' },
    { path: './platform/vibrant-ui', name: 'Vibrant UI' }
  ];

  try {
    // Build shared utilities first (dependency)
    await buildWorkspace(workspaces[0].path, workspaces[0].name, cache, buildMetrics);

    // Build rest in parallel
    const buildPromises = workspaces.slice(1).map(ws =>
      buildWorkspace(ws.path, ws.name, cache, buildMetrics)
    );

    await Promise.all(buildPromises);
    await saveCache(cache);

    // Generate build report
    const totalEndTime = performance.now();
    const totalDuration = Math.round(totalEndTime - totalStartTime);

    log('\\n📊 Build Performance Report', 'magenta');
    log('================================', 'magenta');

    let totalBuildTime = 0;
    let cachedBuilds = 0;
    let successfulBuilds = 0;

    for (const [workspace, metrics] of Object.entries(buildMetrics)) {
      if (metrics.cached) {
        log(`⚡ ${workspace}: Cached (${metrics.duration}ms)`, 'blue');
        cachedBuilds++;
      } else if (metrics.success) {
        const tool = metrics.useEsbuild ? 'esbuild' : 'npm';
        log(`✓ ${workspace}: ${metrics.duration}ms (${tool})`, 'green');
        totalBuildTime += metrics.duration;
        successfulBuilds++;
      } else if (metrics.skipped) {
        log(`⊘ ${workspace}: Skipped (${metrics.reason})`, 'yellow');
      } else {
        log(`✗ ${workspace}: Failed (${metrics.duration}ms)`, 'red');
      }
    }

    log('\\n📈 Summary:', 'cyan');
    log(`Total time: ${totalDuration}ms`, 'cyan');
    log(`Successful builds: ${successfulBuilds}`, 'green');
    log(`Cached builds: ${cachedBuilds}`, 'blue');
    log(`Average build time: ${successfulBuilds > 0 ? Math.round(totalBuildTime / successfulBuilds) : 0}ms`, 'cyan');

    // Bundle size analysis
    const bundleAnalysis = await analyzeBundleSizes();
    if (Object.keys(bundleAnalysis).length > 0) {
      log('\\n📦 Bundle Analysis:', 'cyan');
      for (const [workspace, analysis] of Object.entries(bundleAnalysis)) {
        log(`${workspace}: ${analysis.totalSize}KB (${analysis.fileCount} files)`, 'cyan');
      }
    }

    log('\\n✓ All builds completed successfully!', 'green');

  } catch (error) {
    await saveCache(cache);
    log('\\n✗ Build process failed', 'red');
    process.exit(1);
  }
}

main().catch(console.error);