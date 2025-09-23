#!/usr/bin/env node

import { promises as fs } from 'fs';
import path from 'path';

const BUILD_METRICS_FILE = '.build-cache/build-metrics.json';

async function loadBuildMetrics() {
  try {
    const metricsData = await fs.readFile(BUILD_METRICS_FILE, 'utf8');
    return JSON.parse(metricsData);
  } catch (error) {
    return { builds: [], summary: {} };
  }
}

async function saveBuildMetrics(metrics) {
  await fs.mkdir('.build-cache', { recursive: true });
  await fs.writeFile(BUILD_METRICS_FILE, JSON.stringify(metrics, null, 2));
}

async function recordBuild(buildData) {
  const metrics = await loadBuildMetrics();

  metrics.builds.push({
    ...buildData,
    timestamp: new Date().toISOString()
  });

  // Keep only last 50 builds
  if (metrics.builds.length > 50) {
    metrics.builds = metrics.builds.slice(-50);
  }

  // Update summary
  const recentBuilds = metrics.builds.slice(-10);
  metrics.summary = {
    averageDuration: Math.round(
      recentBuilds.reduce((sum, build) => sum + (build.totalDuration || 0), 0) / recentBuilds.length
    ),
    successRate: Math.round(
      (recentBuilds.filter(build => build.success).length / recentBuilds.length) * 100
    ),
    lastBuild: buildData,
    totalBuilds: metrics.builds.length
  };

  await saveBuildMetrics(metrics);
  return metrics;
}

async function getBuildReport() {
  const metrics = await loadBuildMetrics();

  if (metrics.builds.length === 0) {
    return 'No build data available.';
  }

  const { summary } = metrics;
  const recentBuilds = metrics.builds.slice(-5);

  let report = `Build Performance Report\\n`;
  report += `========================\\n\\n`;
  report += `Total builds: ${summary.totalBuilds}\\n`;
  report += `Average duration: ${summary.averageDuration}ms\\n`;
  report += `Success rate: ${summary.successRate}%\\n\\n`;

  report += `Recent builds:\\n`;
  for (const build of recentBuilds.reverse()) {
    const status = build.success ? '✓' : '✗';
    const date = new Date(build.timestamp).toLocaleString();
    report += `${status} ${date} - ${build.totalDuration}ms\\n`;
  }

  if (summary.lastBuild && summary.lastBuild.workspaceMetrics) {
    report += `\\nLast build details:\\n`;
    for (const [workspace, metrics] of Object.entries(summary.lastBuild.workspaceMetrics)) {
      if (metrics.cached) {
        report += `  ⚡ ${workspace}: Cached\\n`;
      } else if (metrics.success) {
        report += `  ✓ ${workspace}: ${metrics.duration}ms\\n`;
      } else if (metrics.skipped) {
        report += `  ⊘ ${workspace}: Skipped\\n`;
      } else {
        report += `  ✗ ${workspace}: Failed\\n`;
      }
    }
  }

  return report;
}

export { recordBuild, getBuildReport, loadBuildMetrics };

// CLI usage
if (process.argv[2] === 'report') {
  getBuildReport().then(console.log);
}