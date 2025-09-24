#!/usr/bin/env node

/**
 * Performance Monitor MCP Server
 * Provides Docker container and system performance monitoring via MCP protocol
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import Docker from 'dockerode';
import si from 'systeminformation';
import schedule from 'node-schedule';

class PerformanceMonitorServer {
  constructor() {
    this.server = new Server(
      {
        name: "performance-monitor-mcp",
        version: "1.0.0",
        description: "Docker container and system performance monitoring server"
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.docker = new Docker();
    this.metrics = {
      containers: new Map(),
      system: {},
      lastUpdate: null
    };

    this.setupToolHandlers();
    this.startPeriodicCollection();
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: "get_container_metrics",
          description: "Get real-time performance metrics for Docker containers",
          inputSchema: {
            type: "object",
            properties: {
              container_id: {
                type: "string",
                description: "Optional container ID to filter results"
              },
              include_system: {
                type: "boolean",
                description: "Include system-wide metrics",
                default: true
              }
            }
          }
        },
        {
          name: "get_performance_summary",
          description: "Get aggregated performance summary with recommendations",
          inputSchema: {
            type: "object",
            properties: {
              threshold_cpu: {
                type: "number",
                description: "CPU usage threshold for alerts (percentage)",
                default: 80
              },
              threshold_memory: {
                type: "number",
                description: "Memory usage threshold for alerts (percentage)",
                default: 85
              }
            }
          }
        },
        {
          name: "get_optimization_recommendations",
          description: "Get performance optimization recommendations based on current metrics",
          inputSchema: {
            type: "object",
            properties: {
              analysis_period: {
                type: "string",
                description: "Time period for analysis (5m, 15m, 1h)",
                default: "15m"
              }
            }
          }
        },
        {
          name: "monitor_resource_health",
          description: "Monitor resource health and detect anomalies",
          inputSchema: {
            type: "object",
            properties: {
              service_names: {
                type: "array",
                items: { type: "string" },
                description: "Array of service names to monitor"
              }
            }
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case "get_container_metrics":
            return await this.getContainerMetrics(args);
          case "get_performance_summary":
            return await this.getPerformanceSummary(args);
          case "get_optimization_recommendations":
            return await this.getOptimizationRecommendations(args);
          case "monitor_resource_health":
            return await this.monitorResourceHealth(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error executing ${name}: ${error.message}`
            }
          ]
        };
      }
    });
  }

  async collectContainerMetrics() {
    try {
      const containers = await this.docker.listContainers();
      const containerMetrics = new Map();

      for (const containerInfo of containers) {
        const container = this.docker.getContainer(containerInfo.Id);
        const stats = await container.stats({ stream: false });

        // Calculate CPU percentage
        const cpuPercent = this.calculateCpuPercent(stats);

        // Calculate memory usage
        const memoryUsage = {
          used: stats.memory_stats.usage || 0,
          limit: stats.memory_stats.limit || 0,
          percent: stats.memory_stats.limit ?
            (stats.memory_stats.usage / stats.memory_stats.limit) * 100 : 0
        };

        // Network I/O
        const networkIO = this.calculateNetworkIO(stats);

        // Block I/O
        const blockIO = this.calculateBlockIO(stats);

        containerMetrics.set(containerInfo.Id, {
          id: containerInfo.Id,
          name: containerInfo.Names[0].replace('/', ''),
          image: containerInfo.Image,
          status: containerInfo.Status,
          cpu: {
            percent: cpuPercent,
            usage: stats.cpu_stats.cpu_usage?.total_usage || 0
          },
          memory: memoryUsage,
          network: networkIO,
          blockIO: blockIO,
          pids: stats.pids_stats?.current || 0,
          timestamp: new Date().toISOString()
        });
      }

      this.metrics.containers = containerMetrics;
      this.metrics.lastUpdate = new Date().toISOString();

    } catch (error) {
      console.error('Error collecting container metrics:', error);
    }
  }

  async collectSystemMetrics() {
    try {
      const [cpu, memory, networkStats, fsStats] = await Promise.all([
        si.currentLoad(),
        si.mem(),
        si.networkStats(),
        si.fsStats()
      ]);

      this.metrics.system = {
        cpu: {
          usage: cpu.currentLoad,
          cores: cpu.cpus?.length || 0,
          loadavg: cpu.avgLoad
        },
        memory: {
          total: memory.total,
          used: memory.used,
          free: memory.free,
          percent: (memory.used / memory.total) * 100
        },
        network: networkStats[0] ? {
          rx_bytes: networkStats[0].rx_bytes,
          tx_bytes: networkStats[0].tx_bytes,
          rx_sec: networkStats[0].rx_sec,
          tx_sec: networkStats[0].tx_sec
        } : {},
        disk: fsStats ? {
          read: fsStats.rx,
          write: fsStats.wx,
          read_sec: fsStats.rx_sec,
          write_sec: fsStats.wx_sec
        } : {},
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error collecting system metrics:', error);
    }
  }

  calculateCpuPercent(stats) {
    const cpuDelta = stats.cpu_stats.cpu_usage?.total_usage -
                    (stats.precpu_stats.cpu_usage?.total_usage || 0);
    const systemDelta = stats.cpu_stats.system_cpu_usage -
                       (stats.precpu_stats.system_cpu_usage || 0);

    if (systemDelta > 0 && cpuDelta > 0) {
      const numberOfCpus = stats.cpu_stats.online_cpus || 1;
      return (cpuDelta / systemDelta) * numberOfCpus * 100;
    }
    return 0;
  }

  calculateNetworkIO(stats) {
    if (!stats.networks) return { rx_bytes: 0, tx_bytes: 0 };

    let rx_bytes = 0, tx_bytes = 0;
    for (const network of Object.values(stats.networks)) {
      rx_bytes += network.rx_bytes || 0;
      tx_bytes += network.tx_bytes || 0;
    }
    return { rx_bytes, tx_bytes };
  }

  calculateBlockIO(stats) {
    if (!stats.blkio_stats?.io_service_bytes_recursive) return { read: 0, write: 0 };

    let read = 0, write = 0;
    for (const io of stats.blkio_stats.io_service_bytes_recursive) {
      if (io.op === 'Read') read += io.value;
      if (io.op === 'Write') write += io.value;
    }
    return { read, write };
  }

  async getContainerMetrics(args) {
    await this.collectContainerMetrics();

    if (args?.include_system) {
      await this.collectSystemMetrics();
    }

    let result = {
      containers: Array.from(this.metrics.containers.values()),
      lastUpdate: this.metrics.lastUpdate
    };

    if (args?.container_id) {
      result.containers = result.containers.filter(c =>
        c.id.startsWith(args.container_id) || c.name.includes(args.container_id)
      );
    }

    if (args?.include_system) {
      result.system = this.metrics.system;
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  }

  async getPerformanceSummary(args) {
    const cpuThreshold = args?.threshold_cpu || 80;
    const memoryThreshold = args?.threshold_memory || 85;

    await this.collectContainerMetrics();
    await this.collectSystemMetrics();

    const containers = Array.from(this.metrics.containers.values());
    const alerts = [];
    const recommendations = [];

    // Analyze container performance
    for (const container of containers) {
      if (container.cpu.percent > cpuThreshold) {
        alerts.push({
          type: "HIGH_CPU",
          container: container.name,
          value: container.cpu.percent,
          threshold: cpuThreshold
        });
        recommendations.push(`Consider scaling or optimizing ${container.name} - CPU usage at ${container.cpu.percent.toFixed(1)}%`);
      }

      if (container.memory.percent > memoryThreshold) {
        alerts.push({
          type: "HIGH_MEMORY",
          container: container.name,
          value: container.memory.percent,
          threshold: memoryThreshold
        });
        recommendations.push(`Check memory leaks in ${container.name} - Memory usage at ${container.memory.percent.toFixed(1)}%`);
      }
    }

    // System-level analysis
    if (this.metrics.system.cpu?.usage > cpuThreshold) {
      alerts.push({
        type: "SYSTEM_HIGH_CPU",
        value: this.metrics.system.cpu.usage,
        threshold: cpuThreshold
      });
    }

    if (this.metrics.system.memory?.percent > memoryThreshold) {
      alerts.push({
        type: "SYSTEM_HIGH_MEMORY",
        value: this.metrics.system.memory.percent,
        threshold: memoryThreshold
      });
    }

    const summary = {
      timestamp: new Date().toISOString(),
      overall_health: alerts.length === 0 ? "HEALTHY" : alerts.length < 3 ? "WARNING" : "CRITICAL",
      container_count: containers.length,
      alerts: alerts,
      recommendations: recommendations,
      top_cpu_containers: containers
        .sort((a, b) => b.cpu.percent - a.cpu.percent)
        .slice(0, 5)
        .map(c => ({ name: c.name, cpu: c.cpu.percent })),
      top_memory_containers: containers
        .sort((a, b) => b.memory.percent - a.memory.percent)
        .slice(0, 5)
        .map(c => ({ name: c.name, memory: c.memory.percent })),
      system_summary: {
        cpu_usage: this.metrics.system.cpu?.usage || 0,
        memory_usage: this.metrics.system.memory?.percent || 0,
        active_containers: containers.filter(c => c.status.includes("Up")).length
      }
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(summary, null, 2)
        }
      ]
    };
  }

  async getOptimizationRecommendations(args) {
    await this.collectContainerMetrics();
    await this.collectSystemMetrics();

    const containers = Array.from(this.metrics.containers.values());
    const optimizations = [];

    // Resource optimization recommendations
    for (const container of containers) {
      // CPU optimization
      if (container.cpu.percent < 5) {
        optimizations.push({
          type: "CPU_UNDERUTILIZED",
          container: container.name,
          recommendation: "Consider reducing CPU limits or consolidating with other services",
          priority: "LOW",
          potential_savings: "10-20% CPU resources"
        });
      } else if (container.cpu.percent > 80) {
        optimizations.push({
          type: "CPU_OVERUTILIZED",
          container: container.name,
          recommendation: "Scale horizontally or increase CPU limits",
          priority: "HIGH",
          action_required: "Immediate scaling needed"
        });
      }

      // Memory optimization
      if (container.memory.percent < 20) {
        optimizations.push({
          type: "MEMORY_UNDERUTILIZED",
          container: container.name,
          recommendation: "Reduce memory limits to free up resources",
          priority: "MEDIUM",
          potential_savings: `${(container.memory.limit - container.memory.used) / 1024 / 1024}MB`
        });
      }

      // Network optimization
      if (container.network.rx_bytes > 100000000) { // 100MB
        optimizations.push({
          type: "HIGH_NETWORK_TRAFFIC",
          container: container.name,
          recommendation: "Consider caching or connection pooling",
          priority: "MEDIUM"
        });
      }
    }

    // System-level optimizations
    const runningContainers = containers.filter(c => c.status.includes("Up"));
    if (runningContainers.length > 20) {
      optimizations.push({
        type: "CONTAINER_SPRAWL",
        recommendation: "Consider consolidating services or using container orchestration",
        priority: "HIGH",
        affected_containers: runningContainers.length
      });
    }

    const result = {
      analysis_timestamp: new Date().toISOString(),
      analysis_period: args?.analysis_period || "current",
      total_optimizations: optimizations.length,
      priority_breakdown: {
        high: optimizations.filter(o => o.priority === "HIGH").length,
        medium: optimizations.filter(o => o.priority === "MEDIUM").length,
        low: optimizations.filter(o => o.priority === "LOW").length
      },
      optimizations: optimizations,
      estimated_savings: {
        cpu_reduction: "15-25%",
        memory_reduction: "20-30%",
        network_efficiency: "10-20%"
      }
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  }

  async monitorResourceHealth(args) {
    const serviceNames = args?.service_names || [];
    await this.collectContainerMetrics();

    const containers = Array.from(this.metrics.containers.values());
    const healthReport = {
      timestamp: new Date().toISOString(),
      services_monitored: serviceNames.length,
      health_status: {}
    };

    for (const serviceName of serviceNames) {
      const container = containers.find(c =>
        c.name.includes(serviceName) || c.image.includes(serviceName)
      );

      if (!container) {
        healthReport.health_status[serviceName] = {
          status: "NOT_FOUND",
          message: "Container not found or not running"
        };
        continue;
      }

      let status = "HEALTHY";
      const issues = [];

      // Health checks
      if (container.cpu.percent > 90) {
        status = "CRITICAL";
        issues.push("CPU usage critically high");
      } else if (container.cpu.percent > 70) {
        status = "WARNING";
        issues.push("CPU usage elevated");
      }

      if (container.memory.percent > 95) {
        status = "CRITICAL";
        issues.push("Memory usage critically high");
      } else if (container.memory.percent > 80) {
        status = status === "CRITICAL" ? "CRITICAL" : "WARNING";
        issues.push("Memory usage elevated");
      }

      if (!container.status.includes("Up")) {
        status = "CRITICAL";
        issues.push("Container not running");
      }

      healthReport.health_status[serviceName] = {
        container_name: container.name,
        status: status,
        cpu_percent: container.cpu.percent,
        memory_percent: container.memory.percent,
        container_status: container.status,
        issues: issues,
        last_check: container.timestamp
      };
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(healthReport, null, 2)
        }
      ]
    };
  }

  startPeriodicCollection() {
    // Collect metrics every 30 seconds
    schedule.scheduleJob('*/30 * * * * *', async () => {
      await this.collectContainerMetrics();
      await this.collectSystemMetrics();
    });

    console.log('Performance monitoring started - collecting metrics every 30 seconds');
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("Performance Monitor MCP Server running on stdio");
  }
}

const server = new PerformanceMonitorServer();
server.run().catch(console.error);