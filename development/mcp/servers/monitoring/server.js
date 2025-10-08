#!/usr/bin/env node
/**
 * Catalytic Computing Monitoring MCP Server
 * Provides Grafana and Prometheus integration for monitoring deployment metrics,
 * system health, performance tracking, and alerting within the Catalytic Computing platform.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import { z } from "zod";
import winston from "winston";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import WebSocket from "ws";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Environment configuration
const PROJECT_ROOT = process.env.PROJECT_ROOT || path.join(__dirname, "../../..");
const PROMETHEUS_URL = process.env.PROMETHEUS_URL || "http://localhost:9090";
const GRAFANA_URL = process.env.GRAFANA_URL || "http://localhost:3000";
const GRAFANA_API_KEY = process.env.GRAFANA_API_KEY;
const LOG_LEVEL = process.env.LOG_LEVEL || "info";

// Logger setup
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "monitoring-mcp-server" },
  transports: [
    new winston.transports.File({ 
      filename: path.join(PROJECT_ROOT, "logs", "monitoring-mcp.log") 
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// HTTP clients setup
const prometheusClient = axios.create({
  baseURL: PROMETHEUS_URL,
  timeout: 30000
});

const grafanaClient = axios.create({
  baseURL: `${GRAFANA_URL}/api`,
  timeout: 30000,
  headers: {
    ...(GRAFANA_API_KEY && { Authorization: `Bearer ${GRAFANA_API_KEY}` }),
    'Content-Type': 'application/json'
  }
});

// Input validation schemas
const PrometheusQuerySchema = z.object({
  query: z.string().describe("PromQL query string"),
  time: z.string().optional().describe("Query timestamp (RFC3339 or Unix timestamp)"),
  timeout: z.string().optional().describe("Query timeout")
});

const PrometheusRangeQuerySchema = z.object({
  query: z.string().describe("PromQL query string"),
  start: z.string().describe("Start timestamp (RFC3339 or Unix timestamp)"),
  end: z.string().describe("End timestamp (RFC3339 or Unix timestamp)"),
  step: z.string().describe("Query resolution step width")
});

const DeploymentMetricsSchema = z.object({
  environment: z.string().describe("Environment to query (production, staging, development)"),
  timeRange: z.string().optional().default("1h").describe("Time range (e.g., '1h', '24h', '7d')"),
  services: z.array(z.string()).optional().describe("Specific services to monitor")
});

const CreateAlertRuleSchema = z.object({
  name: z.string().describe("Alert rule name"),
  query: z.string().describe("PromQL query for the alert"),
  condition: z.string().describe("Alert condition (e.g., '> 0.8')"),
  duration: z.string().optional().default("5m").describe("Duration threshold"),
  labels: z.record(z.string()).optional().describe("Additional labels"),
  annotations: z.record(z.string()).optional().describe("Alert annotations")
});

const GrafanaDashboardSchema = z.object({
  title: z.string().describe("Dashboard title"),
  tags: z.array(z.string()).optional().describe("Dashboard tags"),
  refresh: z.string().optional().default("30s").describe("Refresh interval"),
  panels: z.array(z.any()).optional().describe("Dashboard panels configuration")
});

// MCP Server setup
const server = new Server(
  {
    name: "catalytic-monitoring-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool definitions
const TOOLS = [
  {
    name: "prometheus_query",
    description: "Execute a PromQL query against Prometheus for instant metrics",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "PromQL query string (e.g., 'up', 'rate(http_requests_total[5m])')"
        },
        time: {
          type: "string",
          description: "Query timestamp (RFC3339 or Unix timestamp, defaults to now)"
        },
        timeout: {
          type: "string",
          description: "Query timeout (e.g., '30s')"
        }
      },
      required: ["query"]
    }
  },
  {
    name: "prometheus_range_query",
    description: "Execute a PromQL range query for metrics over time",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "PromQL query string"
        },
        start: {
          type: "string",
          description: "Start timestamp (RFC3339 or Unix timestamp)"
        },
        end: {
          type: "string",
          description: "End timestamp (RFC3339 or Unix timestamp)"
        },
        step: {
          type: "string",
          description: "Query resolution step (e.g., '15s', '1m')"
        }
      },
      required: ["query", "start", "end", "step"]
    }
  },
  {
    name: "get_deployment_metrics",
    description: "Get comprehensive deployment metrics for a specific environment",
    inputSchema: {
      type: "object",
      properties: {
        environment: {
          type: "string",
          description: "Environment (production, staging, development)"
        },
        timeRange: {
          type: "string",
          description: "Time range (1h, 24h, 7d, etc.)",
          default: "1h"
        },
        services: {
          type: "array",
          items: {
            type: "string"
          },
          description: "Specific services to monitor"
        }
      },
      required: ["environment"]
    }
  },
  {
    name: "get_system_health",
    description: "Get overall system health status and key metrics",
    inputSchema: {
      type: "object",
      properties: {
        environment: {
          type: "string",
          description: "Environment filter"
        }
      }
    }
  },
  {
    name: "get_performance_summary",
    description: "Get performance summary including response times, throughput, and errors",
    inputSchema: {
      type: "object",
      properties: {
        timeRange: {
          type: "string",
          description: "Time range for analysis",
          default: "1h"
        },
        environment: {
          type: "string",
          description: "Environment filter"
        }
      }
    }
  },
  {
    name: "create_grafana_dashboard",
    description: "Create a new Grafana dashboard for monitoring",
    inputSchema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description: "Dashboard title"
        },
        tags: {
          type: "array",
          items: {
            type: "string"
          },
          description: "Dashboard tags for organization"
        },
        refresh: {
          type: "string",
          description: "Dashboard refresh interval (30s, 1m, 5m, etc.)",
          default: "30s"
        },
        panels: {
          type: "array",
          description: "Dashboard panels configuration"
        }
      },
      required: ["title"]
    }
  },
  {
    name: "list_grafana_dashboards",
    description: "List available Grafana dashboards",
    inputSchema: {
      type: "object",
      properties: {
        tag: {
          type: "string",
          description: "Filter by tag"
        },
        starred: {
          type: "boolean",
          description: "Show only starred dashboards"
        }
      }
    }
  },
  {
    name: "get_grafana_dashboard",
    description: "Get a specific Grafana dashboard by UID or slug",
    inputSchema: {
      type: "object",
      properties: {
        uid: {
          type: "string",
          description: "Dashboard UID or slug"
        }
      },
      required: ["uid"]
    }
  },
  {
    name: "create_alert_rule",
    description: "Create a Prometheus alert rule for monitoring conditions",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Alert rule name"
        },
        query: {
          type: "string",
          description: "PromQL query for the alert condition"
        },
        condition: {
          type: "string",
          description: "Alert condition threshold (e.g., '> 0.8', '< 100')"
        },
        duration: {
          type: "string",
          description: "Duration threshold (e.g., '5m', '1h')",
          default: "5m"
        },
        labels: {
          type: "object",
          description: "Additional labels for the alert",
          additionalProperties: {
            type: "string"
          }
        },
        annotations: {
          type: "object", 
          description: "Alert annotations (description, summary, etc.)",
          additionalProperties: {
            type: "string"
          }
        }
      },
      required: ["name", "query", "condition"]
    }
  },
  {
    name: "get_active_alerts",
    description: "Get currently active alerts from Prometheus",
    inputSchema: {
      type: "object",
      properties: {
        state: {
          type: "string",
          enum: ["inactive", "pending", "firing"],
          description: "Filter by alert state"
        }
      }
    }
  }
];

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.info("Listing available monitoring tools");
  return { tools: TOOLS };
});

// Tool execution handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  logger.info("Tool called", { tool: name, args });

  try {
    switch (name) {
      case "prometheus_query":
        return await prometheusQuery(args);
      case "prometheus_range_query":
        return await prometheusRangeQuery(args);
      case "get_deployment_metrics":
        return await getDeploymentMetrics(args);
      case "get_system_health":
        return await getSystemHealth(args);
      case "get_performance_summary":
        return await getPerformanceSummary(args);
      case "create_grafana_dashboard":
        return await createGrafanaDashboard(args);
      case "list_grafana_dashboards":
        return await listGrafanaDashboards(args);
      case "get_grafana_dashboard":
        return await getGrafanaDashboard(args);
      case "create_alert_rule":
        return await createAlertRule(args);
      case "get_active_alerts":
        return await getActiveAlerts(args);
      default:
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: ${name}`
        );
    }
  } catch (error) {
    logger.error("Tool execution failed", { tool: name, error: error.message, stack: error.stack });
    
    if (error instanceof McpError) {
      throw error;
    }
    
    throw new McpError(
      ErrorCode.InternalError,
      `Tool execution failed: ${error.message}`
    );
  }
});

// Tool implementations
async function prometheusQuery(args) {
  const { query, time, timeout } = PrometheusQuerySchema.parse(args);
  
  logger.info("Executing Prometheus query", { query, time });
  
  const params = { query };
  if (time) params.time = time;
  if (timeout) params.timeout = timeout;
  
  const response = await prometheusClient.get('/api/v1/query', { params });
  const data = response.data;
  
  if (data.status !== 'success') {
    throw new Error(`Query failed: ${data.error}`);
  }
  
  const results = data.data.result;
  
  return {
    content: [{
      type: "text",
      text: `📊 **Prometheus Query Results**\n\n` +
            `Query: \`${query}\`\n` +
            `Results: ${results.length} series\n\n` +
            results.map((result, index) => {
              const metric = result.metric;
              const value = result.value;
              const labels = Object.entries(metric)
                .map(([key, val]) => `${key}="${val}"`)
                .join(", ");
              
              return `${index + 1}. **${metric.__name__ || 'metric'}**{${labels}}\n` +
                     `   Value: ${value[1]} (at ${new Date(value[0] * 1000).toLocaleString()})`;
            }).join("\n\n")
    }]
  };
}

async function prometheusRangeQuery(args) {
  const { query, start, end, step } = PrometheusRangeQuerySchema.parse(args);
  
  logger.info("Executing Prometheus range query", { query, start, end, step });
  
  const params = { query, start, end, step };
  const response = await prometheusClient.get('/api/v1/query_range', { params });
  const data = response.data;
  
  if (data.status !== 'success') {
    throw new Error(`Range query failed: ${data.error}`);
  }
  
  const results = data.data.result;
  
  return {
    content: [{
      type: "text",
      text: `📈 **Prometheus Range Query Results**\n\n` +
            `Query: \`${query}\`\n` +
            `Time Range: ${start} to ${end} (step: ${step})\n` +
            `Results: ${results.length} series\n\n` +
            results.map((result, index) => {
              const metric = result.metric;
              const values = result.values;
              const labels = Object.entries(metric)
                .map(([key, val]) => `${key}="${val}"`)
                .join(", ");
              
              const firstValue = values[0];
              const lastValue = values[values.length - 1];
              
              return `${index + 1}. **${metric.__name__ || 'metric'}**{${labels}}\n` +
                     `   Data Points: ${values.length}\n` +
                     `   First: ${firstValue[1]} (${new Date(firstValue[0] * 1000).toLocaleString()})\n` +
                     `   Last: ${lastValue[1]} (${new Date(lastValue[0] * 1000).toLocaleString()})`;
            }).join("\n\n")
    }]
  };
}

async function getDeploymentMetrics(args) {
  const { environment, timeRange, services } = DeploymentMetricsSchema.parse(args);
  
  logger.info("Getting deployment metrics", { environment, timeRange, services });
  
  const endTime = Math.floor(Date.now() / 1000);
  const startTime = endTime - parseTimeRange(timeRange);
  
  // Build base queries
  const queries = {
    uptime: `up{environment="${environment}"}`,
    cpuUsage: `rate(cpu_usage_seconds_total{environment="${environment}"}[5m]) * 100`,
    memoryUsage: `memory_usage_bytes{environment="${environment}"} / memory_limit_bytes{environment="${environment}"} * 100`,
    httpRequests: `rate(http_requests_total{environment="${environment}"}[5m])`,
    httpErrors: `rate(http_requests_total{environment="${environment}",status=~"5.."}[5m])`,
    responseTime: `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{environment="${environment}"}[5m]))`
  };
  
  // Execute all queries in parallel
  const results = await Promise.allSettled(
    Object.entries(queries).map(async ([name, query]) => {
      try {
        const response = await prometheusClient.get('/api/v1/query', { 
          params: { query, time: endTime }
        });
        return { name, data: response.data.data.result };
      } catch (error) {
        logger.warn("Query failed", { query: name, error: error.message });
        return { name, data: [], error: error.message };
      }
    })
  );
  
  // Process results
  const metrics = {};
  results.forEach((result) => {
    if (result.status === 'fulfilled') {
      metrics[result.value.name] = result.value.data;
    }
  });
  
  // Calculate summary statistics
  const summary = {
    servicesUp: metrics.uptime?.filter(m => m.value[1] === "1").length || 0,
    totalServices: metrics.uptime?.length || 0,
    avgCpuUsage: calculateAverage(metrics.cpuUsage),
    avgMemoryUsage: calculateAverage(metrics.memoryUsage),
    requestRate: calculateSum(metrics.httpRequests),
    errorRate: calculateSum(metrics.httpErrors),
    avgResponseTime: calculateAverage(metrics.responseTime)
  };
  
  return {
    content: [{
      type: "text",
      text: `🚀 **Deployment Metrics - ${environment.toUpperCase()}**\n` +
            `📊 Time Range: ${timeRange}\n` +
            `⏰ Last Updated: ${new Date().toLocaleString()}\n\n` +
            
            `**🔄 Service Status**\n` +
            `• Services Up: ${summary.servicesUp}/${summary.totalServices}\n` +
            `• Health: ${summary.totalServices > 0 ? ((summary.servicesUp / summary.totalServices) * 100).toFixed(1) : 0}%\n\n` +
            
            `**💻 Resource Usage**\n` +
            `• Average CPU: ${summary.avgCpuUsage.toFixed(2)}%\n` +
            `• Average Memory: ${summary.avgMemoryUsage.toFixed(2)}%\n\n` +
            
            `**🌐 HTTP Metrics**\n` +
            `• Request Rate: ${summary.requestRate.toFixed(2)} req/sec\n` +
            `• Error Rate: ${summary.errorRate.toFixed(4)} errors/sec\n` +
            `• 95th Percentile Response Time: ${(summary.avgResponseTime * 1000).toFixed(2)}ms\n` +
            `• Error Percentage: ${summary.requestRate > 0 ? ((summary.errorRate / summary.requestRate) * 100).toFixed(3) : 0}%\n\n` +
            
            `**📈 Service Details**\n` +
            (metrics.uptime?.map(service => {
              const serviceName = service.metric.instance || service.metric.job || "unknown";
              const status = service.value[1] === "1" ? "🟢 UP" : "🔴 DOWN";
              return `• ${serviceName}: ${status}`;
            }).join("\n") || "No services found")
    }]
  };
}

async function getSystemHealth(args) {
  const { environment } = args || {};
  
  logger.info("Getting system health", { environment });
  
  const queries = [
    { name: "services", query: `up${environment ? `{environment="${environment}"}` : ""}` },
    { name: "disk", query: `disk_usage_percent${environment ? `{environment="${environment}"}` : ""}` },
    { name: "memory", query: `memory_usage_percent${environment ? `{environment="${environment}"}` : ""}` },
    { name: "load", query: `node_load1${environment ? `{environment="${environment}"}` : ""}` }
  ];
  
  const results = await Promise.allSettled(
    queries.map(async ({ name, query }) => {
      try {
        const response = await prometheusClient.get('/api/v1/query', { 
          params: { query }
        });
        return { name, data: response.data.data.result };
      } catch (error) {
        return { name, data: [], error: error.message };
      }
    })
  );
  
  const healthData = {};
  results.forEach((result) => {
    if (result.status === 'fulfilled') {
      healthData[result.value.name] = result.value.data;
    }
  });
  
  // Calculate health scores
  const upServices = healthData.services?.filter(s => s.value[1] === "1").length || 0;
  const totalServices = healthData.services?.length || 1;
  const serviceHealth = (upServices / totalServices) * 100;
  
  const avgDiskUsage = calculateAverage(healthData.disk);
  const avgMemoryUsage = calculateAverage(healthData.memory);
  const avgLoad = calculateAverage(healthData.load);
  
  // Overall health score
  const healthScore = Math.min(
    serviceHealth,
    Math.max(0, 100 - avgDiskUsage),
    Math.max(0, 100 - avgMemoryUsage),
    Math.max(0, 100 - (avgLoad * 20)) // Load of 5 = 0% health
  );
  
  const healthStatus = healthScore >= 90 ? "🟢 EXCELLENT" :
                      healthScore >= 75 ? "🟡 GOOD" :
                      healthScore >= 50 ? "🟠 WARNING" : "🔴 CRITICAL";
  
  return {
    content: [{
      type: "text",
      text: `🏥 **System Health Report**${environment ? ` - ${environment.toUpperCase()}` : ""}\n\n` +
            `**Overall Health: ${healthScore.toFixed(1)}% ${healthStatus}**\n\n` +
            
            `📊 **Service Status**\n` +
            `• Services Up: ${upServices}/${totalServices} (${serviceHealth.toFixed(1)}%)\n\n` +
            
            `💾 **Resource Utilization**\n` +
            `• Disk Usage: ${avgDiskUsage.toFixed(1)}%\n` +
            `• Memory Usage: ${avgMemoryUsage.toFixed(1)}%\n` +
            `• System Load: ${avgLoad.toFixed(2)}\n\n` +
            
            `🚨 **Health Indicators**\n` +
            `• ${serviceHealth >= 95 ? "✅" : "❌"} Service Availability (${serviceHealth.toFixed(1)}%)\n` +
            `• ${avgDiskUsage < 80 ? "✅" : "❌"} Disk Space (${avgDiskUsage.toFixed(1)}% used)\n` +
            `• ${avgMemoryUsage < 85 ? "✅" : "❌"} Memory Usage (${avgMemoryUsage.toFixed(1)}% used)\n` +
            `• ${avgLoad < 4 ? "✅" : "❌"} System Load (${avgLoad.toFixed(2)})\n\n` +
            
            `⏰ Last Updated: ${new Date().toLocaleString()}`
    }]
  };
}

async function getPerformanceSummary(args) {
  const { timeRange = "1h", environment } = args || {};
  
  logger.info("Getting performance summary", { timeRange, environment });
  
  const endTime = Math.floor(Date.now() / 1000);
  const startTime = endTime - parseTimeRange(timeRange);
  const step = Math.max(60, Math.floor((endTime - startTime) / 100)); // Max 100 data points
  
  const envFilter = environment ? `{environment="${environment}"}` : "";
  
  const queries = [
    { name: "throughput", query: `rate(http_requests_total${envFilter}[5m])` },
    { name: "latency_p50", query: `histogram_quantile(0.50, rate(http_request_duration_seconds_bucket${envFilter}[5m]))` },
    { name: "latency_p95", query: `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket${envFilter}[5m]))` },
    { name: "latency_p99", query: `histogram_quantile(0.99, rate(http_request_duration_seconds_bucket${envFilter}[5m]))` },
    { name: "errors", query: `rate(http_requests_total${envFilter}{status=~"5.."}[5m])` }
  ];
  
  const results = await Promise.allSettled(
    queries.map(async ({ name, query }) => {
      try {
        const response = await prometheusClient.get('/api/v1/query_range', {
          params: { query, start: startTime, end: endTime, step: `${step}s` }
        });
        return { name, data: response.data.data.result };
      } catch (error) {
        return { name, data: [], error: error.message };
      }
    })
  );
  
  const perfData = {};
  results.forEach((result) => {
    if (result.status === 'fulfilled') {
      perfData[result.value.name] = result.value.data;
    }
  });
  
  // Calculate summary statistics
  const throughput = calculateTimeSeriesAverage(perfData.throughput);
  const latencyP50 = calculateTimeSeriesAverage(perfData.latency_p50) * 1000; // Convert to ms
  const latencyP95 = calculateTimeSeriesAverage(perfData.latency_p95) * 1000;
  const latencyP99 = calculateTimeSeriesAverage(perfData.latency_p99) * 1000;
  const errorRate = calculateTimeSeriesAverage(perfData.errors);
  
  const errorPercentage = throughput > 0 ? (errorRate / throughput) * 100 : 0;
  
  return {
    content: [{
      type: "text",
      text: `⚡ **Performance Summary**${environment ? ` - ${environment.toUpperCase()}` : ""}\n` +
            `📊 Time Range: ${timeRange}\n` +
            `⏰ Analysis Period: ${new Date(startTime * 1000).toLocaleString()} to ${new Date(endTime * 1000).toLocaleString()}\n\n` +
            
            `**🚀 Throughput**\n` +
            `• Average Request Rate: ${throughput.toFixed(2)} req/sec\n` +
            `• Estimated Requests: ${Math.round(throughput * parseTimeRange(timeRange))} requests\n\n` +
            
            `**⏱️ Response Times**\n` +
            `• 50th Percentile: ${latencyP50.toFixed(2)}ms\n` +
            `• 95th Percentile: ${latencyP95.toFixed(2)}ms\n` +
            `• 99th Percentile: ${latencyP99.toFixed(2)}ms\n\n` +
            
            `**🚨 Error Metrics**\n` +
            `• Error Rate: ${errorRate.toFixed(4)} errors/sec\n` +
            `• Error Percentage: ${errorPercentage.toFixed(3)}%\n` +
            `• Estimated Errors: ${Math.round(errorRate * parseTimeRange(timeRange))} errors\n\n` +
            
            `**📈 Performance Grade**\n` +
            `• Throughput: ${getThroughputGrade(throughput)}\n` +
            `• Latency: ${getLatencyGrade(latencyP95)}\n` +
            `• Reliability: ${getReliabilityGrade(errorPercentage)}\n\n` +
            
            `⏰ Last Updated: ${new Date().toLocaleString()}`
    }]
  };
}

async function createGrafanaDashboard(args) {
  const { title, tags = [], refresh = "30s", panels = [] } = GrafanaDashboardSchema.parse(args);
  
  logger.info("Creating Grafana dashboard", { title, tags });
  
  const dashboardPayload = {
    dashboard: {
      title,
      tags,
      refresh,
      panels,
      time: {
        from: "now-1h",
        to: "now"
      },
      timepicker: {
        refresh_intervals: ["5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"]
      },
      timezone: "browser",
      version: 1
    },
    overwrite: false
  };
  
  const response = await grafanaClient.post('/dashboards/db', dashboardPayload);
  const result = response.data;
  
  return {
    content: [{
      type: "text",
      text: `📊 **Grafana Dashboard Created**\n\n` +
            `• Title: ${title}\n` +
            `• UID: ${result.uid}\n` +
            `• URL: ${GRAFANA_URL}/d/${result.uid}/${result.slug}\n` +
            `• Version: ${result.version}\n` +
            `• Status: ${result.status}\n` +
            `• Tags: ${tags.join(", ") || "None"}\n` +
            `• Panels: ${panels.length} configured\n\n` +
            `✅ Dashboard is ready for use!`
    }]
  };
}

async function listGrafanaDashboards(args) {
  const { tag, starred } = args || {};
  
  logger.info("Listing Grafana dashboards", { tag, starred });
  
  const params = {};
  if (tag) params.tag = tag;
  if (starred) params.starred = "true";
  
  const response = await grafanaClient.get('/search', { params });
  const dashboards = response.data;
  
  return {
    content: [{
      type: "text",
      text: `📊 **Grafana Dashboards** (${dashboards.length} found)\n\n` +
            dashboards.map((dashboard, index) => 
              `${index + 1}. **${dashboard.title}**\n` +
              `   • UID: ${dashboard.uid}\n` +
              `   • Type: ${dashboard.type}\n` +
              `   • URL: ${GRAFANA_URL}${dashboard.url}\n` +
              `   • Tags: ${dashboard.tags?.join(", ") || "None"}\n` +
              `   • Starred: ${dashboard.isStarred ? "⭐" : "☆"}`
            ).join("\n\n")
    }]
  };
}

async function getGrafanaDashboard(args) {
  const { uid } = args;
  
  logger.info("Getting Grafana dashboard", { uid });
  
  const response = await grafanaClient.get(`/dashboards/uid/${uid}`);
  const result = response.data;
  const dashboard = result.dashboard;
  
  return {
    content: [{
      type: "text",
      text: `📊 **Dashboard: ${dashboard.title}**\n\n` +
            `• UID: ${dashboard.uid}\n` +
            `• Version: ${dashboard.version}\n` +
            `• Created: ${new Date(dashboard.meta?.created).toLocaleDateString()}\n` +
            `• Updated: ${new Date(dashboard.meta?.updated).toLocaleDateString()}\n` +
            `• Tags: ${dashboard.tags?.join(", ") || "None"}\n` +
            `• Panels: ${dashboard.panels?.length || 0}\n` +
            `• Refresh: ${dashboard.refresh}\n` +
            `• URL: ${GRAFANA_URL}/d/${dashboard.uid}/${dashboard.meta?.slug}\n\n` +
            
            `**Panel Overview:**\n` +
            (dashboard.panels?.map((panel, index) => 
              `${index + 1}. ${panel.title || `Panel ${panel.id}`} (${panel.type})`
            ).join("\n") || "No panels configured")
    }]
  };
}

async function createAlertRule(args) {
  const { name, query, condition, duration, labels = {}, annotations = {} } = CreateAlertRuleSchema.parse(args);
  
  logger.info("Creating alert rule", { name, query, condition });
  
  // This is a simplified implementation - in a real scenario, you'd integrate with Alertmanager
  const alertRule = {
    alert: name,
    expr: `${query} ${condition}`,
    for: duration,
    labels: {
      severity: labels.severity || "warning",
      service: labels.service || "catalytic-computing",
      ...labels
    },
    annotations: {
      summary: annotations.summary || `Alert: ${name}`,
      description: annotations.description || `${query} ${condition} for more than ${duration}`,
      ...annotations
    }
  };
  
  // In a real implementation, you would write this to a Prometheus rules file
  const alertConfig = `
groups:
  - name: catalytic-computing-alerts
    rules:
      - alert: ${alertRule.alert}
        expr: ${alertRule.expr}
        for: ${alertRule.for}
        labels:
${Object.entries(alertRule.labels).map(([key, value]) => `          ${key}: ${value}`).join('\n')}
        annotations:
${Object.entries(alertRule.annotations).map(([key, value]) => `          ${key}: "${value}"`).join('\n')}
`;
  
  return {
    content: [{
      type: "text",
      text: `🚨 **Alert Rule Created**\n\n` +
            `• Name: ${name}\n` +
            `• Query: ${query}\n` +
            `• Condition: ${condition}\n` +
            `• Duration: ${duration}\n` +
            `• Labels: ${Object.keys(labels).length} configured\n` +
            `• Annotations: ${Object.keys(annotations).length} configured\n\n` +
            `**Generated Rule:**\n` +
            `\`\`\`yaml\n${alertConfig.trim()}\n\`\`\`\n\n` +
            `⚠️ **Note:** Add this rule to your Prometheus configuration and reload to activate.`
    }]
  };
}

async function getActiveAlerts(args) {
  const { state } = args || {};
  
  logger.info("Getting active alerts", { state });
  
  const params = {};
  if (state) params.state = state;
  
  const response = await prometheusClient.get('/api/v1/alerts', { params });
  const alerts = response.data.data.alerts;
  
  const groupedAlerts = alerts.reduce((groups, alert) => {
    const alertState = alert.state;
    if (!groups[alertState]) groups[alertState] = [];
    groups[alertState].push(alert);
    return groups;
  }, {});
  
  const stateEmojis = {
    firing: "🔥",
    pending: "⏳", 
    inactive: "✅"
  };
  
  return {
    content: [{
      type: "text",
      text: `🚨 **Active Alerts** (${alerts.length} total)\n\n` +
            Object.entries(groupedAlerts).map(([alertState, stateAlerts]) =>
              `**${stateEmojis[alertState] || "❓"} ${alertState.toUpperCase()}** (${stateAlerts.length})\n` +
              stateAlerts.map(alert => {
                const labels = Object.entries(alert.labels)
                  .filter(([key]) => key !== '__name__')
                  .map(([key, value]) => `${key}="${value}"`)
                  .join(", ");
                
                return `• **${alert.labels.alertname}**\n` +
                       `  Labels: {${labels}}\n` +
                       `  Value: ${alert.value}\n` +
                       `  Started: ${new Date(alert.activeAt).toLocaleString()}\n` +
                       (alert.annotations?.description ? `  Description: ${alert.annotations.description}\n` : "");
              }).join("\n")
            ).join("\n\n") || "No alerts found"
    }]
  };
}

// Utility functions
function parseTimeRange(timeRange) {
  const units = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  const match = timeRange.match(/^(\d+)([smhdw])$/);
  if (!match) return 3600; // Default 1 hour
  
  const [, amount, unit] = match;
  return parseInt(amount) * (units[unit] || 3600);
}

function calculateAverage(series) {
  if (!series || !Array.isArray(series) || series.length === 0) return 0;
  
  const values = series.map(s => parseFloat(s.value[1])).filter(v => !isNaN(v));
  return values.length > 0 ? values.reduce((a, b) => a + b, 0) / values.length : 0;
}

function calculateSum(series) {
  if (!series || !Array.isArray(series) || series.length === 0) return 0;
  
  const values = series.map(s => parseFloat(s.value[1])).filter(v => !isNaN(v));
  return values.reduce((a, b) => a + b, 0);
}

function calculateTimeSeriesAverage(series) {
  if (!series || !Array.isArray(series) || series.length === 0) return 0;
  
  let totalSum = 0;
  let totalPoints = 0;
  
  series.forEach(s => {
    if (s.values && Array.isArray(s.values)) {
      s.values.forEach(([, value]) => {
        const numValue = parseFloat(value);
        if (!isNaN(numValue)) {
          totalSum += numValue;
          totalPoints++;
        }
      });
    }
  });
  
  return totalPoints > 0 ? totalSum / totalPoints : 0;
}

function getThroughputGrade(rps) {
  if (rps >= 100) return "🟢 Excellent";
  if (rps >= 50) return "🟡 Good";
  if (rps >= 10) return "🟠 Fair";
  return "🔴 Low";
}

function getLatencyGrade(p95Ms) {
  if (p95Ms <= 100) return "🟢 Excellent";
  if (p95Ms <= 500) return "🟡 Good";
  if (p95Ms <= 1000) return "🟠 Fair";
  return "🔴 Poor";
}

function getReliabilityGrade(errorPercent) {
  if (errorPercent <= 0.1) return "🟢 Excellent";
  if (errorPercent <= 1) return "🟡 Good";
  if (errorPercent <= 5) return "🟠 Fair";
  return "🔴 Poor";
}

// Error handling
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server
async function main() {
  // Ensure logs directory exists
  const logsDir = path.join(PROJECT_ROOT, "logs");
  try {
    await fs.mkdir(logsDir, { recursive: true });
  } catch (error) {
    // Directory might already exist
  }
  
  // Test Prometheus connection
  try {
    await prometheusClient.get('/api/v1/query', { 
      params: { query: 'up' },
      timeout: 5000
    });
    logger.info("Prometheus connection verified", { url: PROMETHEUS_URL });
  } catch (error) {
    logger.warn("Could not connect to Prometheus", { 
      url: PROMETHEUS_URL, 
      error: error.message 
    });
  }
  
  // Test Grafana connection (if API key provided)
  if (GRAFANA_API_KEY) {
    try {
      await grafanaClient.get('/org');
      logger.info("Grafana connection verified", { url: GRAFANA_URL });
    } catch (error) {
      logger.warn("Could not connect to Grafana", { 
        url: GRAFANA_URL, 
        error: error.message 
      });
    }
  } else {
    logger.warn("Grafana API key not provided - Grafana features will be limited");
  }
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Catalytic Monitoring MCP Server started", { 
    prometheus: PROMETHEUS_URL,
    grafana: GRAFANA_URL
  });
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});