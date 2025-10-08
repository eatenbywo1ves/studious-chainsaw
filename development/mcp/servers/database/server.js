#!/usr/bin/env node
/**
 * Catalytic Computing Database MCP Server
 * Provides database operations and deployment status tracking
 * with PostgreSQL and Redis integration for the Catalytic Computing platform.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import pg from "pg";
import { createClient } from "redis";
import { z } from "zod";
import winston from "winston";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const { Pool } = pg;

// Environment configuration
const PROJECT_ROOT = process.env.PROJECT_ROOT || path.join(__dirname, "../../..");
const DATABASE_URL = process.env.DATABASE_URL;
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
const LOG_LEVEL = process.env.LOG_LEVEL || "info";

// Logger setup
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "database-mcp-server" },
  transports: [
    new winston.transports.File({ 
      filename: path.join(PROJECT_ROOT, "logs", "database-mcp.log") 
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Database clients
let pgPool = null;
let redisClient = null;

// Initialize database connections
async function initializeConnections() {
  // PostgreSQL connection
  if (DATABASE_URL) {
    try {
      pgPool = new Pool({
        connectionString: DATABASE_URL,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
      });
      
      // Test connection
      await pgPool.query('SELECT NOW()');
      logger.info("PostgreSQL connection established");
      
      // Ensure deployment tracking tables exist
      await createDeploymentTables();
      
    } catch (error) {
      logger.error("Failed to connect to PostgreSQL", { error: error.message });
      pgPool = null;
    }
  } else {
    logger.warn("DATABASE_URL not provided - PostgreSQL features disabled");
  }
  
  // Redis connection
  try {
    redisClient = createClient({
      url: REDIS_URL
    });
    
    redisClient.on('error', (err) => {
      logger.error('Redis client error:', err);
    });
    
    redisClient.on('connect', () => {
      logger.info('Connected to Redis');
    });
    
    redisClient.on('reconnecting', () => {
      logger.info('Reconnecting to Redis...');
    });
    
    await redisClient.connect();
    
    // Test connection
    await redisClient.ping();
    logger.info("Redis connection established");
    
  } catch (error) {
    logger.error("Failed to connect to Redis", { error: error.message });
    redisClient = null;
  }
}

// Create deployment tracking tables
async function createDeploymentTables() {
  if (!pgPool) return;
  
  const deploymentSchema = `
    CREATE TABLE IF NOT EXISTS deployments (
      id SERIAL PRIMARY KEY,
      deployment_id VARCHAR(255) UNIQUE NOT NULL,
      environment VARCHAR(50) NOT NULL,
      service_name VARCHAR(100),
      version VARCHAR(100),
      git_commit VARCHAR(40),
      git_branch VARCHAR(100),
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      completed_at TIMESTAMP WITH TIME ZONE,
      duration_seconds INTEGER,
      deployed_by VARCHAR(100),
      rollback_to VARCHAR(255),
      configuration JSONB,
      metadata JSONB,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
    
    CREATE INDEX IF NOT EXISTS idx_deployments_environment ON deployments(environment);
    CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status);
    CREATE INDEX IF NOT EXISTS idx_deployments_started_at ON deployments(started_at);
    CREATE INDEX IF NOT EXISTS idx_deployments_service ON deployments(service_name);
  `;
  
  const deploymentEventsSchema = `
    CREATE TABLE IF NOT EXISTS deployment_events (
      id SERIAL PRIMARY KEY,
      deployment_id VARCHAR(255) NOT NULL REFERENCES deployments(deployment_id),
      event_type VARCHAR(50) NOT NULL,
      message TEXT,
      details JSONB,
      timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
    
    CREATE INDEX IF NOT EXISTS idx_deployment_events_deployment_id ON deployment_events(deployment_id);
    CREATE INDEX IF NOT EXISTS idx_deployment_events_timestamp ON deployment_events(timestamp);
  `;
  
  const deploymentMetricsSchema = `
    CREATE TABLE IF NOT EXISTS deployment_metrics (
      id SERIAL PRIMARY KEY,
      deployment_id VARCHAR(255) NOT NULL REFERENCES deployments(deployment_id),
      metric_name VARCHAR(100) NOT NULL,
      metric_value NUMERIC,
      metric_unit VARCHAR(20),
      timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
    
    CREATE INDEX IF NOT EXISTS idx_deployment_metrics_deployment_id ON deployment_metrics(deployment_id);
    CREATE INDEX IF NOT EXISTS idx_deployment_metrics_name ON deployment_metrics(metric_name);
  `;
  
  try {
    await pgPool.query(deploymentSchema);
    await pgPool.query(deploymentEventsSchema);
    await pgPool.query(deploymentMetricsSchema);
    logger.info("Deployment tracking tables created/verified");
  } catch (error) {
    logger.error("Failed to create deployment tables", { error: error.message });
  }
}

// Input validation schemas
const CreateDeploymentSchema = z.object({
  deploymentId: z.string().describe("Unique deployment identifier"),
  environment: z.string().describe("Target environment"),
  serviceName: z.string().optional().describe("Service being deployed"),
  version: z.string().optional().describe("Version/tag being deployed"),
  gitCommit: z.string().optional().describe("Git commit hash"),
  gitBranch: z.string().optional().describe("Git branch"),
  deployedBy: z.string().optional().describe("User initiating deployment"),
  configuration: z.record(z.any()).optional().describe("Deployment configuration"),
  metadata: z.record(z.any()).optional().describe("Additional metadata")
});

const UpdateDeploymentSchema = z.object({
  deploymentId: z.string().describe("Deployment identifier"),
  status: z.enum(["pending", "in_progress", "success", "failure", "cancelled", "rolled_back"]).optional().describe("Deployment status"),
  completedAt: z.string().optional().describe("Completion timestamp"),
  durationSeconds: z.number().optional().describe("Deployment duration"),
  rollbackTo: z.string().optional().describe("Rollback target deployment ID"),
  metadata: z.record(z.any()).optional().describe("Updated metadata")
});

const AddDeploymentEventSchema = z.object({
  deploymentId: z.string().describe("Deployment identifier"),
  eventType: z.string().describe("Event type (started, progress, completed, error, etc.)"),
  message: z.string().optional().describe("Event message"),
  details: z.record(z.any()).optional().describe("Event details")
});

const QuerySchema = z.object({
  sql: z.string().describe("SQL query to execute"),
  params: z.array(z.any()).optional().describe("Query parameters")
});

// MCP Server setup
const server = new Server(
  {
    name: "catalytic-database-mcp",
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
    name: "create_deployment",
    description: "Create a new deployment record for tracking",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Unique deployment identifier"
        },
        environment: {
          type: "string",
          description: "Target environment (production, staging, development)"
        },
        serviceName: {
          type: "string",
          description: "Service being deployed"
        },
        version: {
          type: "string",
          description: "Version/tag being deployed"
        },
        gitCommit: {
          type: "string",
          description: "Git commit hash"
        },
        gitBranch: {
          type: "string",
          description: "Git branch"
        },
        deployedBy: {
          type: "string",
          description: "User initiating deployment"
        },
        configuration: {
          type: "object",
          description: "Deployment configuration"
        },
        metadata: {
          type: "object",
          description: "Additional metadata"
        }
      },
      required: ["deploymentId", "environment"]
    }
  },
  {
    name: "update_deployment",
    description: "Update deployment status and details",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment identifier"
        },
        status: {
          type: "string",
          enum: ["pending", "in_progress", "success", "failure", "cancelled", "rolled_back"],
          description: "Deployment status"
        },
        completedAt: {
          type: "string",
          description: "Completion timestamp (ISO string)"
        },
        durationSeconds: {
          type: "number",
          description: "Deployment duration in seconds"
        },
        rollbackTo: {
          type: "string",
          description: "Rollback target deployment ID"
        },
        metadata: {
          type: "object",
          description: "Updated metadata"
        }
      },
      required: ["deploymentId"]
    }
  },
  {
    name: "get_deployment",
    description: "Get deployment details by ID",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment identifier"
        }
      },
      required: ["deploymentId"]
    }
  },
  {
    name: "list_deployments",
    description: "List deployments with filtering options",
    inputSchema: {
      type: "object",
      properties: {
        environment: {
          type: "string",
          description: "Filter by environment"
        },
        status: {
          type: "string",
          description: "Filter by status"
        },
        serviceName: {
          type: "string",
          description: "Filter by service name"
        },
        limit: {
          type: "number",
          description: "Maximum number of results (default: 50)"
        },
        offset: {
          type: "number",
          description: "Offset for pagination (default: 0)"
        }
      }
    }
  },
  {
    name: "add_deployment_event",
    description: "Add an event to deployment timeline",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment identifier"
        },
        eventType: {
          type: "string",
          description: "Event type (started, progress, completed, error, etc.)"
        },
        message: {
          type: "string",
          description: "Event message"
        },
        details: {
          type: "object",
          description: "Event details"
        }
      },
      required: ["deploymentId", "eventType"]
    }
  },
  {
    name: "get_deployment_events",
    description: "Get events for a deployment",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment identifier"
        }
      },
      required: ["deploymentId"]
    }
  },
  {
    name: "add_deployment_metric",
    description: "Add a metric measurement for a deployment",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment identifier"
        },
        metricName: {
          type: "string",
          description: "Metric name (e.g., 'response_time', 'error_rate')"
        },
        metricValue: {
          type: "number",
          description: "Metric value"
        },
        metricUnit: {
          type: "string",
          description: "Metric unit (e.g., 'ms', 'percent', 'count')"
        }
      },
      required: ["deploymentId", "metricName", "metricValue"]
    }
  },
  {
    name: "get_deployment_metrics",
    description: "Get metrics for a deployment",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment identifier"
        },
        metricName: {
          type: "string",
          description: "Filter by metric name"
        }
      },
      required: ["deploymentId"]
    }
  },
  {
    name: "get_deployment_stats",
    description: "Get deployment statistics and trends",
    inputSchema: {
      type: "object",
      properties: {
        environment: {
          type: "string",
          description: "Filter by environment"
        },
        days: {
          type: "number",
          description: "Number of days to analyze (default: 30)"
        }
      }
    }
  },
  {
    name: "cache_set",
    description: "Set a value in Redis cache",
    inputSchema: {
      type: "object",
      properties: {
        key: {
          type: "string",
          description: "Cache key"
        },
        value: {
          type: "string",
          description: "Cache value (will be JSON stringified if object)"
        },
        ttl: {
          type: "number",
          description: "Time to live in seconds (optional)"
        }
      },
      required: ["key", "value"]
    }
  },
  {
    name: "cache_get",
    description: "Get a value from Redis cache",
    inputSchema: {
      type: "object",
      properties: {
        key: {
          type: "string",
          description: "Cache key"
        }
      },
      required: ["key"]
    }
  },
  {
    name: "cache_delete",
    description: "Delete a key from Redis cache",
    inputSchema: {
      type: "object",
      properties: {
        key: {
          type: "string",
          description: "Cache key to delete"
        }
      },
      required: ["key"]
    }
  },
  {
    name: "execute_query",
    description: "Execute a custom SQL query (use with caution)",
    inputSchema: {
      type: "object",
      properties: {
        sql: {
          type: "string",
          description: "SQL query to execute"
        },
        params: {
          type: "array",
          description: "Query parameters"
        }
      },
      required: ["sql"]
    }
  }
];

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.info("Listing available database tools");
  return { tools: TOOLS };
});

// Tool execution handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  logger.info("Tool called", { tool: name, args });

  try {
    switch (name) {
      case "create_deployment":
        return await createDeployment(args);
      case "update_deployment":
        return await updateDeployment(args);
      case "get_deployment":
        return await getDeployment(args);
      case "list_deployments":
        return await listDeployments(args);
      case "add_deployment_event":
        return await addDeploymentEvent(args);
      case "get_deployment_events":
        return await getDeploymentEvents(args);
      case "add_deployment_metric":
        return await addDeploymentMetric(args);
      case "get_deployment_metrics":
        return await getDeploymentMetrics(args);
      case "get_deployment_stats":
        return await getDeploymentStats(args);
      case "cache_set":
        return await cacheSet(args);
      case "cache_get":
        return await cacheGet(args);
      case "cache_delete":
        return await cacheDelete(args);
      case "execute_query":
        return await executeQuery(args);
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
async function createDeployment(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const {
    deploymentId,
    environment,
    serviceName,
    version,
    gitCommit,
    gitBranch,
    deployedBy,
    configuration,
    metadata
  } = CreateDeploymentSchema.parse(args);
  
  logger.info("Creating deployment record", { deploymentId, environment });
  
  const query = `
    INSERT INTO deployments (
      deployment_id, environment, service_name, version, git_commit, 
      git_branch, deployed_by, configuration, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING *
  `;
  
  const values = [
    deploymentId,
    environment,
    serviceName || null,
    version || null,
    gitCommit || null,
    gitBranch || null,
    deployedBy || null,
    configuration ? JSON.stringify(configuration) : null,
    metadata ? JSON.stringify(metadata) : null
  ];
  
  const result = await pgPool.query(query, values);
  const deployment = result.rows[0];
  
  // Cache deployment for quick access
  if (redisClient) {
    await redisClient.setEx(
      `deployment:${deploymentId}`,
      3600, // 1 hour TTL
      JSON.stringify(deployment)
    );
  }
  
  return {
    content: [{
      type: "text",
      text: `✅ **Deployment Created**\n\n` +
            `• ID: ${deployment.deployment_id}\n` +
            `• Environment: ${deployment.environment}\n` +
            `• Service: ${deployment.service_name || "N/A"}\n` +
            `• Version: ${deployment.version || "N/A"}\n` +
            `• Branch: ${deployment.git_branch || "N/A"}\n` +
            `• Commit: ${deployment.git_commit?.substring(0, 7) || "N/A"}\n` +
            `• Deployed by: ${deployment.deployed_by || "N/A"}\n` +
            `• Status: ${deployment.status}\n` +
            `• Created: ${new Date(deployment.created_at).toLocaleString()}`
    }]
  };
}

async function updateDeployment(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const {
    deploymentId,
    status,
    completedAt,
    durationSeconds,
    rollbackTo,
    metadata
  } = UpdateDeploymentSchema.parse(args);
  
  logger.info("Updating deployment", { deploymentId, status });
  
  // Build dynamic update query
  const updates = [];
  const values = [];
  let paramIndex = 1;
  
  if (status) {
    updates.push(`status = $${paramIndex++}`);
    values.push(status);
  }
  
  if (completedAt) {
    updates.push(`completed_at = $${paramIndex++}`);
    values.push(completedAt);
  }
  
  if (durationSeconds !== undefined) {
    updates.push(`duration_seconds = $${paramIndex++}`);
    values.push(durationSeconds);
  }
  
  if (rollbackTo) {
    updates.push(`rollback_to = $${paramIndex++}`);
    values.push(rollbackTo);
  }
  
  if (metadata) {
    updates.push(`metadata = $${paramIndex++}`);
    values.push(JSON.stringify(metadata));
  }
  
  updates.push(`updated_at = NOW()`);
  values.push(deploymentId);
  
  const query = `
    UPDATE deployments 
    SET ${updates.join(", ")}
    WHERE deployment_id = $${paramIndex}
    RETURNING *
  `;
  
  const result = await pgPool.query(query, values);
  
  if (result.rows.length === 0) {
    throw new McpError(ErrorCode.InvalidRequest, `Deployment ${deploymentId} not found`);
  }
  
  const deployment = result.rows[0];
  
  // Update cache
  if (redisClient) {
    await redisClient.setEx(
      `deployment:${deploymentId}`,
      3600,
      JSON.stringify(deployment)
    );
  }
  
  return {
    content: [{
      type: "text",
      text: `📝 **Deployment Updated**\n\n` +
            `• ID: ${deployment.deployment_id}\n` +
            `• Status: ${deployment.status}\n` +
            `• Environment: ${deployment.environment}\n` +
            `• Duration: ${deployment.duration_seconds ? `${deployment.duration_seconds}s` : "N/A"}\n` +
            `• Completed: ${deployment.completed_at ? new Date(deployment.completed_at).toLocaleString() : "N/A"}\n` +
            `• Updated: ${new Date(deployment.updated_at).toLocaleString()}`
    }]
  };
}

async function getDeployment(args) {
  const { deploymentId } = args;
  
  logger.info("Getting deployment", { deploymentId });
  
  // Try cache first
  if (redisClient) {
    try {
      const cached = await redisClient.get(`deployment:${deploymentId}`);
      if (cached) {
        const deployment = JSON.parse(cached);
        return formatDeploymentDetails(deployment, "(cached)");
      }
    } catch (error) {
      logger.warn("Cache read failed", { error: error.message });
    }
  }
  
  // Fallback to database
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const query = `
    SELECT * FROM deployments 
    WHERE deployment_id = $1
  `;
  
  const result = await pgPool.query(query, [deploymentId]);
  
  if (result.rows.length === 0) {
    throw new McpError(ErrorCode.InvalidRequest, `Deployment ${deploymentId} not found`);
  }
  
  const deployment = result.rows[0];
  
  // Cache for future requests
  if (redisClient) {
    await redisClient.setEx(
      `deployment:${deploymentId}`,
      3600,
      JSON.stringify(deployment)
    );
  }
  
  return formatDeploymentDetails(deployment);
}

async function listDeployments(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const { environment, status, serviceName, limit = 50, offset = 0 } = args || {};
  
  logger.info("Listing deployments", { environment, status, serviceName, limit, offset });
  
  // Build dynamic query
  const conditions = [];
  const values = [];
  let paramIndex = 1;
  
  if (environment) {
    conditions.push(`environment = $${paramIndex++}`);
    values.push(environment);
  }
  
  if (status) {
    conditions.push(`status = $${paramIndex++}`);
    values.push(status);
  }
  
  if (serviceName) {
    conditions.push(`service_name = $${paramIndex++}`);
    values.push(serviceName);
  }
  
  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  
  const query = `
    SELECT * FROM deployments
    ${whereClause}
    ORDER BY started_at DESC
    LIMIT $${paramIndex++} OFFSET $${paramIndex++}
  `;
  
  values.push(limit, offset);
  
  const result = await pgPool.query(query, values);
  const deployments = result.rows;
  
  return {
    content: [{
      type: "text",
      text: `📋 **Deployments** (${deployments.length} found)\n\n` +
            deployments.map((deployment, index) => 
              `${index + 1}. **${deployment.deployment_id}**\n` +
              `   • Environment: ${deployment.environment}\n` +
              `   • Service: ${deployment.service_name || "N/A"}\n` +
              `   • Status: ${getStatusEmoji(deployment.status)} ${deployment.status.toUpperCase()}\n` +
              `   • Version: ${deployment.version || "N/A"}\n` +
              `   • Started: ${new Date(deployment.started_at).toLocaleString()}\n` +
              `   • Duration: ${deployment.duration_seconds ? `${deployment.duration_seconds}s` : "N/A"}\n`
            ).join("\n")
    }]
  };
}

async function addDeploymentEvent(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const { deploymentId, eventType, message, details } = AddDeploymentEventSchema.parse(args);
  
  logger.info("Adding deployment event", { deploymentId, eventType });
  
  const query = `
    INSERT INTO deployment_events (deployment_id, event_type, message, details)
    VALUES ($1, $2, $3, $4)
    RETURNING *
  `;
  
  const values = [
    deploymentId,
    eventType,
    message || null,
    details ? JSON.stringify(details) : null
  ];
  
  const result = await pgPool.query(query, values);
  const event = result.rows[0];
  
  return {
    content: [{
      type: "text",
      text: `📝 **Event Added**\n\n` +
            `• Deployment: ${deploymentId}\n` +
            `• Type: ${eventType}\n` +
            `• Message: ${message || "N/A"}\n` +
            `• Timestamp: ${new Date(event.timestamp).toLocaleString()}`
    }]
  };
}

async function getDeploymentEvents(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const { deploymentId } = args;
  
  logger.info("Getting deployment events", { deploymentId });
  
  const query = `
    SELECT * FROM deployment_events
    WHERE deployment_id = $1
    ORDER BY timestamp ASC
  `;
  
  const result = await pgPool.query(query, [deploymentId]);
  const events = result.rows;
  
  return {
    content: [{
      type: "text",
      text: `📋 **Deployment Events** for ${deploymentId}\n\n` +
            (events.length > 0 
              ? events.map((event, index) => 
                  `${index + 1}. **${event.event_type}**\n` +
                  `   • Time: ${new Date(event.timestamp).toLocaleString()}\n` +
                  `   • Message: ${event.message || "N/A"}\n` +
                  (event.details ? `   • Details: ${JSON.stringify(event.details, null, 2)}\n` : "")
                ).join("\n")
              : "No events found"
            )
    }]
  };
}

async function addDeploymentMetric(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const { deploymentId, metricName, metricValue, metricUnit } = args;
  
  logger.info("Adding deployment metric", { deploymentId, metricName, metricValue });
  
  const query = `
    INSERT INTO deployment_metrics (deployment_id, metric_name, metric_value, metric_unit)
    VALUES ($1, $2, $3, $4)
    RETURNING *
  `;
  
  const result = await pgPool.query(query, [deploymentId, metricName, metricValue, metricUnit || null]);
  const metric = result.rows[0];
  
  return {
    content: [{
      type: "text",
      text: `📊 **Metric Added**\n\n` +
            `• Deployment: ${deploymentId}\n` +
            `• Metric: ${metricName}\n` +
            `• Value: ${metricValue}${metricUnit ? ` ${metricUnit}` : ""}\n` +
            `• Timestamp: ${new Date(metric.timestamp).toLocaleString()}`
    }]
  };
}

async function getDeploymentMetrics(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const { deploymentId, metricName } = args;
  
  logger.info("Getting deployment metrics", { deploymentId, metricName });
  
  let query = `
    SELECT * FROM deployment_metrics
    WHERE deployment_id = $1
  `;
  const values = [deploymentId];
  
  if (metricName) {
    query += ` AND metric_name = $2`;
    values.push(metricName);
  }
  
  query += ` ORDER BY timestamp ASC`;
  
  const result = await pgPool.query(query, values);
  const metrics = result.rows;
  
  return {
    content: [{
      type: "text",
      text: `📊 **Deployment Metrics** for ${deploymentId}\n\n` +
            (metrics.length > 0
              ? metrics.map((metric, index) =>
                  `${index + 1}. **${metric.metric_name}**\n` +
                  `   • Value: ${metric.metric_value}${metric.metric_unit ? ` ${metric.metric_unit}` : ""}\n` +
                  `   • Time: ${new Date(metric.timestamp).toLocaleString()}\n`
                ).join("\n")
              : "No metrics found"
            )
    }]
  };
}

async function getDeploymentStats(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const { environment, days = 30 } = args || {};
  
  logger.info("Getting deployment stats", { environment, days });
  
  const baseCondition = `WHERE started_at >= NOW() - INTERVAL '${days} days'`;
  const envCondition = environment ? ` AND environment = '${environment}'` : '';
  
  const queries = [
    // Total deployments
    `SELECT COUNT(*) as total_deployments FROM deployments ${baseCondition}${envCondition}`,
    
    // Success rate
    `SELECT 
       status,
       COUNT(*) as count
     FROM deployments ${baseCondition}${envCondition}
     GROUP BY status`,
    
    // Average duration
    `SELECT AVG(duration_seconds) as avg_duration 
     FROM deployments 
     ${baseCondition}${envCondition} AND duration_seconds IS NOT NULL`,
    
    // Deployments per day
    `SELECT 
       DATE(started_at) as deploy_date,
       COUNT(*) as count
     FROM deployments ${baseCondition}${envCondition}
     GROUP BY DATE(started_at)
     ORDER BY deploy_date DESC
     LIMIT 7`
  ];
  
  const [totalResult, statusResult, durationResult, dailyResult] = await Promise.all(
    queries.map(query => pgPool.query(query))
  );
  
  const total = parseInt(totalResult.rows[0].total_deployments);
  const statuses = statusResult.rows.reduce((acc, row) => {
    acc[row.status] = parseInt(row.count);
    return acc;
  }, {});
  
  const avgDuration = durationResult.rows[0].avg_duration ? 
    Math.round(parseFloat(durationResult.rows[0].avg_duration)) : 0;
  
  const successRate = total > 0 ? ((statuses.success || 0) / total * 100).toFixed(1) : 0;
  
  return {
    content: [{
      type: "text",
      text: `📊 **Deployment Statistics**${environment ? ` - ${environment.toUpperCase()}` : ""}\n` +
            `📅 Period: Last ${days} days\n\n` +
            
            `**📈 Overview**\n` +
            `• Total Deployments: ${total}\n` +
            `• Success Rate: ${successRate}%\n` +
            `• Average Duration: ${avgDuration}s\n\n` +
            
            `**📊 Status Breakdown**\n` +
            Object.entries(statuses).map(([status, count]) =>
              `• ${getStatusEmoji(status)} ${status.toUpperCase()}: ${count} (${(count/total*100).toFixed(1)}%)`
            ).join("\n") + "\n\n" +
            
            `**📅 Recent Activity**\n` +
            dailyResult.rows.map(row =>
              `• ${row.deploy_date}: ${row.count} deployments`
            ).join("\n")
    }]
  };
}

async function cacheSet(args) {
  if (!redisClient) throw new McpError(ErrorCode.InternalError, "Redis not available");
  
  const { key, value, ttl } = args;
  
  logger.info("Setting cache value", { key, ttl });
  
  const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
  
  if (ttl) {
    await redisClient.setEx(key, ttl, stringValue);
  } else {
    await redisClient.set(key, stringValue);
  }
  
  return {
    content: [{
      type: "text",
      text: `✅ **Cache Set**\n\n` +
            `• Key: ${key}\n` +
            `• Value Length: ${stringValue.length} chars\n` +
            `• TTL: ${ttl ? `${ttl}s` : "No expiration"}`
    }]
  };
}

async function cacheGet(args) {
  if (!redisClient) throw new McpError(ErrorCode.InternalError, "Redis not available");
  
  const { key } = args;
  
  logger.info("Getting cache value", { key });
  
  const value = await redisClient.get(key);
  
  if (value === null) {
    return {
      content: [{
        type: "text",
        text: `❌ **Cache Miss**\n\nKey '${key}' not found in cache`
      }]
    };
  }
  
  return {
    content: [{
      type: "text",
      text: `✅ **Cache Hit**\n\n` +
            `• Key: ${key}\n` +
            `• Value: ${value.length > 1000 ? value.substring(0, 1000) + '...' : value}`
    }]
  };
}

async function cacheDelete(args) {
  if (!redisClient) throw new McpError(ErrorCode.InternalError, "Redis not available");
  
  const { key } = args;
  
  logger.info("Deleting cache key", { key });
  
  const result = await redisClient.del(key);
  
  return {
    content: [{
      type: "text",
      text: `${result > 0 ? "✅" : "❌"} **Cache Delete**\n\n` +
            `• Key: ${key}\n` +
            `• Result: ${result > 0 ? "Deleted" : "Key not found"}`
    }]
  };
}

async function executeQuery(args) {
  if (!pgPool) throw new McpError(ErrorCode.InternalError, "PostgreSQL not available");
  
  const { sql, params = [] } = QuerySchema.parse(args);
  
  logger.info("Executing custom query", { sql: sql.substring(0, 100) + "..." });
  
  // Safety check - only allow SELECT, INSERT, UPDATE statements
  const trimmedSql = sql.trim().toLowerCase();
  if (!trimmedSql.startsWith('select') && 
      !trimmedSql.startsWith('insert') && 
      !trimmedSql.startsWith('update')) {
    throw new McpError(ErrorCode.InvalidRequest, "Only SELECT, INSERT, UPDATE queries are allowed");
  }
  
  const result = await pgPool.query(sql, params);
  
  return {
    content: [{
      type: "text",
      text: `📝 **Query Executed**\n\n` +
            `• Rows affected: ${result.rowCount}\n` +
            `• Execution time: ${new Date().toLocaleString()}\n\n` +
            (result.rows.length > 0
              ? `**Results (first 10 rows):**\n` +
                result.rows.slice(0, 10).map((row, index) =>
                  `${index + 1}. ${JSON.stringify(row, null, 2)}`
                ).join("\n")
              : "No rows returned"
            )
    }]
  };
}

// Helper functions
function formatDeploymentDetails(deployment, source = "") {
  return {
    content: [{
      type: "text",
      text: `🚀 **Deployment Details** ${source}\n\n` +
            `• **ID:** ${deployment.deployment_id}\n` +
            `• **Environment:** ${deployment.environment}\n` +
            `• **Service:** ${deployment.service_name || "N/A"}\n` +
            `• **Version:** ${deployment.version || "N/A"}\n` +
            `• **Status:** ${getStatusEmoji(deployment.status)} ${deployment.status.toUpperCase()}\n` +
            `• **Git Branch:** ${deployment.git_branch || "N/A"}\n` +
            `• **Git Commit:** ${deployment.git_commit?.substring(0, 7) || "N/A"}\n` +
            `• **Deployed by:** ${deployment.deployed_by || "N/A"}\n` +
            `• **Started:** ${new Date(deployment.started_at).toLocaleString()}\n` +
            `• **Completed:** ${deployment.completed_at ? new Date(deployment.completed_at).toLocaleString() : "In progress"}\n` +
            `• **Duration:** ${deployment.duration_seconds ? `${deployment.duration_seconds}s` : "N/A"}\n` +
            `• **Rollback to:** ${deployment.rollback_to || "N/A"}\n\n` +
            (deployment.configuration ? 
              `**Configuration:**\n\`\`\`json\n${JSON.stringify(deployment.configuration, null, 2)}\n\`\`\`\n\n` : ""
            ) +
            (deployment.metadata ? 
              `**Metadata:**\n\`\`\`json\n${JSON.stringify(deployment.metadata, null, 2)}\n\`\`\`` : ""
            )
    }]
  };
}

function getStatusEmoji(status) {
  const emojis = {
    pending: "⏳",
    in_progress: "🔄",
    success: "✅", 
    failure: "❌",
    cancelled: "⏹️",
    rolled_back: "↩️"
  };
  return emojis[status] || "❓";
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

// Graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Shutting down gracefully...');
  
  if (pgPool) {
    await pgPool.end();
    logger.info('PostgreSQL connection closed');
  }
  
  if (redisClient) {
    await redisClient.quit();
    logger.info('Redis connection closed');
  }
  
  process.exit(0);
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
  
  // Initialize database connections
  await initializeConnections();
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Catalytic Database MCP Server started", { 
    postgresql: !!pgPool,
    redis: !!redisClient
  });
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});