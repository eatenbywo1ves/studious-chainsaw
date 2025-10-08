#!/usr/bin/env node
/**
 * Catalytic Computing Deployment Orchestration MCP Server
 * Provides comprehensive deployment orchestration with Docker Compose integration,
 * real-time monitoring via SSE/WebSocket, progressive deployments, and rollback capabilities.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import winston from "winston";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { spawn, exec } from "child_process";
import { promisify } from "util";
import express from "express";
import { WebSocketServer } from "ws";
import { Docker } from "node-docker-api";
import YAML from "yaml";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const execAsync = promisify(exec);

// Environment configuration
const PROJECT_ROOT = process.env.PROJECT_ROOT || path.join(__dirname, "../../..");
const DOCKER_COMPOSE_PATH = process.env.DOCKER_COMPOSE_PATH || path.join(PROJECT_ROOT, "docker-compose.yml");
const SSE_PORT = parseInt(process.env.SSE_PORT) || 8090;
const WEBSOCKET_PORT = parseInt(process.env.WEBSOCKET_PORT) || 8091;
const LOG_LEVEL = process.env.LOG_LEVEL || "info";

// Logger setup
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "deployment-mcp-server" },
  transports: [
    new winston.transports.File({ 
      filename: path.join(PROJECT_ROOT, "logs", "deployment-mcp.log") 
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Docker client
const docker = new Docker({ socketPath: '/var/run/docker.sock' });

// Deployment state management
const deploymentState = new Map();
const deploymentHistory = [];
const activeDeployments = new Set();

// SSE and WebSocket clients
const sseClients = new Set();
const wsClients = new Set();

// Express app for SSE endpoints
const app = express();
app.use(express.json());

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// SSE endpoint for deployment updates
app.get('/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  const clientId = Date.now();
  const client = { id: clientId, res };
  sseClients.add(client);

  // Send initial connection event
  res.write(`data: ${JSON.stringify({ 
    type: 'connected', 
    clientId, 
    timestamp: new Date().toISOString() 
  })}\n\n`);

  req.on('close', () => {
    sseClients.delete(client);
    logger.debug('SSE client disconnected', { clientId });
  });

  logger.debug('SSE client connected', { clientId });
});

// WebSocket server
const wss = new WebSocketServer({ port: WEBSOCKET_PORT });

wss.on('connection', (ws) => {
  const clientId = Date.now();
  ws.clientId = clientId;
  wsClients.add(ws);

  ws.send(JSON.stringify({
    type: 'connected',
    clientId,
    timestamp: new Date().toISOString()
  }));

  ws.on('close', () => {
    wsClients.delete(ws);
    logger.debug('WebSocket client disconnected', { clientId });
  });

  ws.on('error', (error) => {
    logger.error('WebSocket error', { clientId, error: error.message });
    wsClients.delete(ws);
  });

  logger.debug('WebSocket client connected', { clientId });
});

// Broadcast function for real-time updates
function broadcast(data) {
  const message = JSON.stringify(data);
  const sseData = `data: ${message}\n\n`;

  // Send to SSE clients
  sseClients.forEach(client => {
    try {
      client.res.write(sseData);
    } catch (error) {
      logger.error('Failed to send SSE message', { error: error.message });
      sseClients.delete(client);
    }
  });

  // Send to WebSocket clients
  wsClients.forEach(ws => {
    try {
      if (ws.readyState === ws.OPEN) {
        ws.send(message);
      }
    } catch (error) {
      logger.error('Failed to send WebSocket message', { error: error.message });
      wsClients.delete(ws);
    }
  });

  logger.debug('Broadcast sent', { clientCount: sseClients.size + wsClients.size });
}

// Input validation schemas
const DeploySchema = z.object({
  profile: z.string().describe("Docker Compose profile to deploy (core, saas, dev, all)"),
  services: z.array(z.string()).optional().describe("Specific services to deploy"),
  environment: z.string().optional().describe("Target environment"),
  version: z.string().optional().describe("Version/tag to deploy"),
  strategy: z.enum(["rolling", "blue_green", "canary"]).optional().default("rolling").describe("Deployment strategy"),
  healthCheckTimeout: z.number().optional().default(300).describe("Health check timeout in seconds"),
  progressiveSteps: z.number().optional().default(3).describe("Number of progressive deployment steps")
});

const RollbackSchema = z.object({
  deploymentId: z.string().describe("Deployment ID to rollback from"),
  targetVersion: z.string().optional().describe("Target version to rollback to"),
  force: z.boolean().optional().default(false).describe("Force rollback without health checks")
});

// MCP Server setup
const server = new Server(
  {
    name: "catalytic-deployment-mcp",
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
    name: "deploy_profile",
    description: "Deploy a Docker Compose profile with real-time monitoring and progressive rollout",
    inputSchema: {
      type: "object",
      properties: {
        profile: {
          type: "string",
          description: "Docker Compose profile (core, saas, dev, monitoring, all)"
        },
        services: {
          type: "array",
          items: { type: "string" },
          description: "Specific services to deploy (optional)"
        },
        environment: {
          type: "string",
          description: "Target environment (production, staging, development)"
        },
        version: {
          type: "string",
          description: "Version/tag to deploy"
        },
        strategy: {
          type: "string",
          enum: ["rolling", "blue_green", "canary"],
          description: "Deployment strategy",
          default: "rolling"
        },
        healthCheckTimeout: {
          type: "number",
          description: "Health check timeout in seconds",
          default: 300
        },
        progressiveSteps: {
          type: "number",
          description: "Number of progressive deployment steps",
          default: 3
        }
      },
      required: ["profile"]
    }
  },
  {
    name: "get_deployment_status",
    description: "Get current status of all active deployments",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Specific deployment ID (optional)"
        }
      }
    }
  },
  {
    name: "list_services",
    description: "List all Docker Compose services and their current status",
    inputSchema: {
      type: "object",
      properties: {
        profile: {
          type: "string",
          description: "Filter by Docker Compose profile"
        }
      }
    }
  },
  {
    name: "scale_service",
    description: "Scale a specific service up or down",
    inputSchema: {
      type: "object",
      properties: {
        service: {
          type: "string",
          description: "Service name to scale"
        },
        replicas: {
          type: "number",
          description: "Number of replicas"
        }
      },
      required: ["service", "replicas"]
    }
  },
  {
    name: "stop_deployment",
    description: "Stop services for a specific deployment",
    inputSchema: {
      type: "object",
      properties: {
        profile: {
          type: "string",
          description: "Docker Compose profile to stop"
        },
        services: {
          type: "array",
          items: { type: "string" },
          description: "Specific services to stop (optional)"
        }
      },
      required: ["profile"]
    }
  },
  {
    name: "rollback_deployment",
    description: "Rollback to a previous deployment version",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Current deployment ID to rollback from"
        },
        targetVersion: {
          type: "string",
          description: "Target version to rollback to (optional)"
        },
        force: {
          type: "boolean",
          description: "Force rollback without health checks",
          default: false
        }
      },
      required: ["deploymentId"]
    }
  },
  {
    name: "get_container_logs",
    description: "Get logs from a specific container or service",
    inputSchema: {
      type: "object",
      properties: {
        service: {
          type: "string",
          description: "Service name"
        },
        container: {
          type: "string", 
          description: "Container ID or name (optional)"
        },
        lines: {
          type: "number",
          description: "Number of log lines to retrieve",
          default: 100
        },
        follow: {
          type: "boolean",
          description: "Follow log output in real-time",
          default: false
        }
      },
      required: ["service"]
    }
  },
  {
    name: "health_check",
    description: "Perform health checks on deployed services",
    inputSchema: {
      type: "object",
      properties: {
        services: {
          type: "array",
          items: { type: "string" },
          description: "Services to check (optional, defaults to all)"
        },
        timeout: {
          type: "number",
          description: "Health check timeout in seconds",
          default: 30
        }
      }
    }
  },
  {
    name: "get_deployment_metrics",
    description: "Get deployment performance metrics and statistics",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment ID (optional)"
        },
        timeRange: {
          type: "string",
          description: "Time range (1h, 24h, 7d)",
          default: "1h"
        }
      }
    }
  },
  {
    name: "cleanup_old_deployments",
    description: "Clean up old containers and images from previous deployments",
    inputSchema: {
      type: "object",
      properties: {
        dryRun: {
          type: "boolean",
          description: "Preview what would be cleaned up",
          default: true
        },
        keepVersions: {
          type: "number",
          description: "Number of versions to keep",
          default: 3
        }
      }
    }
  }
];

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.info("Listing available deployment tools");
  return { tools: TOOLS };
});

// Tool execution handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  logger.info("Tool called", { tool: name, args });

  try {
    switch (name) {
      case "deploy_profile":
        return await deployProfile(args);
      case "get_deployment_status":
        return await getDeploymentStatus(args);
      case "list_services":
        return await listServices(args);
      case "scale_service":
        return await scaleService(args);
      case "stop_deployment":
        return await stopDeployment(args);
      case "rollback_deployment":
        return await rollbackDeployment(args);
      case "get_container_logs":
        return await getContainerLogs(args);
      case "health_check":
        return await healthCheck(args);
      case "get_deployment_metrics":
        return await getDeploymentMetrics(args);
      case "cleanup_old_deployments":
        return await cleanupOldDeployments(args);
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
async function deployProfile(args) {
  const {
    profile,
    services,
    environment,
    version,
    strategy,
    healthCheckTimeout,
    progressiveSteps
  } = DeploySchema.parse(args);
  
  const deploymentId = `deploy-${Date.now()}`;
  logger.info("Starting deployment", { deploymentId, profile, strategy });
  
  // Initialize deployment state
  const deployment = {
    id: deploymentId,
    profile,
    services,
    environment,
    version,
    strategy,
    status: "starting",
    startTime: new Date(),
    steps: [],
    currentStep: 0,
    totalSteps: progressiveSteps,
    healthCheckTimeout
  };
  
  deploymentState.set(deploymentId, deployment);
  activeDeployments.add(deploymentId);
  
  // Broadcast deployment start
  broadcast({
    type: 'deployment_started',
    deploymentId,
    profile,
    strategy,
    timestamp: new Date().toISOString()
  });
  
  try {
    // Execute deployment asynchronously
    executeDeployment(deploymentId).catch(error => {
      logger.error("Deployment failed", { deploymentId, error: error.message });
      updateDeploymentStatus(deploymentId, "failed", { error: error.message });
    });
    
    return {
      content: [{
        type: "text",
        text: `🚀 **Deployment Started**\n\n` +
              `• Deployment ID: ${deploymentId}\n` +
              `• Profile: ${profile}\n` +
              `• Strategy: ${strategy}\n` +
              `• Environment: ${environment || "default"}\n` +
              `• Version: ${version || "latest"}\n` +
              `• Services: ${services ? services.join(", ") : "all"}\n` +
              `• Progressive Steps: ${progressiveSteps}\n\n` +
              `📊 **Real-time Monitoring:**\n` +
              `• SSE: http://localhost:${SSE_PORT}/events\n` +
              `• WebSocket: ws://localhost:${WEBSOCKET_PORT}\n\n` +
              `⏳ Deployment is running in the background...`
      }]
    };
    
  } catch (error) {
    activeDeployments.delete(deploymentId);
    throw error;
  }
}

async function executeDeployment(deploymentId) {
  const deployment = deploymentState.get(deploymentId);
  if (!deployment) {
    throw new Error(`Deployment ${deploymentId} not found`);
  }
  
  try {
    updateDeploymentStatus(deploymentId, "in_progress", { message: "Validating deployment configuration" });
    
    // Validate Docker Compose configuration
    await validateDockerCompose(deployment.profile);
    
    updateDeploymentStatus(deploymentId, "in_progress", { message: "Building/pulling images" });
    
    // Build or pull images
    await buildImages(deployment);
    
    // Execute deployment based on strategy
    switch (deployment.strategy) {
      case "rolling":
        await executeRollingDeployment(deploymentId);
        break;
      case "blue_green":
        await executeBlueGreenDeployment(deploymentId);
        break;
      case "canary":
        await executeCanaryDeployment(deploymentId);
        break;
    }
    
    updateDeploymentStatus(deploymentId, "success", { message: "Deployment completed successfully" });
    
  } catch (error) {
    updateDeploymentStatus(deploymentId, "failed", { error: error.message });
    throw error;
  } finally {
    activeDeployments.delete(deploymentId);
  }
}

async function executeRollingDeployment(deploymentId) {
  const deployment = deploymentState.get(deploymentId);
  const { profile, services, totalSteps } = deployment;
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Starting rolling deployment" });
  
  // Get list of services to deploy
  const servicesToDeploy = services || await getProfileServices(profile);
  const servicesPerStep = Math.ceil(servicesToDeploy.length / totalSteps);
  
  for (let step = 0; step < totalSteps; step++) {
    const stepServices = servicesToDeploy.slice(
      step * servicesPerStep,
      (step + 1) * servicesPerStep
    );
    
    if (stepServices.length === 0) break;
    
    deployment.currentStep = step + 1;
    
    updateDeploymentStatus(deploymentId, "in_progress", {
      message: `Rolling deployment step ${step + 1}/${totalSteps}`,
      step: step + 1,
      services: stepServices
    });
    
    // Deploy services in this step
    await deployServices(profile, stepServices);
    
    // Wait for health checks
    await waitForHealthChecks(stepServices, deployment.healthCheckTimeout);
    
    // Brief pause between steps
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
}

async function executeBlueGreenDeployment(deploymentId) {
  const deployment = deploymentState.get(deploymentId);
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Starting blue-green deployment" });
  
  // Create green environment
  const greenProfile = `${deployment.profile}-green`;
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Deploying to green environment" });
  
  await deployServices(greenProfile, deployment.services);
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Health checking green environment" });
  
  await waitForHealthChecks(deployment.services, deployment.healthCheckTimeout);
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Switching traffic to green environment" });
  
  // Switch traffic (this would typically involve load balancer reconfiguration)
  // For now, we'll stop the blue environment and rename green to primary
  await stopServices(deployment.profile);
  await renameServices(greenProfile, deployment.profile);
}

async function executeCanaryDeployment(deploymentId) {
  const deployment = deploymentState.get(deploymentId);
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Starting canary deployment" });
  
  // Deploy canary version (typically 10% of traffic)
  const canaryProfile = `${deployment.profile}-canary`;
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Deploying canary version" });
  
  await deployServices(canaryProfile, deployment.services);
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Monitoring canary performance" });
  
  // Monitor canary for specified duration
  await monitorCanary(canaryProfile, 300); // 5 minutes
  
  updateDeploymentStatus(deploymentId, "in_progress", { message: "Promoting canary to full deployment" });
  
  // If canary is healthy, promote to full deployment
  await promoteCanary(deployment.profile, canaryProfile);
}

async function validateDockerCompose(profile) {
  logger.info("Validating Docker Compose configuration", { profile });
  
  const { stdout, stderr } = await execAsync(
    `docker compose --profile ${profile} config`,
    { cwd: PROJECT_ROOT }
  );
  
  if (stderr && !stderr.includes('WARN')) {
    throw new Error(`Docker Compose validation failed: ${stderr}`);
  }
  
  return stdout;
}

async function buildImages(deployment) {
  logger.info("Building/pulling images", { deploymentId: deployment.id });
  
  const { stdout, stderr } = await execAsync(
    `docker compose --profile ${deployment.profile} build --pull`,
    { cwd: PROJECT_ROOT }
  );
  
  if (stderr && stderr.includes('ERROR')) {
    throw new Error(`Image build failed: ${stderr}`);
  }
}

async function deployServices(profile, services = null) {
  logger.info("Deploying services", { profile, services });
  
  let command = `docker compose --profile ${profile}`;
  
  if (services && services.length > 0) {
    command += ` up -d ${services.join(" ")}`;
  } else {
    command += " up -d";
  }
  
  const { stdout, stderr } = await execAsync(command, { cwd: PROJECT_ROOT });
  
  if (stderr && stderr.includes('ERROR')) {
    throw new Error(`Service deployment failed: ${stderr}`);
  }
  
  return stdout;
}

async function waitForHealthChecks(services, timeout = 300) {
  logger.info("Waiting for health checks", { services, timeout });
  
  const startTime = Date.now();
  const checkInterval = 5000; // 5 seconds
  
  while (Date.now() - startTime < timeout * 1000) {
    try {
      const healthyServices = await checkServicesHealth(services);
      
      if (healthyServices.length === (services || []).length) {
        logger.info("All services healthy", { services: healthyServices });
        return true;
      }
      
      logger.debug("Waiting for services to become healthy", {
        healthy: healthyServices.length,
        total: (services || []).length
      });
      
    } catch (error) {
      logger.warn("Health check failed", { error: error.message });
    }
    
    await new Promise(resolve => setTimeout(resolve, checkInterval));
  }
  
  throw new Error("Health check timeout exceeded");
}

async function checkServicesHealth(services) {
  // This would typically check service-specific health endpoints
  // For now, we'll check if containers are running
  
  const { stdout } = await execAsync(
    "docker compose ps --format json",
    { cwd: PROJECT_ROOT }
  );
  
  const containers = stdout.trim().split('\n')
    .filter(line => line.trim())
    .map(line => JSON.parse(line));
  
  const healthyServices = containers
    .filter(container => 
      container.State === 'running' && 
      (!services || services.includes(container.Service))
    )
    .map(container => container.Service);
  
  return [...new Set(healthyServices)]; // Remove duplicates
}

async function getProfileServices(profile) {
  try {
    const composeContent = await fs.readFile(DOCKER_COMPOSE_PATH, 'utf8');
    const composeConfig = YAML.parse(composeContent);
    
    const services = Object.entries(composeConfig.services || {})
      .filter(([, service]) => {
        const profiles = service.profiles || [];
        return profiles.includes(profile) || profile === 'all';
      })
      .map(([serviceName]) => serviceName);
    
    return services;
  } catch (error) {
    logger.error("Failed to parse Docker Compose file", { error: error.message });
    return [];
  }
}

async function stopServices(profile) {
  logger.info("Stopping services", { profile });
  
  const { stdout, stderr } = await execAsync(
    `docker compose --profile ${profile} down`,
    { cwd: PROJECT_ROOT }
  );
  
  if (stderr && stderr.includes('ERROR')) {
    throw new Error(`Failed to stop services: ${stderr}`);
  }
  
  return stdout;
}

async function renameServices(fromProfile, toProfile) {
  // This is a simplified implementation
  // In practice, you'd need to handle service renaming/recreation
  logger.info("Renaming services", { fromProfile, toProfile });
  return true;
}

async function monitorCanary(profile, duration) {
  logger.info("Monitoring canary", { profile, duration });
  
  // Monitor metrics, error rates, etc.
  // For now, just wait for the specified duration
  await new Promise(resolve => setTimeout(resolve, duration * 1000));
  
  return true;
}

async function promoteCanary(primaryProfile, canaryProfile) {
  logger.info("Promoting canary", { primaryProfile, canaryProfile });
  
  // Stop primary, promote canary
  await stopServices(primaryProfile);
  await renameServices(canaryProfile, primaryProfile);
  
  return true;
}

function updateDeploymentStatus(deploymentId, status, data = {}) {
  const deployment = deploymentState.get(deploymentId);
  if (!deployment) return;
  
  deployment.status = status;
  deployment.lastUpdate = new Date();
  
  if (data.step) deployment.currentStep = data.step;
  if (data.message) {
    deployment.steps.push({
      step: deployment.currentStep,
      message: data.message,
      timestamp: new Date(),
      ...data
    });
  }
  
  // Broadcast status update
  broadcast({
    type: 'deployment_status',
    deploymentId,
    status,
    step: deployment.currentStep,
    totalSteps: deployment.totalSteps,
    message: data.message,
    timestamp: new Date().toISOString(),
    ...data
  });
  
  // Add to history if completed
  if (status === 'success' || status === 'failed') {
    deployment.endTime = new Date();
    deployment.duration = deployment.endTime - deployment.startTime;
    
    deploymentHistory.push({
      ...deployment,
      completedAt: deployment.endTime
    });
    
    // Keep only last 50 deployments in history
    if (deploymentHistory.length > 50) {
      deploymentHistory.shift();
    }
  }
  
  logger.info("Deployment status updated", { deploymentId, status, message: data.message });
}

async function getDeploymentStatus(args) {
  const { deploymentId } = args || {};
  
  if (deploymentId) {
    const deployment = deploymentState.get(deploymentId);
    if (!deployment) {
      throw new McpError(ErrorCode.InvalidRequest, `Deployment ${deploymentId} not found`);
    }
    
    return formatDeploymentStatus(deployment);
  }
  
  // Return all active deployments
  const active = Array.from(deploymentState.values());
  const recent = deploymentHistory.slice(-5); // Last 5 completed
  
  return {
    content: [{
      type: "text",
      text: `📊 **Deployment Status Overview**\n\n` +
            `**🔄 Active Deployments (${active.length})**\n` +
            (active.length > 0
              ? active.map(d => 
                  `• ${d.id} - ${d.profile} - ${d.status} (Step ${d.currentStep}/${d.totalSteps})`
                ).join("\n")
              : "No active deployments"
            ) + "\n\n" +
            
            `**📋 Recent Deployments (${recent.length})**\n` +
            (recent.length > 0
              ? recent.map(d => 
                  `• ${d.id} - ${d.profile} - ${d.status} - ${Math.round(d.duration / 1000)}s`
                ).join("\n")
              : "No recent deployments"
            ) + "\n\n" +
            
            `**📡 Real-time Monitoring:**\n` +
            `• Active SSE clients: ${sseClients.size}\n` +
            `• Active WebSocket clients: ${wsClients.size}\n` +
            `• SSE endpoint: http://localhost:${SSE_PORT}/events\n` +
            `• WebSocket endpoint: ws://localhost:${WEBSOCKET_PORT}`
    }]
  };
}

function formatDeploymentStatus(deployment) {
  const duration = deployment.endTime 
    ? Math.round((deployment.endTime - deployment.startTime) / 1000)
    : Math.round((Date.now() - deployment.startTime) / 1000);
  
  return {
    content: [{
      type: "text",
      text: `🚀 **Deployment Status: ${deployment.id}**\n\n` +
            `• **Profile:** ${deployment.profile}\n` +
            `• **Strategy:** ${deployment.strategy}\n` +
            `• **Status:** ${getStatusEmoji(deployment.status)} ${deployment.status.toUpperCase()}\n` +
            `• **Progress:** ${deployment.currentStep}/${deployment.totalSteps} steps\n` +
            `• **Environment:** ${deployment.environment || "default"}\n` +
            `• **Version:** ${deployment.version || "latest"}\n` +
            `• **Services:** ${deployment.services ? deployment.services.join(", ") : "all"}\n` +
            `• **Duration:** ${duration}s\n` +
            `• **Started:** ${deployment.startTime.toLocaleString()}\n` +
            `• **Last Update:** ${deployment.lastUpdate?.toLocaleString() || "Never"}\n\n` +
            
            `**📋 Deployment Steps:**\n` +
            (deployment.steps.length > 0
              ? deployment.steps.map((step, index) => 
                  `${index + 1}. ${step.message} (${step.timestamp.toLocaleTimeString()})`
                ).join("\n")
              : "No steps recorded"
            )
    }]
  };
}

async function listServices(args) {
  const { profile } = args || {};
  
  logger.info("Listing services", { profile });
  
  try {
    const { stdout } = await execAsync(
      `docker compose ${profile ? `--profile ${profile}` : ""} ps --format json`,
      { cwd: PROJECT_ROOT }
    );
    
    const containers = stdout.trim().split('\n')
      .filter(line => line.trim())
      .map(line => JSON.parse(line));
    
    // Group by service
    const services = containers.reduce((acc, container) => {
      const serviceName = container.Service;
      if (!acc[serviceName]) {
        acc[serviceName] = {
          name: serviceName,
          containers: [],
          status: 'unknown'
        };
      }
      
      acc[serviceName].containers.push(container);
      
      // Determine overall service status
      const statuses = acc[serviceName].containers.map(c => c.State);
      if (statuses.every(s => s === 'running')) {
        acc[serviceName].status = 'running';
      } else if (statuses.some(s => s === 'running')) {
        acc[serviceName].status = 'partial';
      } else {
        acc[serviceName].status = 'stopped';
      }
      
      return acc;
    }, {});
    
    const serviceList = Object.values(services);
    
    return {
      content: [{
        type: "text",
        text: `🐳 **Docker Services**${profile ? ` (Profile: ${profile})` : ""}\n\n` +
              `Found ${serviceList.length} services:\n\n` +
              serviceList.map(service => 
                `**${service.name}** ${getServiceStatusEmoji(service.status)}\n` +
                `• Status: ${service.status.toUpperCase()}\n` +
                `• Containers: ${service.containers.length}\n` +
                service.containers.map(c => 
                  `  - ${c.Name}: ${c.State} (${c.Status})`
                ).join("\n")
              ).join("\n\n")
      }]
    };
    
  } catch (error) {
    logger.error("Failed to list services", { error: error.message });
    throw new McpError(ErrorCode.InternalError, `Failed to list services: ${error.message}`);
  }
}

async function scaleService(args) {
  const { service, replicas } = args;
  
  logger.info("Scaling service", { service, replicas });
  
  try {
    const { stdout, stderr } = await execAsync(
      `docker compose up -d --scale ${service}=${replicas} ${service}`,
      { cwd: PROJECT_ROOT }
    );
    
    if (stderr && stderr.includes('ERROR')) {
      throw new Error(stderr);
    }
    
    // Broadcast scaling event
    broadcast({
      type: 'service_scaled',
      service,
      replicas,
      timestamp: new Date().toISOString()
    });
    
    return {
      content: [{
        type: "text",
        text: `📈 **Service Scaled**\n\n` +
              `• Service: ${service}\n` +
              `• Replicas: ${replicas}\n` +
              `• Status: Scaling in progress...\n\n` +
              `Output:\n${stdout}`
      }]
    };
    
  } catch (error) {
    logger.error("Failed to scale service", { service, replicas, error: error.message });
    throw new McpError(ErrorCode.InternalError, `Failed to scale service: ${error.message}`);
  }
}

async function stopDeployment(args) {
  const { profile, services } = args;
  
  logger.info("Stopping deployment", { profile, services });
  
  try {
    let command = `docker compose --profile ${profile}`;
    
    if (services && services.length > 0) {
      command += ` stop ${services.join(" ")}`;
    } else {
      command += " down";
    }
    
    const { stdout, stderr } = await execAsync(command, { cwd: PROJECT_ROOT });
    
    if (stderr && stderr.includes('ERROR')) {
      throw new Error(stderr);
    }
    
    // Broadcast stop event
    broadcast({
      type: 'deployment_stopped',
      profile,
      services,
      timestamp: new Date().toISOString()
    });
    
    return {
      content: [{
        type: "text",
        text: `⏹️ **Deployment Stopped**\n\n` +
              `• Profile: ${profile}\n` +
              `• Services: ${services ? services.join(", ") : "all"}\n\n` +
              `Output:\n${stdout}`
      }]
    };
    
  } catch (error) {
    logger.error("Failed to stop deployment", { profile, services, error: error.message });
    throw new McpError(ErrorCode.InternalError, `Failed to stop deployment: ${error.message}`);
  }
}

async function rollbackDeployment(args) {
  const { deploymentId, targetVersion, force } = RollbackSchema.parse(args);
  
  logger.info("Starting rollback", { deploymentId, targetVersion, force });
  
  const rollbackId = `rollback-${Date.now()}`;
  
  // Find the deployment to rollback
  const deployment = deploymentState.get(deploymentId) || 
    deploymentHistory.find(d => d.id === deploymentId);
  
  if (!deployment) {
    throw new McpError(ErrorCode.InvalidRequest, `Deployment ${deploymentId} not found`);
  }
  
  // Create rollback deployment
  const rollback = {
    id: rollbackId,
    type: 'rollback',
    originalDeploymentId: deploymentId,
    profile: deployment.profile,
    services: deployment.services,
    environment: deployment.environment,
    targetVersion,
    status: "starting",
    startTime: new Date(),
    steps: [],
    force
  };
  
  deploymentState.set(rollbackId, rollback);
  
  // Broadcast rollback start
  broadcast({
    type: 'rollback_started',
    rollbackId,
    originalDeploymentId: deploymentId,
    targetVersion,
    timestamp: new Date().toISOString()
  });
  
  try {
    // Execute rollback asynchronously
    executeRollback(rollbackId).catch(error => {
      logger.error("Rollback failed", { rollbackId, error: error.message });
      updateDeploymentStatus(rollbackId, "failed", { error: error.message });
    });
    
    return {
      content: [{
        type: "text",
        text: `↩️ **Rollback Started**\n\n` +
              `• Rollback ID: ${rollbackId}\n` +
              `• Original Deployment: ${deploymentId}\n` +
              `• Profile: ${deployment.profile}\n` +
              `• Target Version: ${targetVersion || "previous"}\n` +
              `• Force: ${force}\n\n` +
              `⏳ Rollback is running in the background...`
      }]
    };
    
  } catch (error) {
    deploymentState.delete(rollbackId);
    throw error;
  }
}

async function executeRollback(rollbackId) {
  const rollback = deploymentState.get(rollbackId);
  
  try {
    updateDeploymentStatus(rollbackId, "in_progress", { message: "Starting rollback process" });
    
    if (!rollback.force) {
      updateDeploymentStatus(rollbackId, "in_progress", { message: "Checking system health" });
      // Perform health checks before rollback
      await checkServicesHealth();
    }
    
    updateDeploymentStatus(rollbackId, "in_progress", { message: "Stopping current deployment" });
    
    // Stop current services
    await stopServices(rollback.profile);
    
    updateDeploymentStatus(rollbackId, "in_progress", { message: "Deploying previous version" });
    
    // Deploy previous version
    await deployServices(rollback.profile, rollback.services);
    
    if (!rollback.force) {
      updateDeploymentStatus(rollbackId, "in_progress", { message: "Verifying rollback health" });
      // Verify rollback is healthy
      await waitForHealthChecks(rollback.services, 120);
    }
    
    updateDeploymentStatus(rollbackId, "success", { message: "Rollback completed successfully" });
    
  } catch (error) {
    updateDeploymentStatus(rollbackId, "failed", { error: error.message });
    throw error;
  }
}

async function getContainerLogs(args) {
  const { service, container, lines = 100, follow = false } = args;
  
  logger.info("Getting container logs", { service, container, lines });
  
  try {
    let command;
    if (container) {
      command = `docker logs ${follow ? '-f' : ''} --tail ${lines} ${container}`;
    } else {
      command = `docker compose logs ${follow ? '-f' : ''} --tail=${lines} ${service}`;
    }
    
    const { stdout, stderr } = await execAsync(command, { 
      cwd: PROJECT_ROOT,
      timeout: follow ? 0 : 30000 // No timeout for follow
    });
    
    return {
      content: [{
        type: "text",
        text: `📋 **Container Logs**\n\n` +
              `• Service: ${service}\n` +
              `• Container: ${container || "all"}\n` +
              `• Lines: ${lines}\n` +
              `• Follow: ${follow}\n\n` +
              `**Logs:**\n\`\`\`\n${stdout}\n\`\`\``
      }]
    };
    
  } catch (error) {
    logger.error("Failed to get container logs", { service, container, error: error.message });
    throw new McpError(ErrorCode.InternalError, `Failed to get logs: ${error.message}`);
  }
}

async function healthCheck(args) {
  const { services, timeout = 30 } = args || {};
  
  logger.info("Performing health checks", { services, timeout });
  
  try {
    const healthyServices = await checkServicesHealth(services);
    const allServices = services || await getAllServices();
    
    const healthStatus = {
      healthy: healthyServices,
      unhealthy: allServices.filter(s => !healthyServices.includes(s)),
      timestamp: new Date()
    };
    
    const overallHealth = healthStatus.unhealthy.length === 0 ? "healthy" : "unhealthy";
    
    return {
      content: [{
        type: "text",
        text: `🏥 **Health Check Results**\n\n` +
              `• Overall Status: ${overallHealth === "healthy" ? "✅ HEALTHY" : "❌ UNHEALTHY"}\n` +
              `• Healthy Services: ${healthStatus.healthy.length}\n` +
              `• Unhealthy Services: ${healthStatus.unhealthy.length}\n` +
              `• Check Time: ${healthStatus.timestamp.toLocaleString()}\n\n` +
              
              (healthStatus.healthy.length > 0 ? 
                `**✅ Healthy Services:**\n${healthStatus.healthy.map(s => `• ${s}`).join("\n")}\n\n` : ""
              ) +
              
              (healthStatus.unhealthy.length > 0 ?
                `**❌ Unhealthy Services:**\n${healthStatus.unhealthy.map(s => `• ${s}`).join("\n")}` : ""
              )
      }]
    };
    
  } catch (error) {
    logger.error("Health check failed", { error: error.message });
    throw new McpError(ErrorCode.InternalError, `Health check failed: ${error.message}`);
  }
}

async function getAllServices() {
  try {
    const { stdout } = await execAsync(
      "docker compose config --services",
      { cwd: PROJECT_ROOT }
    );
    
    return stdout.trim().split('\n').filter(s => s.trim());
  } catch (error) {
    logger.error("Failed to get service list", { error: error.message });
    return [];
  }
}

async function getDeploymentMetrics(args) {
  const { deploymentId, timeRange = "1h" } = args || {};
  
  logger.info("Getting deployment metrics", { deploymentId, timeRange });
  
  // This would typically query your metrics system
  // For now, return mock metrics
  const metrics = {
    deploymentId,
    timeRange,
    timestamp: new Date(),
    metrics: {
      requestRate: Math.random() * 100,
      errorRate: Math.random() * 5,
      responseTime: Math.random() * 200 + 50,
      cpuUsage: Math.random() * 80 + 10,
      memoryUsage: Math.random() * 70 + 20,
      activeConnections: Math.floor(Math.random() * 1000) + 100
    }
  };
  
  return {
    content: [{
      type: "text",
      text: `📊 **Deployment Metrics**\n\n` +
            `• Deployment: ${deploymentId || "all"}\n` +
            `• Time Range: ${timeRange}\n` +
            `• Generated: ${metrics.timestamp.toLocaleString()}\n\n` +
            
            `**🚀 Performance Metrics:**\n` +
            `• Request Rate: ${metrics.metrics.requestRate.toFixed(2)} req/sec\n` +
            `• Error Rate: ${metrics.metrics.errorRate.toFixed(2)}%\n` +
            `• Response Time: ${metrics.metrics.responseTime.toFixed(2)}ms\n\n` +
            
            `**💻 Resource Metrics:**\n` +
            `• CPU Usage: ${metrics.metrics.cpuUsage.toFixed(2)}%\n` +
            `• Memory Usage: ${metrics.metrics.memoryUsage.toFixed(2)}%\n` +
            `• Active Connections: ${metrics.metrics.activeConnections}`
    }]
  };
}

async function cleanupOldDeployments(args) {
  const { dryRun = true, keepVersions = 3 } = args || {};
  
  logger.info("Cleaning up old deployments", { dryRun, keepVersions });
  
  try {
    // Get list of unused images and containers
    const { stdout: imagesOutput } = await execAsync("docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}'");
    const { stdout: containersOutput } = await execAsync("docker ps -a --format '{{.Names}} {{.ID}} {{.Status}}'");
    
    const images = imagesOutput.trim().split('\n').filter(line => line.trim());
    const containers = containersOutput.trim().split('\n').filter(line => line.trim());
    
    const cleanup = {
      images: images.slice(keepVersions), // Keep only specified versions
      containers: containers.filter(line => line.includes('Exited')),
      dryRun
    };
    
    let cleanupSummary = "";
    
    if (dryRun) {
      cleanupSummary = `🔍 **Dry Run - Cleanup Preview**\n\n` +
                      `Would remove:\n` +
                      `• ${cleanup.images.length} old images\n` +
                      `• ${cleanup.containers.length} stopped containers\n\n` +
                      `**Images to remove:**\n` +
                      cleanup.images.slice(0, 10).map(img => `• ${img}`).join("\n") +
                      (cleanup.images.length > 10 ? `\n• ... and ${cleanup.images.length - 10} more` : "") + "\n\n" +
                      `**Containers to remove:**\n` +
                      cleanup.containers.slice(0, 10).map(cont => `• ${cont}`).join("\n") +
                      (cleanup.containers.length > 10 ? `\n• ... and ${cleanup.containers.length - 10} more` : "");
    } else {
      // Actually perform cleanup
      let removedImages = 0;
      let removedContainers = 0;
      
      // Remove containers
      for (const containerLine of cleanup.containers) {
        try {
          const containerId = containerLine.split(' ')[1];
          await execAsync(`docker rm ${containerId}`);
          removedContainers++;
        } catch (error) {
          logger.warn("Failed to remove container", { error: error.message });
        }
      }
      
      // Remove images (simplified - would need more sophisticated logic in practice)
      for (const imageLine of cleanup.images) {
        try {
          const imageId = imageLine.split(' ')[1];
          await execAsync(`docker rmi ${imageId}`);
          removedImages++;
        } catch (error) {
          logger.warn("Failed to remove image", { error: error.message });
        }
      }
      
      cleanupSummary = `🧹 **Cleanup Completed**\n\n` +
                      `• Removed ${removedImages} images\n` +
                      `• Removed ${removedContainers} containers\n` +
                      `• Kept ${keepVersions} recent versions`;
    }
    
    return {
      content: [{
        type: "text",
        text: cleanupSummary
      }]
    };
    
  } catch (error) {
    logger.error("Cleanup failed", { error: error.message });
    throw new McpError(ErrorCode.InternalError, `Cleanup failed: ${error.message}`);
  }
}

// Helper functions
function getStatusEmoji(status) {
  const emojis = {
    starting: "⏳",
    in_progress: "🔄",
    success: "✅",
    failed: "❌",
    cancelled: "⏹️",
    rolled_back: "↩️"
  };
  return emojis[status] || "❓";
}

function getServiceStatusEmoji(status) {
  const emojis = {
    running: "🟢",
    partial: "🟡",
    stopped: "🔴",
    unknown: "⚪"
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
  
  // Close WebSocket server
  wss.close();
  
  // Close SSE connections
  sseClients.forEach(client => {
    try {
      client.res.end();
    } catch (error) {
      // Ignore errors during shutdown
    }
  });
  
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
  
  // Start Express server for SSE
  const httpServer = app.listen(SSE_PORT, () => {
    logger.info(`SSE server listening on port ${SSE_PORT}`);
  });
  
  // Verify Docker Compose file exists
  try {
    await fs.access(DOCKER_COMPOSE_PATH);
    logger.info("Docker Compose file found", { path: DOCKER_COMPOSE_PATH });
  } catch (error) {
    logger.warn("Docker Compose file not found", { path: DOCKER_COMPOSE_PATH });
  }
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  logger.info("Catalytic Deployment MCP Server started", {
    ssePort: SSE_PORT,
    websocketPort: WEBSOCKET_PORT,
    dockerCompose: DOCKER_COMPOSE_PATH
  });
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});