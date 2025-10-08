#!/usr/bin/env node
/**
 * Catalytic Computing Slack MCP Server
 * Provides Slack integration for deployment notifications, alerts,
 * and team communication within the Catalytic Computing platform.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { WebClient } from "@slack/web-api";
import { z } from "zod";
import winston from "winston";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Environment configuration
const PROJECT_ROOT = process.env.PROJECT_ROOT || path.join(__dirname, "../../..");
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SLACK_CHANNEL = process.env.SLACK_CHANNEL || "#deployments";
const LOG_LEVEL = process.env.LOG_LEVEL || "info";

// Logger setup
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "slack-mcp-server" },
  transports: [
    new winston.transports.File({ 
      filename: path.join(PROJECT_ROOT, "logs", "slack-mcp.log") 
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Slack client setup
const slack = new WebClient(SLACK_BOT_TOKEN);

// Input validation schemas
const SendMessageSchema = z.object({
  channel: z.string().optional().describe("Slack channel (defaults to configured channel)"),
  text: z.string().describe("Message text"),
  blocks: z.array(z.any()).optional().describe("Slack Block Kit blocks for rich formatting"),
  thread_ts: z.string().optional().describe("Thread timestamp for replies")
});

const SendDeploymentNotificationSchema = z.object({
  environment: z.string().describe("Deployment environment (production, staging, development)"),
  status: z.enum(["started", "success", "failure", "cancelled", "in_progress"]).describe("Deployment status"),
  version: z.string().optional().describe("Version/tag being deployed"),
  commit: z.string().optional().describe("Git commit hash"),
  branch: z.string().optional().describe("Git branch"),
  duration: z.number().optional().describe("Deployment duration in seconds"),
  url: z.string().optional().describe("Deployment URL"),
  changes: z.array(z.string()).optional().describe("List of changes/features"),
  channel: z.string().optional().describe("Override default channel")
});

const SendAlertSchema = z.object({
  severity: z.enum(["info", "warning", "error", "critical"]).describe("Alert severity level"),
  title: z.string().describe("Alert title"),
  message: z.string().describe("Alert message"),
  service: z.string().optional().describe("Service name"),
  environment: z.string().optional().describe("Environment"),
  channel: z.string().optional().describe("Override default channel"),
  mention_users: z.array(z.string()).optional().describe("Users to mention (@username)")
});

// MCP Server setup
const server = new Server(
  {
    name: "catalytic-slack-mcp",
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
    name: "send_message",
    description: "Send a message to a Slack channel",
    inputSchema: {
      type: "object",
      properties: {
        channel: {
          type: "string",
          description: "Slack channel (e.g., '#deployments', '@username')"
        },
        text: {
          type: "string",
          description: "Message text content"
        },
        blocks: {
          type: "array",
          description: "Slack Block Kit blocks for rich formatting",
          items: {
            type: "object"
          }
        },
        thread_ts: {
          type: "string",
          description: "Thread timestamp for replies"
        }
      },
      required: ["text"]
    }
  },
  {
    name: "send_deployment_notification",
    description: "Send a formatted deployment notification with status, environment details, and rich formatting",
    inputSchema: {
      type: "object",
      properties: {
        environment: {
          type: "string",
          description: "Deployment environment (production, staging, development)"
        },
        status: {
          type: "string",
          enum: ["started", "success", "failure", "cancelled", "in_progress"],
          description: "Deployment status"
        },
        version: {
          type: "string",
          description: "Version/tag being deployed"
        },
        commit: {
          type: "string",
          description: "Git commit hash (short form)"
        },
        branch: {
          type: "string",
          description: "Git branch name"
        },
        duration: {
          type: "number",
          description: "Deployment duration in seconds"
        },
        url: {
          type: "string",
          description: "Live deployment URL"
        },
        changes: {
          type: "array",
          items: {
            type: "string"
          },
          description: "List of changes/features in this deployment"
        },
        channel: {
          type: "string",
          description: "Override default channel"
        }
      },
      required: ["environment", "status"]
    }
  },
  {
    name: "send_alert",
    description: "Send a formatted alert/incident notification with severity indicators",
    inputSchema: {
      type: "object",
      properties: {
        severity: {
          type: "string",
          enum: ["info", "warning", "error", "critical"],
          description: "Alert severity level"
        },
        title: {
          type: "string",
          description: "Alert title/summary"
        },
        message: {
          type: "string",
          description: "Detailed alert message"
        },
        service: {
          type: "string",
          description: "Affected service name"
        },
        environment: {
          type: "string",
          description: "Environment (production, staging, development)"
        },
        channel: {
          type: "string",
          description: "Override default channel"
        },
        mention_users: {
          type: "array",
          items: {
            type: "string"
          },
          description: "Users to mention for urgent alerts"
        }
      },
      required: ["severity", "title", "message"]
    }
  },
  {
    name: "send_metrics_report",
    description: "Send a formatted metrics/performance report",
    inputSchema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description: "Report title"
        },
        metrics: {
          type: "object",
          description: "Key-value pairs of metrics",
          additionalProperties: {
            type: ["string", "number"]
          }
        },
        environment: {
          type: "string",
          description: "Environment"
        },
        timeframe: {
          type: "string",
          description: "Time period for the report"
        },
        channel: {
          type: "string",
          description: "Override default channel"
        }
      },
      required: ["title", "metrics"]
    }
  },
  {
    name: "get_channel_info",
    description: "Get information about a Slack channel",
    inputSchema: {
      type: "object",
      properties: {
        channel: {
          type: "string",
          description: "Channel name or ID"
        }
      },
      required: ["channel"]
    }
  },
  {
    name: "list_channels",
    description: "List available Slack channels",
    inputSchema: {
      type: "object",
      properties: {
        types: {
          type: "string",
          description: "Channel types to include (public_channel,private_channel,im,mpim)"
        }
      }
    }
  },
  {
    name: "get_user_info",
    description: "Get information about a Slack user",
    inputSchema: {
      type: "object",
      properties: {
        user: {
          type: "string",
          description: "User ID or username"
        }
      },
      required: ["user"]
    }
  }
];

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.info("Listing available Slack tools");
  return { tools: TOOLS };
});

// Tool execution handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  logger.info("Tool called", { tool: name, args });

  try {
    switch (name) {
      case "send_message":
        return await sendMessage(args);
      case "send_deployment_notification":
        return await sendDeploymentNotification(args);
      case "send_alert":
        return await sendAlert(args);
      case "send_metrics_report":
        return await sendMetricsReport(args);
      case "get_channel_info":
        return await getChannelInfo(args);
      case "list_channels":
        return await listChannels(args);
      case "get_user_info":
        return await getUserInfo(args);
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
async function sendMessage(args) {
  const { channel = SLACK_CHANNEL, text, blocks, thread_ts } = SendMessageSchema.parse(args);
  
  logger.info("Sending Slack message", { channel, hasBlocks: !!blocks });
  
  const messageParams = {
    channel,
    text,
    ...(blocks && { blocks }),
    ...(thread_ts && { thread_ts })
  };
  
  const result = await slack.chat.postMessage(messageParams);
  
  return {
    content: [{
      type: "text",
      text: `Message sent successfully to ${channel}\n` +
            `• Timestamp: ${result.ts}\n` +
            `• Channel: ${result.channel}\n` +
            `• Message: ${text.substring(0, 100)}${text.length > 100 ? "..." : ""}`
    }]
  };
}

async function sendDeploymentNotification(args) {
  const {
    environment,
    status,
    version,
    commit,
    branch,
    duration,
    url,
    changes,
    channel = SLACK_CHANNEL
  } = SendDeploymentNotificationSchema.parse(args);
  
  logger.info("Sending deployment notification", { environment, status, version });
  
  // Status colors and emojis
  const statusConfig = {
    started: { color: "#36a64f", emoji: "🚀", action: "Deployment Started" },
    in_progress: { color: "#ff9900", emoji: "⏳", action: "Deployment In Progress" },
    success: { color: "#36a64f", emoji: "✅", action: "Deployment Successful" },
    failure: { color: "#ff0000", emoji: "❌", action: "Deployment Failed" },
    cancelled: { color: "#808080", emoji: "⏹️", action: "Deployment Cancelled" }
  };
  
  const config = statusConfig[status];
  const timestamp = Math.floor(Date.now() / 1000);
  
  // Build fields for the attachment
  const fields = [
    {
      title: "Environment",
      value: environment.toUpperCase(),
      short: true
    },
    {
      title: "Status",
      value: `${config.emoji} ${status.toUpperCase()}`,
      short: true
    }
  ];
  
  if (version) {
    fields.push({
      title: "Version",
      value: version,
      short: true
    });
  }
  
  if (commit) {
    fields.push({
      title: "Commit",
      value: commit,
      short: true
    });
  }
  
  if (branch) {
    fields.push({
      title: "Branch",
      value: branch,
      short: true
    });
  }
  
  if (duration) {
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;
    fields.push({
      title: "Duration",
      value: `${minutes}m ${seconds}s`,
      short: true
    });
  }
  
  // Build blocks for rich formatting
  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${config.emoji} ${config.action}`,
        emoji: true
      }
    },
    {
      type: "section",
      fields: fields.map(field => ({
        type: "mrkdwn",
        text: `*${field.title}:*\n${field.value}`
      }))
    }
  ];
  
  // Add URL if provided
  if (url) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `🔗 *Live URL:* <${url}|View Deployment>`
      }
    });
  }
  
  // Add changes if provided
  if (changes && changes.length > 0) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Changes in this deployment:*\n${changes.map(change => `• ${change}`).join("\n")}`
      }
    });
  }
  
  // Add context footer
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `Catalytic Computing Platform | <!date^${timestamp}^{date_num} at {time_secs}|${new Date().toISOString()}>`
      }
    ]
  });
  
  const result = await slack.chat.postMessage({
    channel,
    text: `${config.action} - ${environment}`,
    blocks,
    attachments: [{
      color: config.color,
      fallback: `${config.action} - ${environment} - ${status}`
    }]
  });
  
  return {
    content: [{
      type: "text",
      text: `${config.emoji} Deployment notification sent successfully!\n` +
            `• Environment: ${environment}\n` +
            `• Status: ${status}\n` +
            `• Channel: ${channel}\n` +
            `• Timestamp: ${result.ts}`
    }]
  };
}

async function sendAlert(args) {
  const {
    severity,
    title,
    message,
    service,
    environment,
    channel = SLACK_CHANNEL,
    mention_users = []
  } = SendAlertSchema.parse(args);
  
  logger.info("Sending alert notification", { severity, title, service });
  
  // Severity colors and emojis
  const severityConfig = {
    info: { color: "#36a64f", emoji: "ℹ️", priority: "INFO" },
    warning: { color: "#ff9900", emoji: "⚠️", priority: "WARNING" },
    error: { color: "#ff0000", emoji: "🔴", priority: "ERROR" },
    critical: { color: "#8B0000", emoji: "🚨", priority: "CRITICAL" }
  };
  
  const config = severityConfig[severity];
  const timestamp = Math.floor(Date.now() / 1000);
  
  // Build mention string for critical alerts
  const mentions = mention_users.length > 0 
    ? mention_users.map(user => `<@${user}>`).join(" ") + " "
    : "";
  
  // Build blocks
  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${config.emoji} ${config.priority}: ${title}`,
        emoji: true
      }
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `${mentions}${message}`
      }
    }
  ];
  
  // Add service/environment context
  const contextFields = [];
  if (service) {
    contextFields.push(`*Service:* ${service}`);
  }
  if (environment) {
    contextFields.push(`*Environment:* ${environment}`);
  }
  
  if (contextFields.length > 0) {
    blocks.push({
      type: "section",
      fields: contextFields.map(field => ({
        type: "mrkdwn",
        text: field
      }))
    });
  }
  
  // Add timestamp context
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `Catalytic Computing Platform | <!date^${timestamp}^{date_num} at {time_secs}|${new Date().toISOString()}>`
      }
    ]
  });
  
  const result = await slack.chat.postMessage({
    channel,
    text: `${config.emoji} ${config.priority}: ${title}`,
    blocks,
    attachments: [{
      color: config.color,
      fallback: `${config.priority}: ${title} - ${message}`
    }]
  });
  
  return {
    content: [{
      type: "text",
      text: `${config.emoji} Alert sent successfully!\n` +
            `• Severity: ${severity.toUpperCase()}\n` +
            `• Title: ${title}\n` +
            `• Channel: ${channel}\n` +
            `• Mentions: ${mention_users.length} users\n` +
            `• Timestamp: ${result.ts}`
    }]
  };
}

async function sendMetricsReport(args) {
  const { title, metrics, environment, timeframe, channel = SLACK_CHANNEL } = args;
  
  logger.info("Sending metrics report", { title, metricsCount: Object.keys(metrics).length });
  
  const timestamp = Math.floor(Date.now() / 1000);
  
  // Build metrics fields
  const metricsFields = Object.entries(metrics).map(([key, value]) => ({
    type: "mrkdwn",
    text: `*${key}:*\n${value}`
  }));
  
  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `📊 ${title}`,
        emoji: true
      }
    },
    {
      type: "section",
      fields: metricsFields
    }
  ];
  
  // Add environment/timeframe context
  const contextInfo = [];
  if (environment) contextInfo.push(`*Environment:* ${environment}`);
  if (timeframe) contextInfo.push(`*Timeframe:* ${timeframe}`);
  
  if (contextInfo.length > 0) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: contextInfo.join(" | ")
      }
    });
  }
  
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `Catalytic Computing Platform | <!date^${timestamp}^{date_num} at {time_secs}|${new Date().toISOString()}>`
      }
    ]
  });
  
  const result = await slack.chat.postMessage({
    channel,
    text: `📊 ${title}`,
    blocks
  });
  
  return {
    content: [{
      type: "text",
      text: `📊 Metrics report sent successfully!\n` +
            `• Title: ${title}\n` +
            `• Metrics: ${Object.keys(metrics).length} items\n` +
            `• Channel: ${channel}\n` +
            `• Timestamp: ${result.ts}`
    }]
  };
}

async function getChannelInfo(args) {
  const { channel } = args;
  
  logger.info("Getting channel info", { channel });
  
  const result = await slack.conversations.info({ channel });
  const channelInfo = result.channel;
  
  return {
    content: [{
      type: "text",
      text: `📺 **Channel Information**\n\n` +
            `• Name: ${channelInfo.name}\n` +
            `• ID: ${channelInfo.id}\n` +
            `• Type: ${channelInfo.is_private ? "Private" : "Public"}\n` +
            `• Members: ${channelInfo.num_members || "Unknown"}\n` +
            `• Purpose: ${channelInfo.purpose?.value || "No purpose set"}\n` +
            `• Topic: ${channelInfo.topic?.value || "No topic set"}\n` +
            `• Created: ${channelInfo.created ? new Date(channelInfo.created * 1000).toLocaleDateString() : "Unknown"}`
    }]
  };
}

async function listChannels(args) {
  const { types = "public_channel,private_channel" } = args || {};
  
  logger.info("Listing channels", { types });
  
  const result = await slack.conversations.list({
    types,
    limit: 50
  });
  
  const channels = result.channels.map(channel => ({
    name: channel.name,
    id: channel.id,
    type: channel.is_private ? "Private" : "Public",
    members: channel.num_members || 0
  }));
  
  return {
    content: [{
      type: "text",
      text: `📺 **Available Channels** (${channels.length} found)\n\n` +
            channels.map(channel => 
              `• #${channel.name} (${channel.type}) - ${channel.members} members`
            ).join("\n")
    }]
  };
}

async function getUserInfo(args) {
  const { user } = args;
  
  logger.info("Getting user info", { user });
  
  const result = await slack.users.info({ user });
  const userInfo = result.user;
  
  return {
    content: [{
      type: "text",
      text: `👤 **User Information**\n\n` +
            `• Name: ${userInfo.real_name || userInfo.name}\n` +
            `• Username: @${userInfo.name}\n` +
            `• ID: ${userInfo.id}\n` +
            `• Email: ${userInfo.profile?.email || "Not available"}\n` +
            `• Status: ${userInfo.presence || "Unknown"}\n` +
            `• Timezone: ${userInfo.tz_label || "Unknown"}\n` +
            `• Is Bot: ${userInfo.is_bot ? "Yes" : "No"}\n` +
            `• Is Admin: ${userInfo.is_admin ? "Yes" : "No"}`
    }]
  };
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
  if (!SLACK_BOT_TOKEN) {
    logger.error("SLACK_BOT_TOKEN environment variable is required");
    process.exit(1);
  }
  
  // Ensure logs directory exists
  const logsDir = path.join(PROJECT_ROOT, "logs");
  try {
    await fs.mkdir(logsDir, { recursive: true });
  } catch (error) {
    // Directory might already exist
  }
  
  // Test Slack connection
  try {
    const auth = await slack.auth.test();
    logger.info("Slack connection verified", { 
      botId: auth.bot_id,
      userId: auth.user_id,
      team: auth.team
    });
  } catch (error) {
    logger.error("Failed to connect to Slack:", error);
    process.exit(1);
  }
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Catalytic Slack MCP Server started", { channel: SLACK_CHANNEL });
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});