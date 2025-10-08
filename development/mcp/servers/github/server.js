#!/usr/bin/env node
/**
 * Catalytic Computing GitHub MCP Server
 * Provides GitHub integration for CI/CD automation, deployment monitoring,
 * and repository management within the Catalytic Computing platform.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { Octokit } from "@octokit/rest";
import { z } from "zod";
import winston from "winston";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Environment configuration
const PROJECT_ROOT = process.env.PROJECT_ROOT || path.join(__dirname, "../../..");
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_REPO = process.env.GITHUB_REPO || "catalytic-computing/platform";
const LOG_LEVEL = process.env.LOG_LEVEL || "info";

// Logger setup
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "github-mcp-server" },
  transports: [
    new winston.transports.File({ 
      filename: path.join(PROJECT_ROOT, "logs", "github-mcp.log") 
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// GitHub client setup
const octokit = new Octokit({
  auth: GITHUB_TOKEN,
  userAgent: "catalytic-computing-mcp/1.0.0"
});

// Parse repository from GITHUB_REPO environment variable
const [owner, repo] = GITHUB_REPO.split("/");

// Input validation schemas
const TriggerWorkflowSchema = z.object({
  workflow: z.string().describe("Workflow file name (e.g., 'ci-cd.yml')"),
  ref: z.string().optional().describe("Git reference (branch/tag)"),
  inputs: z.record(z.string()).optional().describe("Workflow input parameters")
});

const GetWorkflowRunSchema = z.object({
  runId: z.number().describe("Workflow run ID")
});

const CreateDeploymentSchema = z.object({
  environment: z.string().describe("Target environment (production, staging, etc.)"),
  ref: z.string().optional().describe("Git reference to deploy"),
  description: z.string().optional().describe("Deployment description"),
  payload: z.record(z.any()).optional().describe("Deployment payload")
});

const GetDeploymentStatusSchema = z.object({
  deploymentId: z.number().describe("Deployment ID")
});

const CreateReleaseSchema = z.object({
  tagName: z.string().describe("Release tag name"),
  name: z.string().optional().describe("Release name"),
  body: z.string().optional().describe("Release description"),
  draft: z.boolean().optional().describe("Create as draft"),
  prerelease: z.boolean().optional().describe("Mark as prerelease")
});

// MCP Server setup
const server = new Server(
  {
    name: "catalytic-github-mcp",
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
    name: "trigger_workflow",
    description: "Trigger a GitHub Actions workflow in the Catalytic Computing repository",
    inputSchema: {
      type: "object",
      properties: {
        workflow: {
          type: "string",
          description: "Workflow file name (e.g., 'ci-cd.yml')"
        },
        ref: {
          type: "string",
          description: "Git reference (branch/tag, defaults to main)"
        },
        inputs: {
          type: "object",
          description: "Workflow input parameters",
          additionalProperties: {
            type: "string"
          }
        }
      },
      required: ["workflow"]
    }
  },
  {
    name: "get_workflow_runs",
    description: "Get recent workflow runs for monitoring deployment status",
    inputSchema: {
      type: "object",
      properties: {
        workflow: {
          type: "string",
          description: "Workflow file name to filter by (optional)"
        },
        status: {
          type: "string",
          enum: ["completed", "in_progress", "queued"],
          description: "Filter by workflow run status"
        },
        per_page: {
          type: "number",
          description: "Number of results per page (default: 10, max: 100)"
        }
      }
    }
  },
  {
    name: "get_workflow_run",
    description: "Get detailed information about a specific workflow run",
    inputSchema: {
      type: "object",
      properties: {
        runId: {
          type: "number",
          description: "Workflow run ID"
        }
      },
      required: ["runId"]
    }
  },
  {
    name: "cancel_workflow_run",
    description: "Cancel a running workflow (emergency stop)",
    inputSchema: {
      type: "object",
      properties: {
        runId: {
          type: "number",
          description: "Workflow run ID to cancel"
        }
      },
      required: ["runId"]
    }
  },
  {
    name: "create_deployment",
    description: "Create a GitHub deployment for tracking releases",
    inputSchema: {
      type: "object",
      properties: {
        environment: {
          type: "string",
          description: "Target environment (production, staging, development)"
        },
        ref: {
          type: "string",
          description: "Git reference to deploy (defaults to main)"
        },
        description: {
          type: "string",
          description: "Deployment description"
        },
        payload: {
          type: "object",
          description: "Deployment payload/configuration"
        }
      },
      required: ["environment"]
    }
  },
  {
    name: "update_deployment_status",
    description: "Update deployment status (success, failure, in_progress)",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "number",
          description: "Deployment ID"
        },
        state: {
          type: "string",
          enum: ["success", "failure", "error", "pending", "in_progress"],
          description: "Deployment state"
        },
        description: {
          type: "string",
          description: "Status description"
        },
        environmentUrl: {
          type: "string",
          description: "URL where the deployment can be accessed"
        }
      },
      required: ["deploymentId", "state"]
    }
  },
  {
    name: "get_deployments",
    description: "List recent deployments with their status",
    inputSchema: {
      type: "object",
      properties: {
        environment: {
          type: "string",
          description: "Filter by environment"
        },
        per_page: {
          type: "number",
          description: "Number of results per page (default: 10)"
        }
      }
    }
  },
  {
    name: "create_release",
    description: "Create a GitHub release for version management",
    inputSchema: {
      type: "object",
      properties: {
        tagName: {
          type: "string",
          description: "Release tag name (e.g., 'v1.2.3')"
        },
        name: {
          type: "string",
          description: "Release name"
        },
        body: {
          type: "string",
          description: "Release description/changelog"
        },
        draft: {
          type: "boolean",
          description: "Create as draft (default: false)"
        },
        prerelease: {
          type: "boolean",
          description: "Mark as prerelease (default: false)"
        }
      },
      required: ["tagName"]
    }
  },
  {
    name: "get_repository_info",
    description: "Get repository information and statistics",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "get_commit_status",
    description: "Get commit status and checks for a specific commit",
    inputSchema: {
      type: "object",
      properties: {
        sha: {
          type: "string",
          description: "Commit SHA"
        }
      },
      required: ["sha"]
    }
  }
];

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.info("Listing available GitHub tools");
  return { tools: TOOLS };
});

// Tool execution handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  logger.info("Tool called", { tool: name, args });

  try {
    switch (name) {
      case "trigger_workflow":
        return await triggerWorkflow(args);
      case "get_workflow_runs":
        return await getWorkflowRuns(args);
      case "get_workflow_run":
        return await getWorkflowRun(args);
      case "cancel_workflow_run":
        return await cancelWorkflowRun(args);
      case "create_deployment":
        return await createDeployment(args);
      case "update_deployment_status":
        return await updateDeploymentStatus(args);
      case "get_deployments":
        return await getDeployments(args);
      case "create_release":
        return await createRelease(args);
      case "get_repository_info":
        return await getRepositoryInfo(args);
      case "get_commit_status":
        return await getCommitStatus(args);
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
async function triggerWorkflow(args) {
  const { workflow, ref = "main", inputs = {} } = TriggerWorkflowSchema.parse(args);
  
  logger.info("Triggering workflow", { workflow, ref, inputs });
  
  const result = await octokit.actions.createWorkflowDispatch({
    owner,
    repo,
    workflow_id: workflow,
    ref,
    inputs
  });
  
  return {
    content: [{
      type: "text",
      text: `Workflow '${workflow}' triggered successfully on ref '${ref}'${
        Object.keys(inputs).length > 0 
          ? ` with inputs: ${JSON.stringify(inputs, null, 2)}` 
          : ""
      }`
    }]
  };
}

async function getWorkflowRuns(args) {
  const { workflow, status, per_page = 10 } = args || {};
  
  logger.info("Getting workflow runs", { workflow, status, per_page });
  
  const params = {
    owner,
    repo,
    per_page: Math.min(per_page, 100)
  };
  
  if (status) params.status = status;
  
  let runs;
  if (workflow) {
    runs = await octokit.actions.listWorkflowRuns({
      ...params,
      workflow_id: workflow
    });
  } else {
    runs = await octokit.actions.listWorkflowRunsForRepo(params);
  }
  
  const formattedRuns = runs.data.workflow_runs.map(run => ({
    id: run.id,
    name: run.name,
    status: run.status,
    conclusion: run.conclusion,
    created_at: run.created_at,
    updated_at: run.updated_at,
    head_branch: run.head_branch,
    head_sha: run.head_sha.substring(0, 7),
    workflow_id: run.workflow_id,
    url: run.html_url,
    run_number: run.run_number
  }));
  
  return {
    content: [{
      type: "text",
      text: `Found ${formattedRuns.length} workflow runs:\n\n` +
            formattedRuns.map(run => 
              `🔄 #${run.run_number} - ${run.name}\n` +
              `   Status: ${run.status} ${run.conclusion ? `(${run.conclusion})` : ""}\n` +
              `   Branch: ${run.head_branch} (${run.head_sha})\n` +
              `   Updated: ${new Date(run.updated_at).toLocaleString()}\n` +
              `   URL: ${run.url}\n`
            ).join("\n")
    }]
  };
}

async function getWorkflowRun(args) {
  const { runId } = GetWorkflowRunSchema.parse(args);
  
  logger.info("Getting workflow run details", { runId });
  
  const [run, jobs] = await Promise.all([
    octokit.actions.getWorkflowRun({ owner, repo, run_id: runId }),
    octokit.actions.listJobsForWorkflowRun({ owner, repo, run_id: runId })
  ]);
  
  const runData = run.data;
  const jobData = jobs.data.jobs.map(job => ({
    name: job.name,
    status: job.status,
    conclusion: job.conclusion,
    started_at: job.started_at,
    completed_at: job.completed_at,
    url: job.html_url,
    steps: job.steps?.map(step => ({
      name: step.name,
      status: step.status,
      conclusion: step.conclusion,
      number: step.number
    })) || []
  }));
  
  return {
    content: [{
      type: "text",
      text: `Workflow Run #${runData.run_number} - ${runData.name}\n\n` +
            `📊 **Overview:**\n` +
            `• Status: ${runData.status} ${runData.conclusion ? `(${runData.conclusion})` : ""}\n` +
            `• Branch: ${runData.head_branch}\n` +
            `• Commit: ${runData.head_sha.substring(0, 7)}\n` +
            `• Started: ${new Date(runData.created_at).toLocaleString()}\n` +
            `• Duration: ${runData.updated_at ? 
                Math.round((new Date(runData.updated_at) - new Date(runData.created_at)) / 1000 / 60) : "ongoing"
              } minutes\n` +
            `• URL: ${runData.html_url}\n\n` +
            `🔧 **Jobs:**\n` +
            jobData.map(job => 
              `• ${job.name}: ${job.status} ${job.conclusion ? `(${job.conclusion})` : ""}\n` +
              (job.steps.length > 0 ? 
                job.steps.map(step => `  - ${step.name}: ${step.status || "pending"}`).join("\n") + "\n"
                : ""
              )
            ).join("\n")
    }]
  };
}

async function cancelWorkflowRun(args) {
  const { runId } = GetWorkflowRunSchema.parse(args);
  
  logger.warn("Cancelling workflow run", { runId });
  
  await octokit.actions.cancelWorkflowRun({
    owner,
    repo,
    run_id: runId
  });
  
  return {
    content: [{
      type: "text",
      text: `⚠️ Workflow run #${runId} has been cancelled`
    }]
  };
}

async function createDeployment(args) {
  const { environment, ref = "main", description, payload } = CreateDeploymentSchema.parse(args);
  
  logger.info("Creating deployment", { environment, ref, description });
  
  const deployment = await octokit.repos.createDeployment({
    owner,
    repo,
    ref,
    environment,
    description: description || `Deployment to ${environment}`,
    payload: payload || {},
    auto_merge: false,
    required_contexts: []
  });
  
  return {
    content: [{
      type: "text",
      text: `🚀 Deployment created:\n` +
            `• ID: ${deployment.data.id}\n` +
            `• Environment: ${environment}\n` +
            `• Ref: ${ref}\n` +
            `• Description: ${deployment.data.description}\n` +
            `• Created: ${new Date(deployment.data.created_at).toLocaleString()}`
    }]
  };
}

async function updateDeploymentStatus(args) {
  const { deploymentId, state, description, environmentUrl } = args;
  
  logger.info("Updating deployment status", { deploymentId, state, description });
  
  const status = await octokit.repos.createDeploymentStatus({
    owner,
    repo,
    deployment_id: deploymentId,
    state,
    description,
    environment_url: environmentUrl
  });
  
  const statusEmoji = {
    success: "✅",
    failure: "❌", 
    error: "🔴",
    pending: "⏳",
    in_progress: "🔄"
  };
  
  return {
    content: [{
      type: "text",
      text: `${statusEmoji[state]} Deployment status updated:\n` +
            `• Deployment ID: ${deploymentId}\n` +
            `• State: ${state}\n` +
            `• Description: ${description || "No description"}\n` +
            `• Environment URL: ${environmentUrl || "Not provided"}`
    }]
  };
}

async function getDeployments(args) {
  const { environment, per_page = 10 } = args || {};
  
  logger.info("Getting deployments", { environment, per_page });
  
  const params = {
    owner,
    repo,
    per_page: Math.min(per_page, 100)
  };
  
  if (environment) params.environment = environment;
  
  const deployments = await octokit.repos.listDeployments(params);
  
  const deploymentsWithStatus = await Promise.all(
    deployments.data.map(async (deployment) => {
      try {
        const statuses = await octokit.repos.listDeploymentStatuses({
          owner,
          repo,
          deployment_id: deployment.id
        });
        
        return {
          ...deployment,
          latest_status: statuses.data[0] || null
        };
      } catch (error) {
        logger.warn("Failed to get deployment status", { deploymentId: deployment.id, error: error.message });
        return { ...deployment, latest_status: null };
      }
    })
  );
  
  return {
    content: [{
      type: "text",
      text: `Found ${deploymentsWithStatus.length} deployments:\n\n` +
            deploymentsWithStatus.map(deployment => {
              const status = deployment.latest_status;
              const statusEmoji = status ? {
                success: "✅",
                failure: "❌",
                error: "🔴", 
                pending: "⏳",
                in_progress: "🔄"
              }[status.state] || "❓" : "❓";
              
              return `${statusEmoji} **${deployment.environment}**\n` +
                     `   ID: ${deployment.id}\n` +
                     `   Ref: ${deployment.ref}\n` +
                     `   Status: ${status?.state || "unknown"}\n` +
                     `   Created: ${new Date(deployment.created_at).toLocaleString()}\n` +
                     `   Description: ${deployment.description || "No description"}\n`;
            }).join("\n")
    }]
  };
}

async function createRelease(args) {
  const { tagName, name, body, draft = false, prerelease = false } = CreateReleaseSchema.parse(args);
  
  logger.info("Creating release", { tagName, name, draft, prerelease });
  
  const release = await octokit.repos.createRelease({
    owner,
    repo,
    tag_name: tagName,
    name: name || tagName,
    body: body || "",
    draft,
    prerelease
  });
  
  return {
    content: [{
      type: "text",
      text: `🎉 Release created:\n` +
            `• Tag: ${release.data.tag_name}\n` +
            `• Name: ${release.data.name}\n` +
            `• Draft: ${release.data.draft}\n` +
            `• Prerelease: ${release.data.prerelease}\n` +
            `• URL: ${release.data.html_url}\n` +
            `• Published: ${new Date(release.data.published_at || release.data.created_at).toLocaleString()}`
    }]
  };
}

async function getRepositoryInfo() {
  logger.info("Getting repository information");
  
  const [repoInfo, branches, releases] = await Promise.all([
    octokit.repos.get({ owner, repo }),
    octokit.repos.listBranches({ owner, repo, per_page: 5 }),
    octokit.repos.listReleases({ owner, repo, per_page: 5 })
  ]);
  
  const repository = repoInfo.data;
  
  return {
    content: [{
      type: "text",
      text: `📊 **${repository.full_name}**\n\n` +
            `• Description: ${repository.description || "No description"}\n` +
            `• Language: ${repository.language || "Multiple"}\n` +
            `• Stars: ${repository.stargazers_count} ⭐\n` +
            `• Forks: ${repository.forks_count} 🍴\n` +
            `• Issues: ${repository.open_issues_count} open\n` +
            `• Default Branch: ${repository.default_branch}\n` +
            `• Created: ${new Date(repository.created_at).toLocaleDateString()}\n` +
            `• Last Push: ${new Date(repository.pushed_at).toLocaleString()}\n\n` +
            `🌿 **Recent Branches:**\n` +
            branches.data.map(branch => `• ${branch.name}`).join("\n") + "\n\n" +
            `🏷️ **Recent Releases:**\n` +
            (releases.data.length > 0 
              ? releases.data.map(release => `• ${release.tag_name} (${new Date(release.published_at).toLocaleDateString()})`).join("\n")
              : "No releases found"
            )
    }]
  };
}

async function getCommitStatus(args) {
  const { sha } = args;
  
  logger.info("Getting commit status", { sha });
  
  const [commit, status, checks] = await Promise.all([
    octokit.repos.getCommit({ owner, repo, ref: sha }),
    octokit.repos.getCombinedStatusForRef({ owner, repo, ref: sha }),
    octokit.checks.listForRef({ owner, repo, ref: sha }).catch(() => ({ data: { check_runs: [] } }))
  ]);
  
  const commitData = commit.data;
  const statusData = status.data;
  const checksData = checks.data.check_runs || [];
  
  return {
    content: [{
      type: "text",
      text: `📝 **Commit ${sha.substring(0, 7)}**\n\n` +
            `• Message: ${commitData.commit.message.split('\n')[0]}\n` +
            `• Author: ${commitData.commit.author.name}\n` +
            `• Date: ${new Date(commitData.commit.author.date).toLocaleString()}\n` +
            `• URL: ${commitData.html_url}\n\n` +
            `🔍 **Status Checks:**\n` +
            `• Overall: ${statusData.state} (${statusData.total_count} checks)\n` +
            statusData.statuses.map(s => `• ${s.context}: ${s.state} - ${s.description}`).join("\n") +
            (checksData.length > 0 ? 
              "\n\n🧪 **Check Runs:**\n" +
              checksData.map(check => 
                `• ${check.name}: ${check.status} ${check.conclusion ? `(${check.conclusion})` : ""}`
              ).join("\n")
              : ""
            )
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
  if (!GITHUB_TOKEN) {
    logger.error("GITHUB_TOKEN environment variable is required");
    process.exit(1);
  }
  
  if (!owner || !repo) {
    logger.error("Invalid GITHUB_REPO format. Expected: 'owner/repo'");
    process.exit(1);
  }
  
  // Ensure logs directory exists
  const logsDir = path.join(PROJECT_ROOT, "logs");
  try {
    await fs.mkdir(logsDir, { recursive: true });
  } catch (error) {
    // Directory might already exist
  }
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Catalytic GitHub MCP Server started", { owner, repo });
}

main().catch((error) => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});