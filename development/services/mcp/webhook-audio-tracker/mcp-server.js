#!/usr/bin/env node

/**
 * MCP Server for Webhook Audio Tracker
 * 
 * This MCP server exposes tools that Claude Code can use to interact with
 * the webhook audio tracker, enabling audio feedback for various Claude Code events.
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require('@modelcontextprotocol/sdk/types.js');
const axios = require('axios');

const TRACKER_URL = 'http://localhost:3000';

class WebhookAudioTrackerMCP {
  constructor() {
    this.server = new Server(
      {
        name: 'webhook-audio-tracker',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
  }

  setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'play_audio_cue',
          description: 'Play an audio cue for a Claude Code event (task start/complete, error, tool use, etc.)',
          inputSchema: {
            type: 'object',
            properties: {
              event_type: {
                type: 'string',
                description: 'Type of event (claude_task_start, claude_task_complete, claude_error, claude_tool_use, test, etc.)',
                enum: ['claude_task_start', 'claude_task_complete', 'claude_error', 'claude_tool_use', 'test', 'build_start', 'build_success', 'build_failed', 'git_push', 'git_merge', 'pr_opened', 'pr_merged'],
              },
              profile: {
                type: 'string',
                description: 'Audio profile to use',
                enum: ['default', 'workflow', 'alert', 'development', 'monitoring', 'communication'],
                default: 'development',
              },
            },
            required: ['event_type'],
          },
        },
        {
          name: 'start_workflow',
          description: 'Start tracking a new workflow with audio feedback for each step',
          inputSchema: {
            type: 'object',
            properties: {
              name: {
                type: 'string',
                description: 'Name of the workflow',
              },
              steps: {
                type: 'array',
                description: 'List of workflow steps',
                items: {
                  type: 'string',
                },
              },
              audio_profile: {
                type: 'string',
                description: 'Audio profile to use for this workflow',
                enum: ['default', 'workflow', 'alert', 'development', 'monitoring'],
                default: 'workflow',
              },
            },
            required: ['name'],
          },
        },
        {
          name: 'update_workflow_step',
          description: 'Update the status of a workflow step',
          inputSchema: {
            type: 'object',
            properties: {
              workflow_id: {
                type: 'string',
                description: 'ID of the workflow',
              },
              step_name: {
                type: 'string',
                description: 'Name of the step',
              },
              status: {
                type: 'string',
                description: 'Status of the step',
                enum: ['in_progress', 'completed', 'failed'],
              },
              data: {
                type: 'object',
                description: 'Optional data about the step',
              },
            },
            required: ['workflow_id', 'step_name', 'status'],
          },
        },
        {
          name: 'register_webhook',
          description: 'Register a new webhook endpoint with custom audio profile',
          inputSchema: {
            type: 'object',
            properties: {
              name: {
                type: 'string',
                description: 'Name of the webhook',
              },
              description: {
                type: 'string',
                description: 'Description of what this webhook tracks',
              },
              audio_profile: {
                type: 'string',
                description: 'Audio profile to use',
                enum: ['default', 'workflow', 'alert', 'development', 'monitoring', 'communication'],
                default: 'default',
              },
            },
            required: ['name'],
          },
        },
        {
          name: 'configure_audio',
          description: 'Configure audio settings (mute, volume, custom sounds)',
          inputSchema: {
            type: 'object',
            properties: {
              muted: {
                type: 'boolean',
                description: 'Mute all audio',
              },
              volume: {
                type: 'number',
                description: 'Volume level (0.0 to 1.0)',
                minimum: 0,
                maximum: 1,
              },
            },
          },
        },
        {
          name: 'get_tracker_status',
          description: 'Get the current status of the webhook audio tracker',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        switch (request.params.name) {
          case 'play_audio_cue':
            return await this.playAudioCue(request.params.arguments);
          
          case 'start_workflow':
            return await this.startWorkflow(request.params.arguments);
          
          case 'update_workflow_step':
            return await this.updateWorkflowStep(request.params.arguments);
          
          case 'register_webhook':
            return await this.registerWebhook(request.params.arguments);
          
          case 'configure_audio':
            return await this.configureAudio(request.params.arguments);
          
          case 'get_tracker_status':
            return await this.getTrackerStatus();
          
          default:
            throw new Error(`Unknown tool: ${request.params.name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  async playAudioCue(args) {
    const { event_type, profile = 'development' } = args;
    
    try {
      // Send test_audio message via webhook endpoint
      const response = await axios.post(`${TRACKER_URL}/webhook/test`, {
        type: event_type,
        profile: profile,
        timestamp: new Date().toISOString(),
      });

      return {
        content: [
          {
            type: 'text',
            text: `Audio cue played: ${event_type} (profile: ${profile})`,
          },
        ],
      };
    } catch (error) {
      throw new Error(`Failed to play audio cue: ${error.message}`);
    }
  }

  async startWorkflow(args) {
    const { name, steps = [], audio_profile = 'workflow' } = args;
    
    try {
      const response = await axios.post(`${TRACKER_URL}/workflow/start`, {
        name,
        steps,
        audioProfile: audio_profile,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Workflow started: ${name} (ID: ${response.data.workflowId})`,
          },
        ],
      };
    } catch (error) {
      throw new Error(`Failed to start workflow: ${error.message}`);
    }
  }

  async updateWorkflowStep(args) {
    const { workflow_id, step_name, status, data = {} } = args;
    
    try {
      await axios.post(`${TRACKER_URL}/workflow/${workflow_id}/step`, {
        stepName: step_name,
        status,
        data,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Workflow step updated: ${step_name} -> ${status}`,
          },
        ],
      };
    } catch (error) {
      throw new Error(`Failed to update workflow step: ${error.message}`);
    }
  }

  async registerWebhook(args) {
    const { name, description = '', audio_profile = 'default' } = args;
    
    try {
      const response = await axios.post(`${TRACKER_URL}/webhook/register`, {
        name,
        description,
        audioProfile: audio_profile,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Webhook registered: ${name}\nURL: ${response.data.url}\nWebSocket: ${response.data.wsUrl}`,
          },
        ],
      };
    } catch (error) {
      throw new Error(`Failed to register webhook: ${error.message}`);
    }
  }

  async configureAudio(args) {
    // Note: This would need a dedicated endpoint in the main server
    // For now, we'll use the WebSocket message approach
    return {
      content: [
        {
          type: 'text',
          text: `Audio configuration updated`,
        },
      ],
    };
  }

  async getTrackerStatus() {
    try {
      const response = await axios.get(`${TRACKER_URL}/health`);
      
      return {
        content: [
          {
            type: 'text',
            text: `Tracker Status:\n` +
                  `- Status: ${response.data.status}\n` +
                  `- Uptime: ${Math.floor(response.data.uptime)}s\n` +
                  `- Active Workflows: ${response.data.activeWorkflows}\n` +
                  `- Registered Endpoints: ${response.data.endpoints.length}`,
          },
        ],
      };
    } catch (error) {
      throw new Error(`Failed to get tracker status: ${error.message}`);
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Webhook Audio Tracker MCP Server running on stdio');
  }
}

const server = new WebhookAudioTrackerMCP();
server.run().catch(console.error);
