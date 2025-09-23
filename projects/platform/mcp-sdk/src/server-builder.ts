/**
 * MCP Server Builder - Fluent API for building MCP servers
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { z } from 'zod';
import { EventEmitter } from 'eventemitter3';
import { pino, Logger } from 'pino';
import { Middleware, MiddlewareChain } from './middleware.js';
import { ValidationSchema } from './validation.js';

export interface ServerConfig {
  name: string;
  version: string;
  description?: string;
  capabilities?: string[];
  metadata?: Record<string, any>;
  logger?: Logger;
}

export interface Tool {
  name: string;
  description: string;
  parameters: z.ZodSchema<any>;
  handler: (params: any) => Promise<any>;
  middleware?: Middleware[];
}

export interface Resource {
  name: string;
  description: string;
  uri: string;
  mimeType?: string;
  handler: () => Promise<any>;
  middleware?: Middleware[];
}

export interface Prompt {
  name: string;
  description: string;
  arguments?: z.ZodSchema<any>;
  template: string | ((args: any) => string);
  middleware?: Middleware[];
}

export class MCPServerBuilder extends EventEmitter {
  private config: ServerConfig;
  private tools: Map<string, Tool> = new Map();
  private resources: Map<string, Resource> = new Map();
  private prompts: Map<string, Prompt> = new Map();
  private globalMiddleware: Middleware[] = [];
  private server?: Server;
  private logger: Logger;

  constructor(config: ServerConfig) {
    super();
    this.config = config;
    this.logger = config.logger || pino({ level: 'info' });
  }

  /**
   * Add a tool to the server
   */
  addTool(tool: Tool): this {
    if (this.tools.has(tool.name)) {
      throw new Error(`Tool ${tool.name} already exists`);
    }

    this.tools.set(tool.name, tool);
    this.emit('tool:added', tool);
    this.logger.info(`Tool added: ${tool.name}`);
    return this;
  }

  /**
   * Add multiple tools
   */
  addTools(...tools: Tool[]): this {
    tools.forEach(tool => this.addTool(tool));
    return this;
  }

  /**
   * Add a resource to the server
   */
  addResource(resource: Resource): this {
    if (this.resources.has(resource.uri)) {
      throw new Error(`Resource ${resource.uri} already exists`);
    }

    this.resources.set(resource.uri, resource);
    this.emit('resource:added', resource);
    this.logger.info(`Resource added: ${resource.uri}`);
    return this;
  }

  /**
   * Add multiple resources
   */
  addResources(...resources: Resource[]): this {
    resources.forEach(resource => this.addResource(resource));
    return this;
  }

  /**
   * Add a prompt to the server
   */
  addPrompt(prompt: Prompt): this {
    if (this.prompts.has(prompt.name)) {
      throw new Error(`Prompt ${prompt.name} already exists`);
    }

    this.prompts.set(prompt.name, prompt);
    this.emit('prompt:added', prompt);
    this.logger.info(`Prompt added: ${prompt.name}`);
    return this;
  }

  /**
   * Add multiple prompts
   */
  addPrompts(...prompts: Prompt[]): this {
    prompts.forEach(prompt => this.addPrompt(prompt));
    return this;
  }

  /**
   * Add global middleware
   */
  use(middleware: Middleware): this {
    this.globalMiddleware.push(middleware);
    return this;
  }

  /**
   * Build and return the MCP server
   */
  build(): Server {
    this.server = new Server({
      name: this.config.name,
      version: this.config.version
    });

    // Register tools
    this.tools.forEach(tool => {
      this.server!.setRequestHandler(
        { method: `tools/${tool.name}` },
        async (request) => {
          const middleware = [...this.globalMiddleware, ...(tool.middleware || [])];
          const chain = new MiddlewareChain(middleware);

          return await chain.execute(async () => {
            // Validate parameters
            const params = tool.parameters.parse(request.params);

            // Execute handler
            const result = await tool.handler(params);

            this.emit('tool:executed', {
              tool: tool.name,
              params,
              result
            });

            return result;
          }, { tool: tool.name, request });
        }
      );
    });

    // Register resources
    this.resources.forEach(resource => {
      this.server!.setRequestHandler(
        { method: `resources/${resource.uri}` },
        async (request) => {
          const middleware = [...this.globalMiddleware, ...(resource.middleware || [])];
          const chain = new MiddlewareChain(middleware);

          return await chain.execute(async () => {
            const result = await resource.handler();

            this.emit('resource:accessed', {
              resource: resource.uri,
              result
            });

            return result;
          }, { resource: resource.uri, request });
        }
      );
    });

    // Register prompts
    this.prompts.forEach(prompt => {
      this.server!.setRequestHandler(
        { method: `prompts/${prompt.name}` },
        async (request) => {
          const middleware = [...this.globalMiddleware, ...(prompt.middleware || [])];
          const chain = new MiddlewareChain(middleware);

          return await chain.execute(async () => {
            const args = prompt.arguments
              ? prompt.arguments.parse(request.params)
              : {};

            const result = typeof prompt.template === 'function'
              ? prompt.template(args)
              : prompt.template;

            this.emit('prompt:generated', {
              prompt: prompt.name,
              args,
              result
            });

            return result;
          }, { prompt: prompt.name, request });
        }
      );
    });

    // List handlers
    this.server.setRequestHandler(
      { method: 'tools/list' },
      async () => ({
        tools: Array.from(this.tools.values()).map(t => ({
          name: t.name,
          description: t.description,
          inputSchema: t.parameters
        }))
      })
    );

    this.server.setRequestHandler(
      { method: 'resources/list' },
      async () => ({
        resources: Array.from(this.resources.values()).map(r => ({
          uri: r.uri,
          name: r.name,
          description: r.description,
          mimeType: r.mimeType
        }))
      })
    );

    this.server.setRequestHandler(
      { method: 'prompts/list' },
      async () => ({
        prompts: Array.from(this.prompts.values()).map(p => ({
          name: p.name,
          description: p.description,
          arguments: p.arguments
        }))
      })
    );

    this.logger.info(`MCP Server built: ${this.config.name} v${this.config.version}`);
    this.emit('server:built', this.server);

    return this.server;
  }

  /**
   * Get the built server instance
   */
  getServer(): Server | undefined {
    return this.server;
  }

  /**
   * Get server metadata
   */
  getMetadata(): Record<string, any> {
    return {
      ...this.config.metadata,
      tools: this.tools.size,
      resources: this.resources.size,
      prompts: this.prompts.size
    };
  }
}