/**
 * Request Router - Routes requests to appropriate MCP servers
 */

import { LoadBalancer } from './load-balancer.js';
import { pino } from 'pino';

const logger = pino({ level: 'info' });

export interface RouteRequest {
  path: string;
  method: string;
  body: any;
  headers: Record<string, string>;
}

export interface RouteResponse {
  success: boolean;
  data?: any;
  error?: string;
  serviceId?: string;
  duration?: number;
}

export class RequestRouter {
  private loadBalancer: LoadBalancer;
  private requestTimeout: number;

  constructor(loadBalancer: LoadBalancer, requestTimeout: number = 30000) {
    this.loadBalancer = loadBalancer;
    this.requestTimeout = requestTimeout;
  }

  async routeRequest(
    serviceName: string,
    request: RouteRequest
  ): Promise<RouteResponse> {
    const startTime = Date.now();

    // Select a service
    const service = this.loadBalancer.selectService(serviceName);
    if (!service) {
      return {
        success: false,
        error: `No healthy service available for ${serviceName}`
      };
    }

    logger.info(`Routing request to service ${service.id} (${service.name})`);

    try {
      // Track connections
      this.loadBalancer.incrementConnections(service.id);

      let response: any;

      switch (service.protocol) {
        case 'http':
          response = await this.routeHttpRequest(service.url, request);
          break;
        case 'ws':
          response = await this.routeWebSocketRequest(service.url, request);
          break;
        case 'stdio':
          response = await this.routeStdioRequest(service.id, request);
          break;
        default:
          throw new Error(`Unsupported protocol: ${service.protocol}`);
      }

      return {
        success: true,
        data: response,
        serviceId: service.id,
        duration: Date.now() - startTime
      };
    } catch (error) {
      logger.error(`Request routing failed:`, error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        serviceId: service.id,
        duration: Date.now() - startTime
      };
    } finally {
      this.loadBalancer.decrementConnections(service.id);
    }
  }

  private async routeHttpRequest(
    baseUrl: string,
    request: RouteRequest
  ): Promise<any> {
    const url = `${baseUrl}/${request.path}`;

    const response = await fetch(url, {
      method: request.method,
      headers: {
        'Content-Type': 'application/json',
        ...request.headers
      },
      body: request.method !== 'GET' ? JSON.stringify(request.body) : undefined,
      signal: AbortSignal.timeout(this.requestTimeout)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  }

  private async routeWebSocketRequest(
    url: string,
    request: RouteRequest
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      const timeout = setTimeout(() => {
        ws.close();
        reject(new Error('WebSocket request timeout'));
      }, this.requestTimeout);

      ws.on('open', () => {
        ws.send(JSON.stringify({
          ...request.body,
          path: request.path
        }));
      });

      ws.on('message', (data) => {
        clearTimeout(timeout);
        ws.close();

        try {
          const response = JSON.parse(data.toString());
          resolve(response);
        } catch (error) {
          reject(new Error('Invalid WebSocket response'));
        }
      });

      ws.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  private async routeStdioRequest(
    serviceId: string,
    request: RouteRequest
  ): Promise<any> {
    // Stdio routing not implemented in this version
    // Stdio MCP servers should be wrapped with an HTTP/WebSocket adapter
    //
    // Migration options:
    // 1. Use an HTTP adapter: Wrap your stdio MCP server with Express/Fastify
    // 2. Use WebSocket protocol: Convert stdio communication to WebSocket
    // 3. Use a process manager: Tools like PM2 can bridge stdio to HTTP
    //
    // Example HTTP adapter:
    //   const { spawn } = require('child_process');
    //   app.post('/mcp', (req, res) => {
    //     const proc = spawn('your-mcp-server');
    //     proc.stdin.write(JSON.stringify(req.body));
    //     proc.stdout.on('data', data => res.json(JSON.parse(data)));
    //   });
    throw new Error(
      'Stdio protocol not supported. Use HTTP or WebSocket protocol instead. ' +
      'See MCP Gateway documentation for migration guide.'
    );
  }

  async routeWebSocketMessage(message: any): Promise<any> {
    // Extract service name from message
    const serviceName = message.service || message.target;
    if (!serviceName) {
      return {
        error: 'Service name not specified in message'
      };
    }

    return this.routeRequest(serviceName, {
      path: message.path || '',
      method: 'POST',
      body: message,
      headers: {}
    });
  }
}