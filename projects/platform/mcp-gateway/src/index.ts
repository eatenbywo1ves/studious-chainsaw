/**
 * MCP Gateway - Central router and orchestrator for MCP servers
 */

import express from 'express';
import { WebSocketServer } from 'ws';
import { Server as MCPServer } from '@modelcontextprotocol/sdk/server/index.js';
import { pino } from 'pino';
import { z } from 'zod';
import PQueue from 'p-queue';
import NodeCache from 'node-cache';
import { ServiceRegistry } from './registry.js';
import { LoadBalancer } from './load-balancer.js';
import { HealthChecker } from './health-checker.js';
import { RequestRouter } from './router.js';
import { MetricsCollector } from './metrics.js';

const logger = pino({ level: 'info' });

// Configuration schema
const ConfigSchema = z.object({
  port: z.number().default(3000),
  wsPort: z.number().default(3001),
  registryUrl: z.string().optional(),
  healthCheckInterval: z.number().default(30000),
  requestTimeout: z.number().default(30000),
  maxConcurrency: z.number().default(100),
  cacheEnabled: z.boolean().default(true),
  cacheTTL: z.number().default(300),
});

type Config = z.infer<typeof ConfigSchema>;

export class MCPGateway {
  private app: express.Application;
  private wss: WebSocketServer;
  private registry: ServiceRegistry;
  private loadBalancer: LoadBalancer;
  private healthChecker: HealthChecker;
  private router: RequestRouter;
  private metrics: MetricsCollector;
  private requestQueue: PQueue;
  private cache: NodeCache;
  private config: Config;

  constructor(config: Partial<Config> = {}) {
    this.config = ConfigSchema.parse(config);
    this.app = express();
    this.wss = new WebSocketServer({ port: this.config.wsPort });

    // Initialize components
    this.registry = new ServiceRegistry();
    this.loadBalancer = new LoadBalancer(this.registry);
    this.healthChecker = new HealthChecker(this.registry, this.config.healthCheckInterval);
    this.router = new RequestRouter(this.loadBalancer);
    this.metrics = new MetricsCollector();

    // Request queue for rate limiting
    this.requestQueue = new PQueue({
      concurrency: this.config.maxConcurrency
    });

    // Response cache
    this.cache = new NodeCache({
      stdTTL: this.config.cacheTTL,
      checkperiod: this.config.cacheTTL * 0.2,
      useClones: false
    });

    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocket();
  }

  private setupMiddleware() {
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));

    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info({
          method: req.method,
          url: req.url,
          status: res.statusCode,
          duration
        });
        this.metrics.recordRequest(req.method, req.url, res.statusCode, duration);
      });
      next();
    });

    // CORS
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
      }
      next();
    });
  }

  private setupRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      const health = {
        status: 'healthy',
        uptime: process.uptime(),
        services: this.registry.getServiceCount(),
        metrics: this.metrics.getSnapshot()
      };
      res.json(health);
    });

    // Service registry endpoints
    this.app.get('/services', (req, res) => {
      const services = this.registry.getAllServices();
      res.json(services);
    });

    this.app.post('/services/register', async (req, res) => {
      try {
        const service = await this.registry.registerService(req.body);
        res.json({ success: true, service });
      } catch (error) {
        logger.error('Service registration failed:', error);
        res.status(400).json({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    });

    this.app.delete('/services/:id', async (req, res) => {
      try {
        await this.registry.unregisterService(req.params.id);
        res.json({ success: true });
      } catch (error) {
        logger.error('Service unregistration failed:', error);
        res.status(400).json({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    });

    // MCP proxy endpoint
    this.app.post('/mcp/:service/*', async (req, res) => {
      const serviceName = req.params.service;
      const path = req.params[0];
      const cacheKey = `${serviceName}:${path}:${JSON.stringify(req.body)}`;

      // Check cache for GET-like operations
      if (this.config.cacheEnabled && req.body.method === 'tools/list') {
        const cached = this.cache.get(cacheKey);
        if (cached) {
          this.metrics.recordCacheHit();
          return res.json(cached);
        }
      }

      try {
        // Queue the request
        const response = await this.requestQueue.add(async () => {
          return await this.router.routeRequest(serviceName, {
            path,
            method: req.method,
            body: req.body,
            headers: req.headers as Record<string, string>
          });
        });

        // Cache successful responses
        if (this.config.cacheEnabled && response.success) {
          this.cache.set(cacheKey, response);
          this.metrics.recordCacheMiss();
        }

        res.json(response);
      } catch (error) {
        logger.error('Request routing failed:', error);
        res.status(500).json({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    });

    // Metrics endpoint
    this.app.get('/metrics', (req, res) => {
      res.json(this.metrics.getSnapshot());
    });
  }

  private setupWebSocket() {
    this.wss.on('connection', (ws) => {
      logger.info('New WebSocket connection');

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());

          // Route WebSocket messages to appropriate service
          const response = await this.router.routeWebSocketMessage(message);
          ws.send(JSON.stringify(response));
        } catch (error) {
          logger.error('WebSocket message handling failed:', error);
          ws.send(JSON.stringify({
            error: error instanceof Error ? error.message : 'Unknown error'
          }));
        }
      });

      ws.on('close', () => {
        logger.info('WebSocket connection closed');
      });
    });
  }

  async start() {
    // Start health checker
    await this.healthChecker.start();

    // Start HTTP server
    this.app.listen(this.config.port, () => {
      logger.info(`MCP Gateway started on port ${this.config.port}`);
      logger.info(`WebSocket server started on port ${this.config.wsPort}`);
    });
  }

  async stop() {
    await this.healthChecker.stop();
    this.wss.close();
  }
}

// Start gateway if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const gateway = new MCPGateway();
  gateway.start().catch(console.error);

  process.on('SIGTERM', async () => {
    await gateway.stop();
    process.exit(0);
  });
}