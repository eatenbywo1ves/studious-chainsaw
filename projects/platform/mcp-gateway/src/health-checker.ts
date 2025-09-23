/**
 * Health Checker - Monitors MCP server health status
 */

import { ServiceRegistry } from './registry.js';
import { pino } from 'pino';

const logger = pino({ level: 'info' });

export class HealthChecker {
  private registry: ServiceRegistry;
  private interval: number;
  private timer?: NodeJS.Timer;
  private checking: boolean = false;

  constructor(registry: ServiceRegistry, interval: number = 30000) {
    this.registry = registry;
    this.interval = interval;
  }

  async start(): Promise<void> {
    if (this.timer) {
      return;
    }

    logger.info(`Starting health checker with interval ${this.interval}ms`);

    // Initial check
    await this.checkAll();

    // Schedule periodic checks
    this.timer = setInterval(async () => {
      if (!this.checking) {
        await this.checkAll();
      }
    }, this.interval);
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  private async checkAll(): Promise<void> {
    this.checking = true;

    try {
      const services = this.registry.getAllServices();
      const checkPromises = services.map(service =>
        this.checkService(service.id).catch(err => {
          logger.error(`Health check failed for ${service.id}:`, err);
        })
      );

      await Promise.all(checkPromises);
    } finally {
      this.checking = false;
    }
  }

  async checkService(serviceId: string): Promise<boolean> {
    const service = this.registry.getService(serviceId);
    if (!service) {
      return false;
    }

    try {
      let isHealthy = false;

      switch (service.protocol) {
        case 'http':
          isHealthy = await this.checkHttpHealth(service.url, service.healthEndpoint);
          break;
        case 'ws':
          isHealthy = await this.checkWebSocketHealth(service.url);
          break;
        case 'stdio':
          // Stdio services are assumed healthy if registered
          isHealthy = true;
          break;
      }

      this.registry.updateServiceStatus(
        serviceId,
        isHealthy ? 'healthy' : 'unhealthy'
      );

      return isHealthy;
    } catch (error) {
      logger.error(`Health check error for ${serviceId}:`, error);
      this.registry.updateServiceStatus(serviceId, 'unhealthy');
      return false;
    }
  }

  private async checkHttpHealth(baseUrl: string, healthEndpoint?: string): Promise<boolean> {
    const url = healthEndpoint
      ? new URL(healthEndpoint, baseUrl).toString()
      : `${baseUrl}/health`;

    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      });

      return response.ok;
    } catch (error) {
      return false;
    }
  }

  private async checkWebSocketHealth(url: string): Promise<boolean> {
    // WebSocket health checks are more complex
    // For now, we'll use a simple ping-pong mechanism
    return new Promise((resolve) => {
      const ws = new WebSocket(url);
      const timeout = setTimeout(() => {
        ws.close();
        resolve(false);
      }, 5000);

      ws.on('open', () => {
        ws.send(JSON.stringify({ type: 'ping' }));
      });

      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          if (message.type === 'pong') {
            clearTimeout(timeout);
            ws.close();
            resolve(true);
          }
        } catch {
          // Invalid response
        }
      });

      ws.on('error', () => {
        clearTimeout(timeout);
        resolve(false);
      });
    });
  }
}