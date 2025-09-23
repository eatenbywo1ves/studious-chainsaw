/**
 * Service Registry - Manages MCP server registration and discovery
 */

import { z } from 'zod';
import { EventEmitter } from 'events';

const ServiceSchema = z.object({
  id: z.string(),
  name: z.string(),
  version: z.string(),
  url: z.string().url(),
  protocol: z.enum(['http', 'ws', 'stdio']),
  capabilities: z.array(z.string()),
  metadata: z.record(z.any()).optional(),
  healthEndpoint: z.string().optional(),
  priority: z.number().default(1),
  weight: z.number().default(1),
  maxConnections: z.number().default(100),
  registeredAt: z.string().datetime(),
  lastHealthCheck: z.string().datetime().optional(),
  status: z.enum(['healthy', 'unhealthy', 'unknown']).default('unknown'),
});

export type Service = z.infer<typeof ServiceSchema>;

export class ServiceRegistry extends EventEmitter {
  private services: Map<string, Service> = new Map();
  private servicesByName: Map<string, Set<string>> = new Map();

  constructor() {
    super();
  }

  async registerService(serviceData: Partial<Service>): Promise<Service> {
    const service = ServiceSchema.parse({
      ...serviceData,
      id: serviceData.id || this.generateId(),
      registeredAt: new Date().toISOString(),
      status: 'unknown'
    });

    // Check for duplicate
    if (this.services.has(service.id)) {
      throw new Error(`Service with id ${service.id} already registered`);
    }

    // Register service
    this.services.set(service.id, service);

    // Index by name
    if (!this.servicesByName.has(service.name)) {
      this.servicesByName.set(service.name, new Set());
    }
    this.servicesByName.get(service.name)!.add(service.id);

    this.emit('service:registered', service);
    return service;
  }

  async unregisterService(id: string): Promise<void> {
    const service = this.services.get(id);
    if (!service) {
      throw new Error(`Service with id ${id} not found`);
    }

    // Remove from name index
    const nameSet = this.servicesByName.get(service.name);
    if (nameSet) {
      nameSet.delete(id);
      if (nameSet.size === 0) {
        this.servicesByName.delete(service.name);
      }
    }

    // Remove service
    this.services.delete(id);
    this.emit('service:unregistered', service);
  }

  getService(id: string): Service | undefined {
    return this.services.get(id);
  }

  getServicesByName(name: string): Service[] {
    const ids = this.servicesByName.get(name);
    if (!ids) return [];

    return Array.from(ids)
      .map(id => this.services.get(id))
      .filter((s): s is Service => s !== undefined);
  }

  getHealthyServicesByName(name: string): Service[] {
    return this.getServicesByName(name)
      .filter(s => s.status === 'healthy');
  }

  getAllServices(): Service[] {
    return Array.from(this.services.values());
  }

  getServiceCount(): number {
    return this.services.size;
  }

  updateServiceStatus(id: string, status: Service['status']): void {
    const service = this.services.get(id);
    if (service) {
      service.status = status;
      service.lastHealthCheck = new Date().toISOString();
      this.emit('service:status:changed', service);
    }
  }

  updateServiceMetadata(id: string, metadata: Record<string, any>): void {
    const service = this.services.get(id);
    if (service) {
      service.metadata = { ...service.metadata, ...metadata };
      this.emit('service:metadata:changed', service);
    }
  }

  findServices(filter: {
    name?: string;
    capability?: string;
    status?: Service['status'];
  }): Service[] {
    let services = Array.from(this.services.values());

    if (filter.name) {
      services = services.filter(s => s.name === filter.name);
    }

    if (filter.capability) {
      services = services.filter(s =>
        s.capabilities.includes(filter.capability)
      );
    }

    if (filter.status) {
      services = services.filter(s => s.status === filter.status);
    }

    return services;
  }

  private generateId(): string {
    return `svc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Persistence methods
  async save(): Promise<void> {
    // Implement persistence to database or file
    const data = {
      services: Array.from(this.services.entries()),
      servicesByName: Array.from(this.servicesByName.entries())
        .map(([name, ids]) => [name, Array.from(ids)])
    };
    // TODO: Save to persistent storage
  }

  async load(): Promise<void> {
    // TODO: Load from persistent storage
  }
}