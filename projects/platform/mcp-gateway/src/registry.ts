/**
 * Service Registry - Manages MCP server registration and discovery
 */

import { z } from 'zod';
import { EventEmitter } from 'events';
import { PersistenceBackend } from './persistence/interface.js';
import { JsonFilePersistence } from './persistence/json-file.js';

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
  private persistence: PersistenceBackend;
  private autoSave: boolean;
  private saveDebounceTimer?: NodeJS.Timeout;

  constructor(persistencePath: string = '.mcp-gateway', autoSave: boolean = true) {
    super();
    this.persistence = new JsonFilePersistence(persistencePath);
    this.autoSave = autoSave;
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

    // Auto-save if enabled
    if (this.autoSave) {
      this.debouncedSave();
    }

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

    // Auto-save if enabled
    if (this.autoSave) {
      this.debouncedSave();
    }
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

  /**
   * Debounced save - delays save operation to batch multiple changes
   * Saves after 5 seconds of inactivity
   */
  private debouncedSave() {
    if (this.saveDebounceTimer) {
      clearTimeout(this.saveDebounceTimer);
    }

    this.saveDebounceTimer = setTimeout(() => {
      this.save().catch(err => {
        console.error('Failed to auto-save registry:', err);
      });
    }, 5000); // Save after 5 seconds of inactivity
  }

  /**
   * Save registry state to persistent storage
   */
  async save(): Promise<void> {
    try {
      const data = {
        services: Array.from(this.services.entries()).map(([id, service]) => ({
          id,
          ...service
        })),
        servicesByName: Object.fromEntries(
          Array.from(this.servicesByName.entries()).map(([name, ids]) => [
            name,
            Array.from(ids)
          ])
        ),
        savedAt: new Date().toISOString(),
        version: '1.0'
      };

      await this.persistence.save('registry', data);
      this.emit('registry:saved', { serviceCount: this.services.size });
    } catch (error) {
      console.error('Failed to save registry:', error);
      this.emit('registry:save:error', error);
      throw error;
    }
  }

  /**
   * Load registry state from persistent storage
   */
  async load(): Promise<void> {
    try {
      const data = await this.persistence.load('registry');

      if (!data) {
        console.info('No existing registry found, starting fresh');
        return;
      }

      // Restore services
      this.services.clear();
      this.servicesByName.clear();

      for (const serviceData of data.services) {
        try {
          const service = ServiceSchema.parse(serviceData);
          this.services.set(service.id, service);

          // Rebuild name index
          if (!this.servicesByName.has(service.name)) {
            this.servicesByName.set(service.name, new Set());
          }
          this.servicesByName.get(service.name)!.add(service.id);
        } catch (error) {
          console.error(`Failed to restore service ${serviceData.id}:`, error);
        }
      }

      console.info(`Loaded ${this.services.size} services from registry`);
      this.emit('registry:loaded', { serviceCount: this.services.size });
    } catch (error) {
      console.error('Failed to load registry:', error);
      this.emit('registry:load:error', error);
      throw error;
    }
  }

  /**
   * Clear all registry data (memory and storage)
   */
  async clear(): Promise<void> {
    this.services.clear();
    this.servicesByName.clear();
    await this.persistence.delete('registry');
    this.emit('registry:cleared');
  }
}