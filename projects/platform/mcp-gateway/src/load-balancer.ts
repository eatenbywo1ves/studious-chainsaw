/**
 * Load Balancer - Distributes requests across healthy MCP servers
 */

import { Service, ServiceRegistry } from './registry.js';

export type LoadBalancingStrategy = 'round-robin' | 'least-connections' | 'weighted' | 'random';

export class LoadBalancer {
  private registry: ServiceRegistry;
  private strategy: LoadBalancingStrategy;
  private roundRobinIndexes: Map<string, number> = new Map();
  private connectionCounts: Map<string, number> = new Map();

  constructor(
    registry: ServiceRegistry,
    strategy: LoadBalancingStrategy = 'round-robin'
  ) {
    this.registry = registry;
    this.strategy = strategy;
  }

  selectService(serviceName: string): Service | null {
    const services = this.registry.getHealthyServicesByName(serviceName);

    if (services.length === 0) {
      return null;
    }

    if (services.length === 1) {
      return services[0];
    }

    switch (this.strategy) {
      case 'round-robin':
        return this.roundRobinSelect(serviceName, services);
      case 'least-connections':
        return this.leastConnectionsSelect(services);
      case 'weighted':
        return this.weightedSelect(services);
      case 'random':
        return this.randomSelect(services);
      default:
        return services[0];
    }
  }

  private roundRobinSelect(serviceName: string, services: Service[]): Service {
    const currentIndex = this.roundRobinIndexes.get(serviceName) || 0;
    const service = services[currentIndex % services.length];
    this.roundRobinIndexes.set(serviceName, currentIndex + 1);
    return service;
  }

  private leastConnectionsSelect(services: Service[]): Service {
    let minConnections = Infinity;
    let selectedService = services[0];

    for (const service of services) {
      const connections = this.connectionCounts.get(service.id) || 0;
      if (connections < minConnections) {
        minConnections = connections;
        selectedService = service;
      }
    }

    return selectedService;
  }

  private weightedSelect(services: Service[]): Service {
    const totalWeight = services.reduce((sum, s) => sum + s.weight, 0);
    let random = Math.random() * totalWeight;

    for (const service of services) {
      random -= service.weight;
      if (random <= 0) {
        return service;
      }
    }

    return services[services.length - 1];
  }

  private randomSelect(services: Service[]): Service {
    const index = Math.floor(Math.random() * services.length);
    return services[index];
  }

  incrementConnections(serviceId: string): void {
    const current = this.connectionCounts.get(serviceId) || 0;
    this.connectionCounts.set(serviceId, current + 1);
  }

  decrementConnections(serviceId: string): void {
    const current = this.connectionCounts.get(serviceId) || 0;
    if (current > 0) {
      this.connectionCounts.set(serviceId, current - 1);
    }
  }

  getConnectionCount(serviceId: string): number {
    return this.connectionCounts.get(serviceId) || 0;
  }

  setStrategy(strategy: LoadBalancingStrategy): void {
    this.strategy = strategy;
  }

  reset(): void {
    this.roundRobinIndexes.clear();
    this.connectionCounts.clear();
  }
}