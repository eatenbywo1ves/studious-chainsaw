// Shared types
export interface AgentMessage {
  id: string;
  timestamp: number;
  source: string;
  type: 'command' | 'data' | 'event' | 'error';
  payload: any;
}

export interface StochasticProcess {
  name: string;
  parameters: Record<string, number>;
  simulate: (steps: number, dt: number) => number[];
}

export interface MCPServerConfig {
  name: string;
  version: string;
  port: number;
  capabilities: string[];
}

// Shared utilities
export class MessageBus {
  private handlers: Map<string, Set<Function>> = new Map();

  on(event: string, handler: Function) {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set());
    }
    this.handlers.get(event)!.add(handler);
  }

  off(event: string, handler: Function) {
    this.handlers.get(event)?.delete(handler);
  }

  emit(event: string, ...args: any[]) {
    this.handlers.get(event)?.forEach(handler => handler(...args));
  }
}

export function generateId(): string {
  return Math.random().toString(36).substr(2, 9);
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Math utilities
export function normalRandom(mean = 0, stdDev = 1): number {
  const u1 = Math.random();
  const u2 = Math.random();
  const z0 = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return z0 * stdDev + mean;
}

export function brownianMotion(steps: number, dt: number, sigma = 1): number[] {
  const path = [0];
  for (let i = 1; i < steps; i++) {
    const dW = normalRandom(0, Math.sqrt(dt) * sigma);
    path.push(path[i - 1] + dW);
  }
  return path;
}

// Configuration helpers
export function loadConfig<T>(defaults: T, overrides?: Partial<T>): T {
  return { ...defaults, ...overrides };
}

export function validatePort(port: number): boolean {
  return port > 0 && port < 65536;
}