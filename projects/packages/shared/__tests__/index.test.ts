import {
  MessageBus,
  generateId,
  sleep,
  normalRandom,
  brownianMotion,
  loadConfig,
  validatePort,
  AgentMessage,
  StochasticProcess,
  MCPServerConfig
} from '../src/index';

describe('MessageBus', () => {
  let messageBus: MessageBus;

  beforeEach(() => {
    messageBus = new MessageBus();
  });

  test('should register and call event handler', () => {
    const handler = jest.fn();
    messageBus.on('test-event', handler);
    messageBus.emit('test-event', 'data');

    expect(handler).toHaveBeenCalledWith('data');
  });

  test('should handle multiple handlers for same event', () => {
    const handler1 = jest.fn();
    const handler2 = jest.fn();

    messageBus.on('test-event', handler1);
    messageBus.on('test-event', handler2);
    messageBus.emit('test-event', 'data');

    expect(handler1).toHaveBeenCalledWith('data');
    expect(handler2).toHaveBeenCalledWith('data');
  });

  test('should remove event handler', () => {
    const handler = jest.fn();
    messageBus.on('test-event', handler);
    messageBus.off('test-event', handler);
    messageBus.emit('test-event', 'data');

    expect(handler).not.toHaveBeenCalled();
  });

  test('should emit with multiple arguments', () => {
    const handler = jest.fn();
    messageBus.on('test-event', handler);
    messageBus.emit('test-event', 'arg1', 'arg2', 'arg3');

    expect(handler).toHaveBeenCalledWith('arg1', 'arg2', 'arg3');
  });
});

describe('Utility Functions', () => {
  describe('generateId', () => {
    test('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();

      expect(id1).not.toBe(id2);
      expect(typeof id1).toBe('string');
      expect(id1.length).toBeGreaterThan(0);
    });

    test('should generate IDs of consistent format', () => {
      const id = generateId();
      expect(id).toMatch(/^[a-z0-9]+$/);
    });
  });

  describe('sleep', () => {
    test('should resolve after specified time', async () => {
      const start = Date.now();
      await sleep(100);
      const end = Date.now();

      expect(end - start).toBeGreaterThanOrEqual(95); // Allow for small timing variance
    });

    test('should return a promise', () => {
      const result = sleep(1);
      expect(result).toBeInstanceOf(Promise);
    });
  });

  describe('validatePort', () => {
    test('should validate valid ports', () => {
      expect(validatePort(80)).toBe(true);
      expect(validatePort(8080)).toBe(true);
      expect(validatePort(65535)).toBe(true);
      expect(validatePort(1)).toBe(true);
    });

    test('should reject invalid ports', () => {
      expect(validatePort(0)).toBe(false);
      expect(validatePort(-1)).toBe(false);
      expect(validatePort(65536)).toBe(false);
      expect(validatePort(100000)).toBe(false);
    });
  });

  describe('loadConfig', () => {
    test('should merge defaults with overrides', () => {
      const defaults = { port: 8080, host: 'localhost', debug: false };
      const overrides = { port: 3000, debug: true };

      const result = loadConfig(defaults, overrides);

      expect(result).toEqual({
        port: 3000,
        host: 'localhost',
        debug: true
      });
    });

    test('should work with no overrides', () => {
      const defaults = { port: 8080, host: 'localhost' };

      const result = loadConfig(defaults);

      expect(result).toEqual(defaults);
    });

    test('should work with empty overrides', () => {
      const defaults = { port: 8080, host: 'localhost' };

      const result = loadConfig(defaults, {});

      expect(result).toEqual(defaults);
    });
  });
});

describe('Math Utilities', () => {
  describe('normalRandom', () => {
    test('should generate numbers with correct mean', () => {
      const samples = 10000;
      const mean = 5;
      const stdDev = 2;

      let sum = 0;
      for (let i = 0; i < samples; i++) {
        sum += normalRandom(mean, stdDev);
      }

      const actualMean = sum / samples;
      expect(actualMean).toBeCloseTo(mean, 0); // Within 1 decimal place
    });

    test('should generate different values', () => {
      const value1 = normalRandom();
      const value2 = normalRandom();

      expect(value1).not.toBe(value2);
    });

    test('should handle default parameters', () => {
      const value = normalRandom();
      expect(typeof value).toBe('number');
      expect(value).not.toBeNaN();
    });
  });

  describe('brownianMotion', () => {
    test('should generate path starting at 0', () => {
      const path = brownianMotion(100, 0.01);
      expect(path[0]).toBe(0);
    });

    test('should generate path of correct length', () => {
      const steps = 50;
      const path = brownianMotion(steps, 0.01);
      expect(path).toHaveLength(steps);
    });

    test('should handle different parameters', () => {
      const path1 = brownianMotion(10, 0.1, 1);
      const path2 = brownianMotion(10, 0.1, 2);

      expect(path1).toHaveLength(10);
      expect(path2).toHaveLength(10);
      expect(path1[0]).toBe(0);
      expect(path2[0]).toBe(0);
    });

    test('should generate different paths', () => {
      const path1 = brownianMotion(10, 0.1);
      const path2 = brownianMotion(10, 0.1);

      // Paths should be different (with very high probability)
      expect(path1).not.toEqual(path2);
    });
  });
});

describe('Type Interfaces', () => {
  test('AgentMessage interface should be properly typed', () => {
    const message: AgentMessage = {
      id: 'test-123',
      timestamp: Date.now(),
      source: 'test-agent',
      type: 'command',
      payload: { action: 'test' }
    };

    expect(message.id).toBe('test-123');
    expect(typeof message.timestamp).toBe('number');
    expect(message.source).toBe('test-agent');
    expect(['command', 'data', 'event', 'error']).toContain(message.type);
  });

  test('StochasticProcess interface should be properly typed', () => {
    const process: StochasticProcess = {
      name: 'Brownian Motion',
      parameters: { sigma: 1, mu: 0 },
      simulate: (steps: number, dt: number) => brownianMotion(steps, dt)
    };

    expect(process.name).toBe('Brownian Motion');
    expect(typeof process.parameters).toBe('object');
    expect(typeof process.simulate).toBe('function');

    const simulation = process.simulate(10, 0.1);
    expect(Array.isArray(simulation)).toBe(true);
    expect(simulation).toHaveLength(10);
  });

  test('MCPServerConfig interface should be properly typed', () => {
    const config: MCPServerConfig = {
      name: 'test-server',
      version: '1.0.0',
      port: 8080,
      capabilities: ['tools', 'resources']
    };

    expect(config.name).toBe('test-server');
    expect(config.version).toBe('1.0.0');
    expect(config.port).toBe(8080);
    expect(Array.isArray(config.capabilities)).toBe(true);
  });
});