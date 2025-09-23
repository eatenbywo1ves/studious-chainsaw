import { render, RenderOptions } from '@testing-library/react';
import React, { ReactElement } from 'react';

// Mock data generators for tests
export const mockStochasticProcessData = (length: number = 100) => {
  const data = [];
  let price = 100;

  for (let i = 0; i < length; i++) {
    const randomChange = (Math.random() - 0.5) * 2;
    price *= (1 + randomChange * 0.01);

    data.push({
      time: i * 0.01,
      price: Math.max(price, 0.01),
      logPrice: Math.log(Math.max(price, 0.01)),
      step: i
    });
  }

  return data;
};

export const mockMultidimensionalData = (length: number = 100) => {
  const data = [];
  let x = 100, y = 100, z = 100;

  for (let i = 0; i < length; i++) {
    const dx = (Math.random() - 0.5) * 2;
    const dy = (Math.random() - 0.5) * 2;
    const dz = (Math.random() - 0.5) * 2;

    x *= (1 + dx * 0.01);
    y *= (1 + dy * 0.01);
    z *= (1 + dz * 0.01);

    const displacement3D = Math.sqrt((x - 100) ** 2 + (y - 100) ** 2 + (z - 100) ** 2);
    const radiusVector = Math.sqrt(x ** 2 + y ** 2 + z ** 2);

    data.push({
      time: i * 0.01,
      x: Math.max(x, 0.01),
      y: Math.max(y, 0.01),
      z: Math.max(z, 0.01),
      logX: Math.log(Math.max(x, 0.01)),
      logY: Math.log(Math.max(y, 0.01)),
      logZ: Math.log(Math.max(z, 0.01)),
      step: i,
      displacement3D,
      radiusVector
    });
  }

  return data;
};

// Test utilities for MCP server testing
export const mockMCPToolCall = (toolName: string, args: any = {}) => ({
  method: 'tools/call',
  params: {
    name: toolName,
    arguments: args
  }
});

export const mockMCPResponse = (content: any) => ({
  content: [{
    type: 'text',
    text: typeof content === 'string' ? content : JSON.stringify(content, null, 2)
  }]
});

// Statistical test helpers
export const calculateMean = (values: number[]): number => {
  return values.reduce((sum, val) => sum + val, 0) / values.length;
};

export const calculateVariance = (values: number[]): number => {
  const mean = calculateMean(values);
  return values.reduce((sum, val) => sum + (val - mean) ** 2, 0) / (values.length - 1);
};

export const calculateStandardDeviation = (values: number[]): number => {
  return Math.sqrt(calculateVariance(values));
};

export const isNormallyDistributed = (values: number[], tolerance: number = 0.5): boolean => {
  const mean = calculateMean(values);
  const stdDev = calculateStandardDeviation(values);

  // Simple normality test: mean should be close to 0, stdDev close to 1
  return Math.abs(mean) < tolerance && Math.abs(stdDev - 1) < tolerance;
};

// React testing utilities
export const renderWithProviders = (
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) => {
  // This could be extended to include providers like Redux, Theme, etc.
  return render(ui, options);
};

// Mock implementations for external dependencies
export const mockMathRandom = (sequence: number[] = [0.5]) => {
  let index = 0;
  return jest.spyOn(Math, 'random').mockImplementation(() => {
    const value = sequence[index % sequence.length];
    index++;
    return value;
  });
};

export const mockDateNow = (timestamp: number = Date.now()) => {
  return jest.spyOn(Date, 'now').mockReturnValue(timestamp);
};

// Async test utilities
export const waitForCondition = async (
  condition: () => boolean,
  timeout: number = 5000,
  interval: number = 100
): Promise<void> => {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    if (condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }

  throw new Error(`Condition not met within ${timeout}ms`);
};

// Validation helpers
export const validateStochasticPath = (path: any[]) => {
  expect(Array.isArray(path)).toBe(true);
  expect(path.length).toBeGreaterThan(0);

  path.forEach((point, index) => {
    expect(point).toHaveProperty('time');
    expect(point).toHaveProperty('step');
    expect(point.step).toBe(index);
    expect(typeof point.time).toBe('number');
    expect(point.time).toBeGreaterThanOrEqual(0);
  });
};

export const validateRiskMetrics = (metrics: any) => {
  const expectedProperties = [
    'meanReturn',
    'volatility',
    'sharpeRatio',
    'valueAtRisk',
    'expectedShortfall',
    'maxDrawdown',
    'totalReturn'
  ];

  expectedProperties.forEach(prop => {
    expect(metrics).toHaveProperty(prop);
    expect(typeof metrics[prop]).toBe('number');
  });

  // Validate ranges
  expect(metrics.volatility).toBeGreaterThanOrEqual(0);
  expect(metrics.maxDrawdown).toBeGreaterThanOrEqual(0);
  expect(metrics.maxDrawdown).toBeLessThanOrEqual(1);
};

// Performance testing utilities
export const measureExecutionTime = async <T>(
  fn: () => Promise<T> | T
): Promise<{ result: T; executionTime: number }> => {
  const start = performance.now();
  const result = await fn();
  const end = performance.now();

  return {
    result,
    executionTime: end - start
  };
};

// Custom Jest matchers
expect.extend({
  toBeWithinRange(received: number, floor: number, ceiling: number) {
    const pass = received >= floor && received <= ceiling;
    if (pass) {
      return {
        message: () => `expected ${received} not to be within range ${floor} - ${ceiling}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be within range ${floor} - ${ceiling}`,
        pass: false,
      };
    }
  },

  toBeApproximatelyEqual(received: number, expected: number, precision: number = 2) {
    const pass = Math.abs(received - expected) < Math.pow(10, -precision);
    if (pass) {
      return {
        message: () => `expected ${received} not to be approximately equal to ${expected}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be approximately equal to ${expected} (precision: ${precision})`,
        pass: false,
      };
    }
  }
});

// Type extensions for custom matchers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeWithinRange(floor: number, ceiling: number): R;
      toBeApproximatelyEqual(expected: number, precision?: number): R;
    }
  }
}