# Testing Guide

Comprehensive testing strategies and best practices for the projects monorepo.

## Overview

Our testing strategy encompasses multiple levels of testing to ensure code quality, reliability, and maintainability across all workspaces. We use Jest as our primary testing framework with additional tools for specialized testing scenarios.

## Testing Philosophy

### Test Pyramid
```
    ┌─────────────────┐
    │   E2E Tests     │  ← Few, high-value integration tests
    │                 │
    ├─────────────────┤
    │                 │
    │ Integration     │  ← Moderate number of integration tests
    │    Tests        │
    │                 │
    ├─────────────────┤
    │                 │
    │                 │
    │   Unit Tests    │  ← Many fast, focused unit tests
    │                 │
    │                 │
    └─────────────────┘
```

### Testing Principles
1. **Fast Feedback**: Unit tests run in milliseconds
2. **Reliable**: Tests are deterministic and isolated
3. **Maintainable**: Tests are easy to read and update
4. **Comprehensive**: High coverage of critical paths
5. **Realistic**: Integration tests use realistic data

## Test Configuration

### Jest Configuration

```javascript
// jest.config.cjs
module.exports = {
  projects: [
    {
      displayName: 'packages',
      testMatch: ['<rootDir>/packages/**/__tests__/**/*.test.{js,ts,tsx}'],
      testEnvironment: 'jsdom',
      setupFilesAfterEnv: ['<rootDir>/jest.setup.js']
    },
    {
      displayName: 'mcp-servers',
      testMatch: ['<rootDir>/mcp-servers/**/__tests__/**/*.test.{js,ts}'],
      testEnvironment: 'node'
    },
    {
      displayName: 'financial-apps',
      testMatch: ['<rootDir>/financial-apps/**/__tests__/**/*.test.{js,ts,tsx}'],
      testEnvironment: 'jsdom'
    },
    {
      displayName: 'agents',
      testMatch: ['<rootDir>/agents/**/__tests__/**/*.test.{js,ts}'],
      testEnvironment: 'node'
    }
  ],
  collectCoverageFrom: [
    'packages/**/*.{js,ts,tsx}',
    'mcp-servers/**/*.{js,ts}',
    '!**/__tests__/**',
    '!**/*.d.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};
```

### Test Setup

```javascript
// jest.setup.js
import '@testing-library/jest-dom';
import { configure } from '@testing-library/react';

// Configure React Testing Library
configure({ testIdAttribute: 'data-testid' });

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

// Global test utilities
global.testTimeout = 10000;
global.mockMath = () => {
  const mockMath = Object.create(global.Math);
  mockMath.random = jest.fn(() => 0.5);
  global.Math = mockMath;
};
```

## Unit Testing

### Component Testing

#### Basic Component Test
```typescript
// packages/stochastic-components/__tests__/StochasticChart.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StochasticChart } from '../src/StochasticChart';

describe('StochasticChart', () => {
  beforeEach(() => {
    mockMath();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('renders with default props', () => {
    render(<StochasticChart />);

    expect(screen.getByTestId('stochastic-chart')).toBeInTheDocument();
    expect(screen.getByText('Brownian Motion')).toBeInTheDocument();
  });

  it('generates correct number of data points', async () => {
    render(
      <StochasticChart
        steps={100}
        processType="brownian"
        data-testid="chart"
      />
    );

    await waitFor(() => {
      const chart = screen.getByTestId('chart');
      expect(chart).toHaveAttribute('data-points', '100');
    });
  });

  it('updates when parameters change', async () => {
    const user = userEvent.setup();
    const onDataUpdate = jest.fn();

    render(
      <StochasticChart
        steps={50}
        onDataUpdate={onDataUpdate}
      />
    );

    const volatilityInput = screen.getByLabelText('Volatility');
    await user.clear(volatilityInput);
    await user.type(volatilityInput, '0.3');

    expect(onDataUpdate).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          timestamp: expect.any(Number),
          value: expect.any(Number)
        })
      ])
    );
  });
});
```

#### Hook Testing
```typescript
// packages/stochastic-components/__tests__/useStochasticProcess.test.ts
import { renderHook, act } from '@testing-library/react';
import { useStochasticProcess } from '../src/hooks/useStochasticProcess';

describe('useStochasticProcess', () => {
  it('initializes with correct default state', () => {
    const { result } = renderHook(() => useStochasticProcess({
      processType: 'brownian',
      steps: 100
    }));

    expect(result.current.data).toHaveLength(0);
    expect(result.current.isRunning).toBe(false);
    expect(result.current.parameters.processType).toBe('brownian');
  });

  it('starts and stops simulation', async () => {
    const { result } = renderHook(() => useStochasticProcess({
      processType: 'brownian',
      steps: 100
    }));

    act(() => {
      result.current.start();
    });

    expect(result.current.isRunning).toBe(true);

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
    });

    expect(result.current.data.length).toBeGreaterThan(0);

    act(() => {
      result.current.stop();
    });

    expect(result.current.isRunning).toBe(false);
  });
});
```

### Utility Function Testing

```typescript
// packages/shared/__tests__/math.test.ts
import {
  clamp,
  randomGaussian,
  distance,
  lerp
} from '../src/utils/math';

describe('Math utilities', () => {
  describe('clamp', () => {
    it('clamps value within range', () => {
      expect(clamp(5, 0, 10)).toBe(5);
      expect(clamp(-5, 0, 10)).toBe(0);
      expect(clamp(15, 0, 10)).toBe(10);
    });
  });

  describe('randomGaussian', () => {
    beforeEach(() => {
      jest.spyOn(Math, 'random')
        .mockReturnValueOnce(0.5)
        .mockReturnValueOnce(0.7);
    });

    it('generates numbers with correct distribution', () => {
      const samples = Array.from({ length: 1000 }, () =>
        randomGaussian(0, 1)
      );

      const mean = samples.reduce((a, b) => a + b) / samples.length;
      const variance = samples.reduce((sum, x) =>
        sum + Math.pow(x - mean, 2), 0
      ) / samples.length;

      expect(mean).toBeCloseTo(0, 0.1);
      expect(Math.sqrt(variance)).toBeCloseTo(1, 0.1);
    });
  });

  describe('distance', () => {
    it('calculates correct distance', () => {
      const a = { x: 0, y: 0 };
      const b = { x: 3, y: 4 };
      expect(distance(a, b)).toBe(5);
    });
  });

  describe('lerp', () => {
    it('interpolates correctly', () => {
      expect(lerp(0, 10, 0.5)).toBe(5);
      expect(lerp(0, 10, 0)).toBe(0);
      expect(lerp(0, 10, 1)).toBe(10);
    });
  });
});
```

## Integration Testing

### Component Integration

```typescript
// __tests__/integration/StochasticWorkflow.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StochasticWorkflow } from '../src/StochasticWorkflow';

describe('Stochastic Workflow Integration', () => {
  it('completes full stochastic analysis workflow', async () => {
    const user = userEvent.setup();

    render(<StochasticWorkflow />);

    // Configure process
    const processSelect = screen.getByLabelText('Process Type');
    await user.selectOptions(processSelect, 'geometric-brownian');

    const stepsInput = screen.getByLabelText('Steps');
    await user.clear(stepsInput);
    await user.type(stepsInput, '1000');

    // Start simulation
    const startButton = screen.getByText('Start Simulation');
    await user.click(startButton);

    // Wait for completion
    await waitFor(() => {
      expect(screen.getByText('Simulation Complete')).toBeInTheDocument();
    }, { timeout: 5000 });

    // Verify results
    expect(screen.getByTestId('chart-container')).toBeInTheDocument();
    expect(screen.getByTestId('statistics-panel')).toBeInTheDocument();

    const dataPoints = screen.getByTestId('data-count');
    expect(dataPoints).toHaveTextContent('1000');
  });
});
```

### MCP Server Integration

```typescript
// mcp-servers/financial-stochastic-mcp/__tests__/integration.test.ts
import { MCPTestClient } from '../test-utils/MCPTestClient';
import { FinancialStochasticServer } from '../src/server';

describe('MCP Server Integration', () => {
  let client: MCPTestClient;
  let server: FinancialStochasticServer;

  beforeAll(async () => {
    server = new FinancialStochasticServer();
    client = new MCPTestClient();
    await client.connect(server);
  });

  afterAll(async () => {
    await client.disconnect();
  });

  it('generates GBM path correctly', async () => {
    const result = await client.callTool('generate_gbm', {
      steps: 252,
      timeHorizon: 1.0,
      mu: 0.05,
      sigma: 0.2,
      initialPrice: 100
    });

    expect(result.model).toBe('geometric_brownian_motion');
    expect(result.path).toHaveLength(252);
    expect(result.path[0].price).toBe(100);
    expect(result.riskMetrics).toMatchObject({
      meanReturn: expect.any(Number),
      volatility: expect.any(Number),
      sharpeRatio: expect.any(Number)
    });
  });

  it('calculates risk metrics correctly', async () => {
    const path = [
      { time: 0, price: 100 },
      { time: 1, price: 105 },
      { time: 2, price: 98 },
      { time: 3, price: 102 }
    ];

    const result = await client.callTool('calculate_risk_metrics', {
      path,
      confidenceLevel: 0.05
    });

    expect(result.valueAtRisk).toBeLessThan(0);
    expect(result.expectedShortfall).toBeLessThan(result.valueAtRisk);
    expect(result.maxDrawdown).toBeGreaterThanOrEqual(0);
  });
});
```

## End-to-End Testing

### Playwright Configuration

```typescript
// playwright.config.ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '__tests__/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure'
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' }
    },
    {
      name: 'firefox',
      use: { browserName: 'firefox' }
    },
    {
      name: 'webkit',
      use: { browserName: 'webkit' }
    }
  ],
  webServer: {
    command: 'npm run dev',
    port: 3000,
    reuseExistingServer: !process.env.CI
  }
});
```

### E2E Test Example

```typescript
// __tests__/e2e/financial-simulator.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Financial Simulator E2E', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/financial-simulator');
  });

  test('complete portfolio analysis workflow', async ({ page }) => {
    // Add assets to portfolio
    await page.click('[data-testid="add-asset-button"]');
    await page.fill('[data-testid="asset-symbol"]', 'AAPL');
    await page.fill('[data-testid="asset-weight"]', '0.4');
    await page.click('[data-testid="confirm-asset"]');

    await page.click('[data-testid="add-asset-button"]');
    await page.fill('[data-testid="asset-symbol"]', 'GOOGL');
    await page.fill('[data-testid="asset-weight"]', '0.6');
    await page.click('[data-testid="confirm-asset"]');

    // Run simulation
    await page.click('[data-testid="run-simulation"]');

    // Wait for results
    await expect(page.locator('[data-testid="simulation-results"]'))
      .toBeVisible({ timeout: 10000 });

    // Verify portfolio metrics
    await expect(page.locator('[data-testid="portfolio-return"]'))
      .toContainText('%');
    await expect(page.locator('[data-testid="portfolio-volatility"]'))
      .toContainText('%');
    await expect(page.locator('[data-testid="sharpe-ratio"]'))
      .toContainText('Sharpe');

    // Verify chart rendering
    await expect(page.locator('[data-testid="portfolio-chart"]'))
      .toBeVisible();

    // Test chart interactions
    await page.hover('[data-testid="portfolio-chart"]');
    await expect(page.locator('[data-testid="chart-tooltip"]'))
      .toBeVisible();
  });

  test('exports simulation results', async ({ page }) => {
    // Setup portfolio and run simulation
    await page.click('[data-testid="add-asset-button"]');
    await page.fill('[data-testid="asset-symbol"]', 'AAPL');
    await page.click('[data-testid="confirm-asset"]');
    await page.click('[data-testid="run-simulation"]');

    await expect(page.locator('[data-testid="simulation-results"]'))
      .toBeVisible();

    // Test export functionality
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv"]');
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toMatch(/portfolio-analysis.*\.csv/);
  });
});
```

## Performance Testing

### Component Performance

```typescript
// __tests__/performance/StochasticChart.perf.test.tsx
import { render } from '@testing-library/react';
import { StochasticChart } from '../src/StochasticChart';

describe('StochasticChart Performance', () => {
  it('renders large datasets efficiently', async () => {
    const startTime = performance.now();

    render(
      <StochasticChart
        steps={10000}
        processType="brownian"
        virtualizeData={true}
      />
    );

    const renderTime = performance.now() - startTime;
    expect(renderTime).toBeLessThan(1000); // Should render in < 1s
  });

  it('handles rapid parameter updates', async () => {
    const { rerender } = render(
      <StochasticChart volatility={0.1} />
    );

    const startTime = performance.now();

    // Simulate rapid parameter changes
    for (let i = 0; i < 100; i++) {
      rerender(
        <StochasticChart volatility={0.1 + i * 0.001} />
      );
    }

    const updateTime = performance.now() - startTime;
    expect(updateTime).toBeLessThan(500); // Should update quickly
  });
});
```

### Load Testing

```typescript
// __tests__/load/mcp-server-load.test.ts
import { MCPLoadTester } from '../test-utils/MCPLoadTester';

describe('MCP Server Load Testing', () => {
  it('handles concurrent requests', async () => {
    const loadTester = new MCPLoadTester({
      concurrency: 10,
      duration: 30000, // 30 seconds
      rampUp: 5000     // 5 second ramp-up
    });

    const results = await loadTester.run(async (client) => {
      return client.callTool('generate_gbm', {
        steps: 1000,
        mu: 0.05,
        sigma: 0.2
      });
    });

    expect(results.successRate).toBeGreaterThan(0.95);
    expect(results.averageResponseTime).toBeLessThan(1000);
    expect(results.maxResponseTime).toBeLessThan(5000);
  });
});
```

## Test Utilities

### Mock Factories

```typescript
// test-utils/factories.ts
export const createMockStochasticData = (count: number = 100) => {
  return Array.from({ length: count }, (_, i) => ({
    timestamp: i,
    value: 100 + Math.sin(i * 0.1) * 10 + Math.random() * 5,
    step: i
  }));
};

export const createMockPortfolio = () => ({
  assets: [
    { symbol: 'AAPL', weight: 0.4, price: 150 },
    { symbol: 'GOOGL', weight: 0.6, price: 2800 }
  ],
  totalValue: 100000,
  riskMetrics: {
    var: -0.032,
    expectedShortfall: -0.048,
    sharpeRatio: 1.2
  }
});
```

### Custom Matchers

```typescript
// test-utils/matchers.ts
expect.extend({
  toBeCloseToArray(received: number[], expected: number[], precision: number = 2) {
    const pass = received.every((value, index) =>
      Math.abs(value - expected[index]) < Math.pow(10, -precision)
    );

    return {
      message: () =>
        `expected ${received} to be close to ${expected} within ${precision} decimal places`,
      pass
    };
  },

  toHaveValidStochasticProperties(received: any[]) {
    const values = received.map(item => item.value);
    const isFinite = values.every(v => Number.isFinite(v));
    const hasVariation = Math.max(...values) > Math.min(...values);

    return {
      message: () => `expected stochastic data to have valid properties`,
      pass: isFinite && hasVariation
    };
  }
});
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18, 20, 22]

    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run unit tests
        run: npm run test:ci

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info

  integration-tests:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run integration tests
        run: npm run test:integration
        env:
          REDIS_URL: redis://localhost:6379

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Install Playwright
        run: npx playwright install --with-deps

      - name: Run E2E tests
        run: npm run test:e2e

      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-report
          path: playwright-report/
```

## Test Commands

### Package Scripts

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:ci": "jest --ci --coverage --watchAll=false",
    "test:packages": "jest --selectProjects packages",
    "test:mcp-servers": "jest --selectProjects mcp-servers",
    "test:financial-apps": "jest --selectProjects financial-apps",
    "test:agents": "jest --selectProjects agents",
    "test:integration": "jest --testPathPattern=integration",
    "test:e2e": "playwright test",
    "test:performance": "jest --testPathPattern=performance",
    "test:load": "jest --testPathPattern=load"
  }
}
```

### Workspace-specific Testing

```bash
# Test specific workspace
npm run test --workspace=@monorepo/stochastic-components

# Test specific file
npm test -- StochasticChart.test.tsx

# Test with debugging
npm test -- --detectOpenHandles --forceExit

# Run tests in debug mode
node --inspect-brk node_modules/.bin/jest --runInBand
```

## Best Practices

### Test Organization

1. **File Naming**: Use `.test.tsx` for component tests, `.test.ts` for utilities
2. **Test Structure**: Arrange-Act-Assert pattern
3. **Descriptive Names**: Test names should describe behavior clearly
4. **Single Responsibility**: Each test should verify one behavior

### Mock Guidelines

1. **Mock External Dependencies**: API calls, file system, timers
2. **Don't Mock Internal Logic**: Test real implementation
3. **Reset Mocks**: Clean up between tests
4. **Mock Sparingly**: Prefer real implementations when possible

### Performance Considerations

1. **Fast Tests**: Unit tests should run in milliseconds
2. **Parallel Execution**: Use Jest's parallel execution
3. **Test Isolation**: Avoid shared state between tests
4. **Resource Cleanup**: Clean up resources in afterEach

### Coverage Guidelines

1. **80% Minimum**: Maintain at least 80% coverage
2. **Critical Paths**: Ensure 100% coverage for critical functionality
3. **Meaningful Coverage**: Focus on behavior coverage, not just line coverage
4. **Regular Review**: Review coverage reports regularly

## Debugging Tests

### VS Code Configuration

```json
{
  "type": "node",
  "request": "launch",
  "name": "Debug Jest Tests",
  "program": "${workspaceFolder}/node_modules/.bin/jest",
  "args": ["--runInBand"],
  "console": "integratedTerminal",
  "internalConsoleOptions": "neverOpen"
}
```

### Common Debug Techniques

```typescript
// Debug component rendering
import { debug } from '@testing-library/react';

render(<MyComponent />);
debug(); // Prints DOM to console

// Debug hooks
import { renderHook } from '@testing-library/react';

const { result } = renderHook(() => useMyHook());
console.log(result.current); // Inspect hook state

// Debug async operations
test('async test', async () => {
  console.log('Before async operation');
  await waitFor(() => {
    console.log('During waitFor');
    expect(element).toBeInTheDocument();
  });
  console.log('After async operation');
});
```

## Continuous Improvement

### Metrics Tracking

- Test execution time trends
- Coverage trends over time
- Flaky test identification
- Performance regression detection

### Test Reviews

- Regular test code reviews
- Coverage gap analysis
- Test performance optimization
- Test maintenance and cleanup

---

This testing guide ensures comprehensive coverage and high code quality across the entire monorepo while providing clear guidelines for developers to write effective tests.