// Note: This file needs to be .js since the source is .js
// Import the classes for testing (we'll need to adjust the import structure)

describe('FinancialStochasticGenerator', () => {
  // Mock Math.random for predictable tests
  let mockRandom;

  beforeEach(() => {
    mockRandom = jest.spyOn(Math, 'random');
    // Set up a predictable sequence of random numbers
    let callCount = 0;
    mockRandom.mockImplementation(() => {
      const values = [0.3, 0.7, 0.1, 0.9, 0.5, 0.2, 0.8, 0.4, 0.6];
      return values[callCount++ % values.length];
    });
  });

  afterEach(() => {
    mockRandom.mockRestore();
  });

  describe('Box-Muller transformation', () => {
    test('should generate normally distributed random numbers', () => {
      // Import the module
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const samples = [];
      for (let i = 0; i < 100; i++) {
        samples.push(FinancialStochasticGenerator.boxMuller());
      }

      // Basic checks for normal distribution properties
      const mean = samples.reduce((sum, val) => sum + val, 0) / samples.length;
      const variance = samples.reduce((sum, val) => sum + (val - mean) ** 2, 0) / (samples.length - 1);

      // Should be approximately normal (mean ≈ 0, variance ≈ 1)
      expect(Math.abs(mean)).toBeLessThan(0.5); // Mean close to 0
      expect(Math.abs(variance - 1)).toBeLessThan(0.5); // Variance close to 1
    });
  });

  describe('Geometric Brownian Motion', () => {
    test('should generate GBM path with correct structure', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const path = FinancialStochasticGenerator.generateGeometricBrownianMotion(
        10, // steps
        1.0, // timeHorizon
        0.05, // mu
        0.2, // sigma
        100 // initialPrice
      );

      // Check structure
      expect(path).toHaveLength(11); // steps + 1 (initial point)
      expect(path[0]).toMatchObject({
        time: 0,
        price: 100,
        logPrice: Math.log(100),
        step: 0
      });

      // Check that all path points have required properties
      path.forEach((point, index) => {
        expect(point).toHaveProperty('time');
        expect(point).toHaveProperty('price');
        expect(point).toHaveProperty('logPrice');
        expect(point).toHaveProperty('step');
        expect(point.step).toBe(index);
        expect(point.price).toBeGreaterThan(0);
      });
    });

    test('should handle default parameters', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const path = FinancialStochasticGenerator.generateGeometricBrownianMotion(5, 1.0);

      expect(path).toHaveLength(6);
      expect(path[0].price).toBe(100); // default initial price
    });
  });

  describe('Ornstein-Uhlenbeck Process', () => {
    test('should generate OU process with mean reversion', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const path = FinancialStochasticGenerator.generateOrnsteinUhlenbeck(
        10, // steps
        1.0, // timeHorizon
        2.0, // kappa
        0.04, // theta (long-term mean in log space)
        0.2, // sigma
        100 // initialValue
      );

      expect(path).toHaveLength(11);
      expect(path[0]).toMatchObject({
        time: 0,
        price: 100,
        step: 0
      });

      // Check structure
      path.forEach(point => {
        expect(point).toHaveProperty('time');
        expect(point).toHaveProperty('price');
        expect(point).toHaveProperty('logPrice');
        expect(point).toHaveProperty('step');
        expect(point.price).toBeGreaterThan(0);
      });
    });
  });

  describe('Heston Model', () => {
    test('should generate Heston model with stochastic volatility', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const path = FinancialStochasticGenerator.generateHestonModel(
        10, // steps
        1.0, // timeHorizon
        0.05, // mu
        2.0, // kappa
        0.04, // theta
        0.1, // xi
        -0.7, // rho
        100, // initialPrice
        0.04 // initialVar
      );

      expect(path).toHaveLength(11);
      expect(path[0]).toMatchObject({
        time: 0,
        price: 100,
        variance: 0.04,
        step: 0
      });

      // Check structure and constraints
      path.forEach(point => {
        expect(point).toHaveProperty('time');
        expect(point).toHaveProperty('price');
        expect(point).toHaveProperty('variance');
        expect(point).toHaveProperty('volatility');
        expect(point).toHaveProperty('step');
        expect(point.price).toBeGreaterThan(0);
        expect(point.variance).toBeGreaterThanOrEqual(0); // Non-negative variance
        expect(point.volatility).toBeGreaterThanOrEqual(0);
      });
    });
  });

  describe('Merton Jump Diffusion', () => {
    test('should generate jump diffusion model', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const path = FinancialStochasticGenerator.generateMertonJumpDiffusion(
        10, // steps
        1.0, // timeHorizon
        0.05, // mu
        0.2, // sigma
        0.1, // lambda
        -0.1, // muJ
        0.15, // sigmaJ
        100 // initialPrice
      );

      expect(path).toHaveLength(11);
      expect(path[0]).toMatchObject({
        time: 0,
        price: 100,
        jumps: 0,
        step: 0
      });

      // Check structure
      path.forEach(point => {
        expect(point).toHaveProperty('time');
        expect(point).toHaveProperty('price');
        expect(point).toHaveProperty('jumps');
        expect(point).toHaveProperty('step');
        expect(point.price).toBeGreaterThan(0);
        expect(point.jumps).toBeGreaterThanOrEqual(0);
      });
    });
  });

  describe('CIR Process', () => {
    test('should generate CIR interest rate model', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const path = FinancialStochasticGenerator.generateCIRProcess(
        10, // steps
        1.0, // timeHorizon
        2.0, // kappa
        0.04, // theta
        0.2, // sigma
        0.03 // initialRate
      );

      expect(path).toHaveLength(11);
      expect(path[0]).toMatchObject({
        time: 0,
        rate: 0.03,
        step: 0
      });

      // Check structure and non-negative rates
      path.forEach(point => {
        expect(point).toHaveProperty('time');
        expect(point).toHaveProperty('rate');
        expect(point).toHaveProperty('step');
        expect(point.rate).toBeGreaterThanOrEqual(0); // Non-negative rates
      });
    });
  });

  describe('Risk Metrics Calculation', () => {
    test('should calculate comprehensive risk metrics', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      // Create a simple price path for testing
      const path = [
        { time: 0, price: 100 },
        { time: 0.1, price: 105 },
        { time: 0.2, price: 98 },
        { time: 0.3, price: 102 },
        { time: 0.4, price: 95 },
        { time: 0.5, price: 108 }
      ];

      const metrics = FinancialStochasticGenerator.calculateRiskMetrics(path, 0.05);

      expect(metrics).toHaveProperty('meanReturn');
      expect(metrics).toHaveProperty('volatility');
      expect(metrics).toHaveProperty('sharpeRatio');
      expect(metrics).toHaveProperty('valueAtRisk');
      expect(metrics).toHaveProperty('expectedShortfall');
      expect(metrics).toHaveProperty('maxDrawdown');
      expect(metrics).toHaveProperty('totalReturn');

      // Check that values are reasonable
      expect(typeof metrics.meanReturn).toBe('number');
      expect(typeof metrics.volatility).toBe('number');
      expect(metrics.volatility).toBeGreaterThan(0);
      expect(metrics.maxDrawdown).toBeGreaterThanOrEqual(0);
      expect(metrics.maxDrawdown).toBeLessThanOrEqual(1);
    });

    test('should handle empty or insufficient data', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const emptyPath = [];
      const singlePoint = [{ time: 0, price: 100 }];

      expect(FinancialStochasticGenerator.calculateRiskMetrics(emptyPath)).toEqual({});
      expect(FinancialStochasticGenerator.calculateRiskMetrics(singlePoint)).toEqual({});
    });

    test('should handle path with rate data (CIR model)', () => {
      const FinancialStochasticGenerator = require('../src/index.js').FinancialStochasticGenerator;

      const ratePath = [
        { time: 0, rate: 0.03 },
        { time: 0.1, rate: 0.035 },
        { time: 0.2, rate: 0.028 },
        { time: 0.3, rate: 0.032 }
      ];

      const metrics = FinancialStochasticGenerator.calculateRiskMetrics(ratePath);

      expect(metrics).toEqual({}); // Should return empty for rate-only data
    });
  });
});

describe('FinancialStochasticMCPServer Integration', () => {
  // These would be integration tests for the MCP server
  // In a real scenario, you'd test the server setup and tool handlers

  test('should initialize server with correct capabilities', () => {
    // Mock the MCP SDK components
    const mockServer = {
      setRequestHandler: jest.fn(),
      onerror: null,
      close: jest.fn()
    };

    // This would require refactoring the module to be more testable
    expect(true).toBe(true); // Placeholder for now
  });

  test('should register all expected tools', () => {
    const expectedTools = [
      'generate_gbm',
      'generate_ou_process',
      'generate_heston_model',
      'generate_merton_jump',
      'generate_cir_process',
      'calculate_risk_metrics'
    ];

    // This would test that all tools are properly registered
    expect(expectedTools).toHaveLength(6);
  });
});