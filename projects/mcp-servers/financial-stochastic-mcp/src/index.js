#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

class FinancialStochasticGenerator {
  // Box-Muller transformation for normal random variables
  static boxMuller() {
    let u = 0, v = 0;
    while(u === 0) u = Math.random();
    while(v === 0) v = Math.random();
    return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
  }

  static generateGeometricBrownianMotion(steps, timeHorizon, mu = 0.05, sigma = 0.2, initialPrice = 100) {
    const dt = timeHorizon / steps;
    const path = [{ time: 0, price: initialPrice, logPrice: Math.log(initialPrice), step: 0 }];
    let S = initialPrice;
    
    for (let i = 1; i <= steps; i++) {
      const dW = Math.sqrt(dt) * this.boxMuller();
      S *= Math.exp((mu - 0.5 * sigma ** 2) * dt + sigma * dW);
      path.push({
        time: i * dt,
        price: S,
        logPrice: Math.log(S),
        step: i
      });
    }
    return path;
  }

  static generateOrnsteinUhlenbeck(steps, timeHorizon, kappa = 2.0, theta = 0.04, sigma = 0.2, initialValue = 100) {
    const dt = timeHorizon / steps;
    const path = [{ time: 0, price: initialValue, step: 0 }];
    let X = Math.log(initialValue);
    
    for (let i = 1; i <= steps; i++) {
      const dW = Math.sqrt(dt) * this.boxMuller();
      X += kappa * (Math.log(theta) - X) * dt + sigma * dW;
      const S = Math.exp(X);
      path.push({
        time: i * dt,
        price: S,
        logPrice: X,
        step: i
      });
    }
    return path;
  }

  static generateHestonModel(steps, timeHorizon, mu = 0.05, kappa = 2.0, theta = 0.04, xi = 0.1, rho = -0.7, initialPrice = 100, initialVar = 0.04) {
    const dt = timeHorizon / steps;
    const path = [{ time: 0, price: initialPrice, variance: initialVar, step: 0 }];
    let S = initialPrice;
    let v = initialVar;
    
    for (let i = 1; i <= steps; i++) {
      const Z1 = this.boxMuller();
      const Z2 = this.boxMuller();
      
      // Correlated random variables
      const dW1 = Math.sqrt(dt) * Z1;
      const dW2 = Math.sqrt(dt) * (rho * Z1 + Math.sqrt(1 - rho ** 2) * Z2);
      
      // Update variance (with Feller condition handling)
      const newV = v + kappa * (theta - v) * dt + xi * Math.sqrt(Math.max(v, 0)) * dW2;
      v = Math.max(newV, 0); // Ensure non-negative variance
      
      // Update price
      S *= Math.exp((mu - 0.5 * v) * dt + Math.sqrt(v) * dW1);
      
      path.push({
        time: i * dt,
        price: S,
        variance: v,
        volatility: Math.sqrt(v),
        step: i
      });
    }
    return path;
  }

  static generateMertonJumpDiffusion(steps, timeHorizon, mu = 0.05, sigma = 0.2, lambda = 0.1, muJ = -0.1, sigmaJ = 0.15, initialPrice = 100) {
    const dt = timeHorizon / steps;
    const path = [{ time: 0, price: initialPrice, jumps: 0, step: 0 }];
    let S = initialPrice;
    let jumpCount = 0;
    
    for (let i = 1; i <= steps; i++) {
      const dW = Math.sqrt(dt) * this.boxMuller();
      
      // Poisson jump process
      const jumpProbability = lambda * dt;
      let jumpSize = 0;
      
      if (Math.random() < jumpProbability) {
        jumpSize = Math.exp(muJ + sigmaJ * this.boxMuller()) - 1;
        jumpCount++;
      }
      
      // Update price with continuous part and jumps
      S *= Math.exp((mu - 0.5 * sigma ** 2 - lambda * (Math.exp(muJ + 0.5 * sigmaJ ** 2) - 1)) * dt + sigma * dW) * (1 + jumpSize);
      
      path.push({
        time: i * dt,
        price: S,
        jumps: jumpCount,
        step: i
      });
    }
    return path;
  }

  static generateCIRProcess(steps, timeHorizon, kappa = 2.0, theta = 0.04, sigma = 0.2, initialRate = 0.03) {
    const dt = timeHorizon / steps;
    const path = [{ time: 0, rate: initialRate, step: 0 }];
    let r = initialRate;
    
    for (let i = 1; i <= steps; i++) {
      const dW = Math.sqrt(dt) * this.boxMuller();
      r += kappa * (theta - r) * dt + sigma * Math.sqrt(Math.max(r, 0)) * dW;
      r = Math.max(r, 0); // Ensure non-negative rates
      
      path.push({
        time: i * dt,
        rate: r,
        step: i
      });
    }
    return path;
  }

  static calculateRiskMetrics(path, confidenceLevel = 0.05) {
    if (path.length < 2) return {};

    const returns = [];
    for (let i = 1; i < path.length; i++) {
      if (path[i].price && path[i-1].price) {
        returns.push(Math.log(path[i].price / path[i-1].price));
      }
    }

    if (returns.length === 0) return {};

    // Sort returns for VaR calculation
    const sortedReturns = [...returns].sort((a, b) => a - b);
    const varIndex = Math.floor(confidenceLevel * returns.length);
    const var95 = sortedReturns[varIndex];
    
    // Expected Shortfall (CVaR)
    const tailReturns = sortedReturns.slice(0, varIndex + 1);
    const expectedShortfall = tailReturns.reduce((sum, ret) => sum + ret, 0) / tailReturns.length;

    // Basic statistics
    const meanReturn = returns.reduce((sum, ret) => sum + ret, 0) / returns.length;
    const variance = returns.reduce((sum, ret) => sum + (ret - meanReturn) ** 2, 0) / (returns.length - 1);
    const volatility = Math.sqrt(variance);
    
    // Sharpe ratio (assuming risk-free rate of 0)
    const sharpeRatio = meanReturn / volatility;

    // Maximum drawdown
    let peak = path[0].price || path[0].rate;
    let maxDrawdown = 0;
    
    for (const point of path) {
      const value = point.price || point.rate;
      if (value > peak) peak = value;
      const drawdown = (peak - value) / peak;
      if (drawdown > maxDrawdown) maxDrawdown = drawdown;
    }

    return {
      meanReturn: meanReturn * 252, // Annualized
      volatility: volatility * Math.sqrt(252), // Annualized
      sharpeRatio: sharpeRatio * Math.sqrt(252), // Annualized
      valueAtRisk: var95,
      expectedShortfall,
      maxDrawdown,
      totalReturn: (path[path.length - 1].price / path[0].price - 1) || 0
    };
  }
}

class FinancialStochasticMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'financial-stochastic-mcp',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    
    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'generate_gbm',
          description: 'Generate Geometric Brownian Motion path for stock price modeling',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              mu: { type: 'number', description: 'Drift rate (annual)', default: 0.05 },
              sigma: { type: 'number', description: 'Volatility (annual)', default: 0.2 },
              initialPrice: { type: 'number', description: 'Initial asset price', default: 100 }
            },
            required: ['steps', 'timeHorizon']
          }
        },
        {
          name: 'generate_ou_process',
          description: 'Generate Ornstein-Uhlenbeck mean-reverting process',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              kappa: { type: 'number', description: 'Mean reversion speed', default: 2.0 },
              theta: { type: 'number', description: 'Long-term mean level', default: 0.04 },
              sigma: { type: 'number', description: 'Volatility parameter', default: 0.2 },
              initialValue: { type: 'number', description: 'Initial value', default: 100 }
            },
            required: ['steps', 'timeHorizon']
          }
        },
        {
          name: 'generate_heston_model',
          description: 'Generate Heston stochastic volatility model paths',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              mu: { type: 'number', description: 'Drift rate', default: 0.05 },
              kappa: { type: 'number', description: 'Volatility mean reversion speed', default: 2.0 },
              theta: { type: 'number', description: 'Long-term variance', default: 0.04 },
              xi: { type: 'number', description: 'Vol of vol', default: 0.1 },
              rho: { type: 'number', description: 'Correlation between price and vol', default: -0.7 },
              initialPrice: { type: 'number', description: 'Initial asset price', default: 100 },
              initialVar: { type: 'number', description: 'Initial variance', default: 0.04 }
            },
            required: ['steps', 'timeHorizon']
          }
        },
        {
          name: 'generate_merton_jump',
          description: 'Generate Merton jump diffusion model with discontinuous jumps',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              mu: { type: 'number', description: 'Drift rate', default: 0.05 },
              sigma: { type: 'number', description: 'Diffusion volatility', default: 0.2 },
              lambda: { type: 'number', description: 'Jump intensity', default: 0.1 },
              muJ: { type: 'number', description: 'Jump mean', default: -0.1 },
              sigmaJ: { type: 'number', description: 'Jump volatility', default: 0.15 },
              initialPrice: { type: 'number', description: 'Initial asset price', default: 100 }
            },
            required: ['steps', 'timeHorizon']
          }
        },
        {
          name: 'generate_cir_process',
          description: 'Generate Cox-Ingersoll-Ross interest rate model',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              kappa: { type: 'number', description: 'Mean reversion speed', default: 2.0 },
              theta: { type: 'number', description: 'Long-term rate level', default: 0.04 },
              sigma: { type: 'number', description: 'Volatility parameter', default: 0.2 },
              initialRate: { type: 'number', description: 'Initial interest rate', default: 0.03 }
            },
            required: ['steps', 'timeHorizon']
          }
        },
        {
          name: 'calculate_risk_metrics',
          description: 'Calculate comprehensive risk metrics from price path',
          inputSchema: {
            type: 'object',
            properties: {
              path: {
                type: 'array',
                description: 'Array of price/rate path points',
                items: {
                  type: 'object',
                  properties: {
                    time: { type: 'number' },
                    price: { type: 'number' },
                    rate: { type: 'number' }
                  }
                }
              },
              confidenceLevel: { type: 'number', description: 'VaR confidence level', default: 0.05 }
            },
            required: ['path']
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        const { name, arguments: args } = request.params;

        switch (name) {
          case 'generate_gbm':
            const gbmPath = FinancialStochasticGenerator.generateGeometricBrownianMotion(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.mu || 0.05,
              args.sigma || 0.2,
              args.initialPrice || 100
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'geometric_brownian_motion',
                  parameters: args,
                  path: gbmPath,
                  riskMetrics: FinancialStochasticGenerator.calculateRiskMetrics(gbmPath)
                }, null, 2)
              }]
            };

          case 'generate_ou_process':
            const ouPath = FinancialStochasticGenerator.generateOrnsteinUhlenbeck(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.kappa || 2.0,
              args.theta || 0.04,
              args.sigma || 0.2,
              args.initialValue || 100
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'ornstein_uhlenbeck',
                  parameters: args,
                  path: ouPath,
                  riskMetrics: FinancialStochasticGenerator.calculateRiskMetrics(ouPath)
                }, null, 2)
              }]
            };

          case 'generate_heston_model':
            const hestonPath = FinancialStochasticGenerator.generateHestonModel(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.mu || 0.05,
              args.kappa || 2.0,
              args.theta || 0.04,
              args.xi || 0.1,
              args.rho || -0.7,
              args.initialPrice || 100,
              args.initialVar || 0.04
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'heston_stochastic_volatility',
                  parameters: args,
                  path: hestonPath,
                  riskMetrics: FinancialStochasticGenerator.calculateRiskMetrics(hestonPath)
                }, null, 2)
              }]
            };

          case 'generate_merton_jump':
            const mertonPath = FinancialStochasticGenerator.generateMertonJumpDiffusion(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.mu || 0.05,
              args.sigma || 0.2,
              args.lambda || 0.1,
              args.muJ || -0.1,
              args.sigmaJ || 0.15,
              args.initialPrice || 100
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'merton_jump_diffusion',
                  parameters: args,
                  path: mertonPath,
                  riskMetrics: FinancialStochasticGenerator.calculateRiskMetrics(mertonPath)
                }, null, 2)
              }]
            };

          case 'generate_cir_process':
            const cirPath = FinancialStochasticGenerator.generateCIRProcess(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.kappa || 2.0,
              args.theta || 0.04,
              args.sigma || 0.2,
              args.initialRate || 0.03
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'cox_ingersoll_ross',
                  parameters: args,
                  path: cirPath,
                  riskMetrics: FinancialStochasticGenerator.calculateRiskMetrics(cirPath)
                }, null, 2)
              }]
            };

          case 'calculate_risk_metrics':
            const riskMetrics = FinancialStochasticGenerator.calculateRiskMetrics(
              args.path,
              args.confidenceLevel || 0.05
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(riskMetrics, null, 2)
              }]
            };

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${error.message}`
        );
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Financial Stochastic MCP server running on stdio');
  }
}

const server = new FinancialStochasticMCPServer();
server.run().catch(console.error);