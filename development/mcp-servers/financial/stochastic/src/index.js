#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as math from 'mathjs';

/**
 * MCP Server for Stochastic Calculus and Process Simulations
 * 
 * Provides tools for:
 * - Geometric Brownian Motion (GBM) simulation
 * - Ornstein-Uhlenbeck process
 * - Heston stochastic volatility model
 * - Cox-Ingersoll-Ross (CIR) process
 * - Jump-diffusion processes (Merton model)
 */

class FinancialStochasticServer {
  constructor() {
    this.server = new Server(
      {
        name: 'financial-stochastic',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    
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
          name: 'simulate_gbm',
          description: 'Simulate Geometric Brownian Motion: dS = μS dt + σS dW',
          inputSchema: {
            type: 'object',
            properties: {
              s0: {
                type: 'number',
                description: 'Initial value',
              },
              mu: {
                type: 'number',
                description: 'Drift coefficient',
              },
              sigma: {
                type: 'number',
                description: 'Volatility coefficient',
              },
              T: {
                type: 'number',
                description: 'Time horizon',
              },
              steps: {
                type: 'number',
                description: 'Number of time steps',
              },
              paths: {
                type: 'number',
                description: 'Number of simulation paths',
                default: 1,
              },
              seed: {
                type: 'number',
                description: 'Random seed for reproducibility',
              },
            },
            required: ['s0', 'mu', 'sigma', 'T', 'steps'],
          },
        },
        {
          name: 'simulate_ornstein_uhlenbeck',
          description: 'Simulate Ornstein-Uhlenbeck process: dX = θ(μ - X)dt + σ dW',
          inputSchema: {
            type: 'object',
            properties: {
              x0: {
                type: 'number',
                description: 'Initial value',
              },
              theta: {
                type: 'number',
                description: 'Mean reversion speed',
              },
              mu: {
                type: 'number',
                description: 'Long-term mean',
              },
              sigma: {
                type: 'number',
                description: 'Volatility',
              },
              T: {
                type: 'number',
                description: 'Time horizon',
              },
              steps: {
                type: 'number',
                description: 'Number of time steps',
              },
              paths: {
                type: 'number',
                description: 'Number of simulation paths',
                default: 1,
              },
            },
            required: ['x0', 'theta', 'mu', 'sigma', 'T', 'steps'],
          },
        },
        {
          name: 'simulate_heston',
          description: 'Simulate Heston stochastic volatility model',
          inputSchema: {
            type: 'object',
            properties: {
              s0: {
                type: 'number',
                description: 'Initial asset price',
              },
              v0: {
                type: 'number',
                description: 'Initial variance',
              },
              mu: {
                type: 'number',
                description: 'Asset drift',
              },
              kappa: {
                type: 'number',
                description: 'Variance mean reversion speed',
              },
              theta: {
                type: 'number',
                description: 'Long-term variance',
              },
              sigma: {
                type: 'number',
                description: 'Volatility of volatility',
              },
              rho: {
                type: 'number',
                description: 'Correlation between asset and variance',
              },
              T: {
                type: 'number',
                description: 'Time horizon',
              },
              steps: {
                type: 'number',
                description: 'Number of time steps',
              },
              paths: {
                type: 'number',
                description: 'Number of simulation paths',
                default: 1,
              },
            },
            required: ['s0', 'v0', 'mu', 'kappa', 'theta', 'sigma', 'rho', 'T', 'steps'],
          },
        },
        {
          name: 'simulate_cir',
          description: 'Simulate Cox-Ingersoll-Ross process: dX = κ(θ - X)dt + σ√X dW',
          inputSchema: {
            type: 'object',
            properties: {
              x0: {
                type: 'number',
                description: 'Initial value',
              },
              kappa: {
                type: 'number',
                description: 'Mean reversion speed',
              },
              theta: {
                type: 'number',
                description: 'Long-term mean',
              },
              sigma: {
                type: 'number',
                description: 'Volatility coefficient',
              },
              T: {
                type: 'number',
                description: 'Time horizon',
              },
              steps: {
                type: 'number',
                description: 'Number of time steps',
              },
              paths: {
                type: 'number',
                description: 'Number of simulation paths',
                default: 1,
              },
            },
            required: ['x0', 'kappa', 'theta', 'sigma', 'T', 'steps'],
          },
        },
        {
          name: 'simulate_jump_diffusion',
          description: 'Simulate Merton jump-diffusion model',
          inputSchema: {
            type: 'object',
            properties: {
              s0: {
                type: 'number',
                description: 'Initial asset price',
              },
              mu: {
                type: 'number',
                description: 'Drift coefficient',
              },
              sigma: {
                type: 'number',
                description: 'Diffusion volatility',
              },
              lambda: {
                type: 'number',
                description: 'Jump intensity (jumps per year)',
              },
              jumpMean: {
                type: 'number',
                description: 'Mean of jump size (log-normal)',
              },
              jumpStd: {
                type: 'number',
                description: 'Std dev of jump size',
              },
              T: {
                type: 'number',
                description: 'Time horizon',
              },
              steps: {
                type: 'number',
                description: 'Number of time steps',
              },
              paths: {
                type: 'number',
                description: 'Number of simulation paths',
                default: 1,
              },
            },
            required: ['s0', 'mu', 'sigma', 'lambda', 'jumpMean', 'jumpStd', 'T', 'steps'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'simulate_gbm':
          return await this.simulateGBM(request.params.arguments);
        case 'simulate_ornstein_uhlenbeck':
          return await this.simulateOU(request.params.arguments);
        case 'simulate_heston':
          return await this.simulateHeston(request.params.arguments);
        case 'simulate_cir':
          return await this.simulateCIR(request.params.arguments);
        case 'simulate_jump_diffusion':
          return await this.simulateJumpDiffusion(request.params.arguments);
        default:
          throw new Error(`Unknown tool: ${request.params.name}`);
      }
    });
  }

  // Box-Muller transform for generating normal random variables
  boxMuller() {
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  }

  async simulateGBM(args) {
    const { s0, mu, sigma, T, steps, paths = 1, seed } = args;
    
    if (seed !== undefined) {
      math.randomSeed(seed);
    }

    const dt = T / steps;
    const results = [];

    for (let p = 0; p < paths; p++) {
      const path = [s0];
      let S = s0;

      for (let i = 0; i < steps; i++) {
        const dW = this.boxMuller() * Math.sqrt(dt);
        S = S * Math.exp((mu - 0.5 * sigma ** 2) * dt + sigma * dW);
        path.push(S);
      }

      results.push({
        pathIndex: p,
        values: path,
        finalValue: S,
      });
    }

    const finalValues = results.map(r => r.finalValue);
    const meanFinal = math.mean(finalValues);
    const stdFinal = math.std(finalValues);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Geometric Brownian Motion',
            parameters: { s0, mu, sigma, T, steps, paths },
            paths: results,
            statistics: {
              meanFinalValue: meanFinal,
              stdFinalValue: stdFinal,
              theoreticalMean: s0 * Math.exp(mu * T),
              theoreticalStd: s0 * Math.exp(mu * T) * Math.sqrt(Math.exp(sigma ** 2 * T) - 1),
            },
          }, null, 2),
        },
      ],
    };
  }

  async simulateOU(args) {
    const { x0, theta, mu, sigma, T, steps, paths = 1 } = args;

    const dt = T / steps;
    const results = [];

    for (let p = 0; p < paths; p++) {
      const path = [x0];
      let X = x0;

      for (let i = 0; i < steps; i++) {
        const dW = this.boxMuller() * Math.sqrt(dt);
        X = X + theta * (mu - X) * dt + sigma * dW;
        path.push(X);
      }

      results.push({
        pathIndex: p,
        values: path,
        finalValue: X,
      });
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Ornstein-Uhlenbeck Process',
            parameters: { x0, theta, mu, sigma, T, steps, paths },
            paths: results,
            statistics: {
              meanFinalValue: math.mean(results.map(r => r.finalValue)),
              longTermMean: mu,
              halfLife: Math.log(2) / theta,
            },
          }, null, 2),
        },
      ],
    };
  }

  async simulateHeston(args) {
    const { s0, v0, mu, kappa, theta, sigma, rho, T, steps, paths = 1 } = args;

    const dt = T / steps;
    const results = [];

    for (let p = 0; p < paths; p++) {
      const pricePath = [s0];
      const variancePath = [v0];
      let S = s0;
      let V = v0;

      for (let i = 0; i < steps; i++) {
        const Z1 = this.boxMuller();
        const Z2 = this.boxMuller();
        
        // Correlated Brownian motions
        const dW1 = Z1 * Math.sqrt(dt);
        const dW2 = (rho * Z1 + Math.sqrt(1 - rho ** 2) * Z2) * Math.sqrt(dt);

        // Update variance (with Feller condition check)
        const Vplus = Math.max(V, 0);
        V = V + kappa * (theta - Vplus) * dt + sigma * Math.sqrt(Vplus) * dW2;

        // Update price
        S = S * Math.exp((mu - 0.5 * Vplus) * dt + Math.sqrt(Vplus) * dW1);

        pricePath.push(S);
        variancePath.push(V);
      }

      results.push({
        pathIndex: p,
        priceValues: pricePath,
        varianceValues: variancePath,
        finalPrice: S,
        finalVariance: V,
      });
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Heston Stochastic Volatility',
            parameters: { s0, v0, mu, kappa, theta, sigma, rho, T, steps, paths },
            paths: results,
            statistics: {
              meanFinalPrice: math.mean(results.map(r => r.finalPrice)),
              meanFinalVariance: math.mean(results.map(r => r.finalVariance)),
              longTermVariance: theta,
              fellerCondition: 2 * kappa * theta > sigma ** 2,
            },
          }, null, 2),
        },
      ],
    };
  }

  async simulateCIR(args) {
    const { x0, kappa, theta, sigma, T, steps, paths = 1 } = args;

    const dt = T / steps;
    const results = [];

    for (let p = 0; p < paths; p++) {
      const path = [x0];
      let X = x0;

      for (let i = 0; i < steps; i++) {
        const dW = this.boxMuller() * Math.sqrt(dt);
        const Xplus = Math.max(X, 0);
        X = X + kappa * (theta - X) * dt + sigma * Math.sqrt(Xplus) * dW;
        path.push(X);
      }

      results.push({
        pathIndex: p,
        values: path,
        finalValue: X,
      });
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Cox-Ingersoll-Ross Process',
            parameters: { x0, kappa, theta, sigma, T, steps, paths },
            paths: results,
            statistics: {
              meanFinalValue: math.mean(results.map(r => r.finalValue)),
              longTermMean: theta,
              fellerCondition: 2 * kappa * theta > sigma ** 2,
              fellerSatisfied: 2 * kappa * theta > sigma ** 2,
            },
          }, null, 2),
        },
      ],
    };
  }

  async simulateJumpDiffusion(args) {
    const { s0, mu, sigma, lambda, jumpMean, jumpStd, T, steps, paths = 1 } = args;

    const dt = T / steps;
    const results = [];

    for (let p = 0; p < paths; p++) {
      const path = [s0];
      let S = s0;
      let jumpCount = 0;

      for (let i = 0; i < steps; i++) {
        // Diffusion component
        const dW = this.boxMuller() * Math.sqrt(dt);
        
        // Jump component (Poisson process)
        const jumpProb = lambda * dt;
        const hasJump = Math.random() < jumpProb;
        let jumpSize = 0;
        
        if (hasJump) {
          jumpCount++;
          const Z = this.boxMuller();
          jumpSize = Math.exp(jumpMean + jumpStd * Z) - 1;
        }

        // Combined dynamics
        S = S * Math.exp((mu - 0.5 * sigma ** 2) * dt + sigma * dW) * (1 + jumpSize);
        path.push(S);
      }

      results.push({
        pathIndex: p,
        values: path,
        finalValue: S,
        jumpCount: jumpCount,
      });
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Merton Jump-Diffusion',
            parameters: { s0, mu, sigma, lambda, jumpMean, jumpStd, T, steps, paths },
            paths: results,
            statistics: {
              meanFinalValue: math.mean(results.map(r => r.finalValue)),
              averageJumps: math.mean(results.map(r => r.jumpCount)),
              expectedJumps: lambda * T,
            },
          }, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Financial Stochastic MCP server running on stdio');
  }
}

const server = new FinancialStochasticServer();
server.run().catch(console.error);
