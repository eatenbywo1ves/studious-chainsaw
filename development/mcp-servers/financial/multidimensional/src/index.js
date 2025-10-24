#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as math from 'mathjs';

/**
 * MCP Server for Multidimensional Stochastic Processes
 * 
 * Provides tools for:
 * - Correlated Brownian motion simulation
 * - Cholesky decomposition for correlation matrices
 * - Multi-asset portfolio simulation
 * - Principal Component Analysis (PCA)
 * - Copula modeling
 */

class MultidimensionalStochasticServer {
  constructor() {
    this.server = new Server(
      {
        name: 'multidimensional-stochastic',
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
          name: 'simulate_correlated_gbm',
          description: 'Simulate multiple correlated Geometric Brownian Motions',
          inputSchema: {
            type: 'object',
            properties: {
              s0: {
                type: 'array',
                items: { type: 'number' },
                description: 'Initial values for each asset',
              },
              mu: {
                type: 'array',
                items: { type: 'number' },
                description: 'Drift coefficients',
              },
              sigma: {
                type: 'array',
                items: { type: 'number' },
                description: 'Volatility coefficients',
              },
              correlation: {
                type: 'array',
                items: {
                  type: 'array',
                  items: { type: 'number' },
                },
                description: 'Correlation matrix (n x n)',
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
            required: ['s0', 'mu', 'sigma', 'correlation', 'T', 'steps'],
          },
        },
        {
          name: 'cholesky_decomposition',
          description: 'Perform Cholesky decomposition of a correlation/covariance matrix',
          inputSchema: {
            type: 'object',
            properties: {
              matrix: {
                type: 'array',
                items: {
                  type: 'array',
                  items: { type: 'number' },
                },
                description: 'Symmetric positive-definite matrix',
              },
            },
            required: ['matrix'],
          },
        },
        {
          name: 'portfolio_var',
          description: 'Calculate portfolio Value-at-Risk (VaR) using Monte Carlo',
          inputSchema: {
            type: 'object',
            properties: {
              weights: {
                type: 'array',
                items: { type: 'number' },
                description: 'Portfolio weights (must sum to 1)',
              },
              returns: {
                type: 'array',
                items: {
                  type: 'array',
                  items: { type: 'number' },
                },
                description: 'Simulated returns for each asset [paths][assets]',
              },
              confidenceLevel: {
                type: 'number',
                description: 'Confidence level (e.g., 0.95 for 95%)',
                default: 0.95,
              },
            },
            required: ['weights', 'returns'],
          },
        },
        {
          name: 'pca_analysis',
          description: 'Perform Principal Component Analysis on correlation matrix',
          inputSchema: {
            type: 'object',
            properties: {
              correlation: {
                type: 'array',
                items: {
                  type: 'array',
                  items: { type: 'number' },
                },
                description: 'Correlation matrix',
              },
              numComponents: {
                type: 'number',
                description: 'Number of principal components to extract',
              },
            },
            required: ['correlation'],
          },
        },
        {
          name: 'generate_correlated_normals',
          description: 'Generate correlated normal random variables',
          inputSchema: {
            type: 'object',
            properties: {
              correlation: {
                type: 'array',
                items: {
                  type: 'array',
                  items: { type: 'number' },
                },
                description: 'Correlation matrix',
              },
              samples: {
                type: 'number',
                description: 'Number of samples to generate',
              },
            },
            required: ['correlation', 'samples'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'simulate_correlated_gbm':
          return await this.simulateCorrelatedGBM(request.params.arguments);
        case 'cholesky_decomposition':
          return await this.choleskyDecomposition(request.params.arguments);
        case 'portfolio_var':
          return await this.portfolioVaR(request.params.arguments);
        case 'pca_analysis':
          return await this.pcaAnalysis(request.params.arguments);
        case 'generate_correlated_normals':
          return await this.generateCorrelatedNormals(request.params.arguments);
        default:
          throw new Error(`Unknown tool: ${request.params.name}`);
      }
    });
  }

  boxMuller() {
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  }

  async choleskyDecomposition(args) {
    const { matrix } = args;
    
    try {
      const L = math.chol(matrix);
      
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              choleskyMatrix: L,
              originalMatrix: matrix,
              verification: math.multiply(L, math.transpose(L)),
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      throw new Error(`Cholesky decomposition failed: ${error.message}. Matrix must be symmetric positive-definite.`);
    }
  }

  async simulateCorrelatedGBM(args) {
    const { s0, mu, sigma, correlation, T, steps, paths = 1 } = args;

    const n = s0.length;
    const dt = T / steps;

    // Cholesky decomposition for correlation
    const L = math.chol(correlation);

    const results = [];

    for (let p = 0; p < paths; p++) {
      const assetPaths = s0.map(s => [s]);
      const S = [...s0];

      for (let t = 0; t < steps; t++) {
        // Generate independent normals
        const Z = Array(n).fill(0).map(() => this.boxMuller());
        
        // Apply correlation via Cholesky
        const correlatedZ = math.multiply(L, Z);

        // Update each asset
        for (let i = 0; i < n; i++) {
          const dW = correlatedZ[i] * Math.sqrt(dt);
          S[i] = S[i] * Math.exp((mu[i] - 0.5 * sigma[i] ** 2) * dt + sigma[i] * dW);
          assetPaths[i].push(S[i]);
        }
      }

      results.push({
        pathIndex: p,
        assetPaths: assetPaths,
        finalValues: S,
      });
    }

    const avgFinalValues = Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      avgFinalValues[i] = math.mean(results.map(r => r.finalValues[i]));
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Correlated GBM',
            parameters: { s0, mu, sigma, correlation, T, steps, paths },
            paths: results,
            statistics: {
              averageFinalValues: avgFinalValues,
              correlationMatrix: correlation,
            },
          }, null, 2),
        },
      ],
    };
  }

  async portfolioVaR(args) {
    const { weights, returns, confidenceLevel = 0.95 } = args;

    // Calculate portfolio returns
    const portfolioReturns = returns.map(pathReturns => {
      return pathReturns.reduce((sum, ret, i) => sum + ret * weights[i], 0);
    });

    // Sort returns
    portfolioReturns.sort((a, b) => a - b);

    // Calculate VaR
    const varIndex = Math.floor((1 - confidenceLevel) * portfolioReturns.length);
    const var95 = -portfolioReturns[varIndex];

    // Calculate CVaR (Expected Shortfall)
    const cvar = -math.mean(portfolioReturns.slice(0, varIndex));

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            valueAtRisk: var95,
            conditionalVaR: cvar,
            confidenceLevel: confidenceLevel,
            portfolioWeights: weights,
            statistics: {
              meanReturn: math.mean(portfolioReturns),
              stdReturn: math.std(portfolioReturns),
              minReturn: Math.min(...portfolioReturns),
              maxReturn: Math.max(...portfolioReturns),
            },
          }, null, 2),
        },
      ],
    };
  }

  async pcaAnalysis(args) {
    const { correlation, numComponents } = args;

    // Calculate eigenvalues and eigenvectors
    const eig = math.eigs(correlation);
    
    // Sort by eigenvalue (descending)
    const sorted = eig.values
      .map((val, i) => ({ value: val, vector: eig.vectors[i] }))
      .sort((a, b) => b.value - a.value);

    const totalVariance = math.sum(sorted.map(e => e.value));
    const explainedVariance = sorted.slice(0, numComponents || sorted.length)
      .map(e => e.value / totalVariance);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            eigenvalues: sorted.map(e => e.value),
            eigenvectors: sorted.map(e => e.vector),
            explainedVariance: explainedVariance,
            cumulativeVariance: explainedVariance.reduce((acc, v, i) => {
              acc.push((acc[i - 1] || 0) + v);
              return acc;
            }, []),
          }, null, 2),
        },
      ],
    };
  }

  async generateCorrelatedNormals(args) {
    const { correlation, samples } = args;

    const n = correlation.length;
    const L = math.chol(correlation);

    const correlatedSamples = [];

    for (let s = 0; s < samples; s++) {
      const Z = Array(n).fill(0).map(() => this.boxMuller());
      const correlatedZ = math.multiply(L, Z);
      correlatedSamples.push(correlatedZ);
    }

    // Calculate sample correlation
    const sampleMean = Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      sampleMean[i] = math.mean(correlatedSamples.map(s => s[i]));
    }

    const sampleCorr = Array(n).fill(0).map(() => Array(n).fill(0));
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        const cov = math.mean(
          correlatedSamples.map(s => (s[i] - sampleMean[i]) * (s[j] - sampleMean[j]))
        );
        const stdI = math.std(correlatedSamples.map(s => s[i]));
        const stdJ = math.std(correlatedSamples.map(s => s[j]));
        sampleCorr[i][j] = cov / (stdI * stdJ);
      }
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            samples: correlatedSamples,
            targetCorrelation: correlation,
            sampleCorrelation: sampleCorr,
            sampleMean: sampleMean,
          }, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Multidimensional Stochastic MCP server running on stdio');
  }
}

const server = new MultidimensionalStochasticServer();
server.run().catch(console.error);
