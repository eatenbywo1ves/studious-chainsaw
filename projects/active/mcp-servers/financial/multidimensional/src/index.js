#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

class MultidimensionalStochasticGenerator {
  // Box-Muller transformation for normal random variables
  static boxMuller() {
    let u = 0, v = 0;
    while(u === 0) u = Math.random();
    while(v === 0) v = Math.random();
    return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
  }

  // Generate correlated random variables using Cholesky decomposition
  static generateCorrelatedRandoms(correlationMatrix, numVariables) {
    const Z = [];
    for (let i = 0; i < numVariables; i++) {
      Z.push(this.boxMuller());
    }

    // Simple 2D/3D correlation implementation
    const result = [...Z];
    
    if (numVariables >= 2 && correlationMatrix.rho_xy !== undefined) {
      result[1] = correlationMatrix.rho_xy * Z[0] + Math.sqrt(1 - correlationMatrix.rho_xy ** 2) * Z[1];
    }
    
    if (numVariables >= 3) {
      const rho_xz = correlationMatrix.rho_xz || 0;
      const rho_yz = correlationMatrix.rho_yz || 0;
      const rho_xy = correlationMatrix.rho_xy || 0;
      
      // Cholesky decomposition for 3D case
      const L21 = rho_xy;
      const L31 = rho_xz;
      const L32 = (rho_yz - rho_xy * rho_xz) / Math.sqrt(1 - rho_xy ** 2);
      const L33 = Math.sqrt(1 - rho_xz ** 2 - L32 ** 2);
      
      result[2] = L31 * Z[0] + L32 * Z[1] + L33 * Z[2];
    }
    
    return result;
  }

  static generateMultiGBM(steps, timeHorizon, assets) {
    const dt = timeHorizon / steps;
    const numAssets = assets.length;
    const path = [];
    
    // Initialize with starting prices
    const initialPoint = { time: 0, step: 0 };
    for (let i = 0; i < numAssets; i++) {
      initialPoint[`asset_${i}`] = assets[i].initialPrice || 100;
      initialPoint[`logPrice_${i}`] = Math.log(assets[i].initialPrice || 100);
    }
    path.push(initialPoint);
    
    // Current prices
    const prices = assets.map(asset => asset.initialPrice || 100);
    
    for (let step = 1; step <= steps; step++) {
      const correlatedRandoms = this.generateCorrelatedRandoms(
        assets[0].correlations || {}, 
        numAssets
      );
      
      const point = { time: step * dt, step };
      
      for (let i = 0; i < numAssets; i++) {
        const asset = assets[i];
        const dW = Math.sqrt(dt) * correlatedRandoms[i];
        
        prices[i] *= Math.exp(
          (asset.mu - 0.5 * asset.sigma ** 2) * dt + asset.sigma * dW
        );
        
        point[`asset_${i}`] = prices[i];
        point[`logPrice_${i}`] = Math.log(prices[i]);
      }
      
      path.push(point);
    }
    
    return path;
  }

  static generateMultiOU(steps, timeHorizon, processes) {
    const dt = timeHorizon / steps;
    const numProcesses = processes.length;
    const path = [];
    
    // Initialize with starting values
    const initialPoint = { time: 0, step: 0 };
    for (let i = 0; i < numProcesses; i++) {
      initialPoint[`process_${i}`] = processes[i].initialValue || 0;
    }
    path.push(initialPoint);
    
    // Current values
    const values = processes.map(proc => proc.initialValue || 0);
    
    for (let step = 1; step <= steps; step++) {
      const correlatedRandoms = this.generateCorrelatedRandoms(
        processes[0].correlations || {}, 
        numProcesses
      );
      
      const point = { time: step * dt, step };
      
      for (let i = 0; i < numProcesses; i++) {
        const proc = processes[i];
        const dW = Math.sqrt(dt) * correlatedRandoms[i];
        
        values[i] += proc.kappa * (proc.theta - values[i]) * dt + proc.sigma * dW;
        point[`process_${i}`] = values[i];
      }
      
      path.push(point);
    }
    
    return path;
  }

  static generateMultiHeston(steps, timeHorizon, assets) {
    const dt = timeHorizon / steps;
    const numAssets = assets.length;
    const path = [];
    
    // Initialize
    const initialPoint = { time: 0, step: 0 };
    for (let i = 0; i < numAssets; i++) {
      initialPoint[`asset_${i}`] = assets[i].initialPrice || 100;
      initialPoint[`variance_${i}`] = assets[i].initialVar || 0.04;
      initialPoint[`volatility_${i}`] = Math.sqrt(assets[i].initialVar || 0.04);
    }
    path.push(initialPoint);
    
    // Current values
    const prices = assets.map(asset => asset.initialPrice || 100);
    const variances = assets.map(asset => asset.initialVar || 0.04);
    
    for (let step = 1; step <= steps; step++) {
      const point = { time: step * dt, step };
      
      for (let i = 0; i < numAssets; i++) {
        const asset = assets[i];
        
        // Generate correlated randoms for price and variance
        const Z1 = this.boxMuller();
        const Z2 = this.boxMuller();
        
        const dW1 = Math.sqrt(dt) * Z1;
        const dW2 = Math.sqrt(dt) * (asset.rho * Z1 + Math.sqrt(1 - asset.rho ** 2) * Z2);
        
        // Update variance
        const newVar = variances[i] + asset.kappa * (asset.theta - variances[i]) * dt + 
                      asset.xi * Math.sqrt(Math.max(variances[i], 0)) * dW2;
        variances[i] = Math.max(newVar, 0);
        
        // Update price
        prices[i] *= Math.exp(
          (asset.mu - 0.5 * variances[i]) * dt + Math.sqrt(variances[i]) * dW1
        );
        
        point[`asset_${i}`] = prices[i];
        point[`variance_${i}`] = variances[i];
        point[`volatility_${i}`] = Math.sqrt(variances[i]);
      }
      
      path.push(point);
    }
    
    return path;
  }

  static calculatePortfolioMetrics(path, weights) {
    if (path.length < 2 || !weights || weights.length === 0) return {};

    const portfolioPath = [];
    const numAssets = weights.length;
    
    // Calculate portfolio values over time
    for (const point of path) {
      let portfolioValue = 0;
      for (let i = 0; i < numAssets; i++) {
        const assetValue = point[`asset_${i}`] || point[`process_${i}`] || 0;
        portfolioValue += weights[i] * assetValue;
      }
      portfolioPath.push({ time: point.time, value: portfolioValue, step: point.step });
    }

    // Calculate returns
    const returns = [];
    for (let i = 1; i < portfolioPath.length; i++) {
      returns.push(Math.log(portfolioPath[i].value / portfolioPath[i-1].value));
    }

    if (returns.length === 0) return { portfolioPath };

    // Portfolio statistics
    const meanReturn = returns.reduce((sum, ret) => sum + ret, 0) / returns.length;
    const variance = returns.reduce((sum, ret) => sum + (ret - meanReturn) ** 2, 0) / (returns.length - 1);
    const volatility = Math.sqrt(variance);

    // VaR calculation
    const sortedReturns = [...returns].sort((a, b) => a - b);
    const varIndex = Math.floor(0.05 * returns.length);
    const var95 = sortedReturns[varIndex];
    
    // Expected Shortfall
    const tailReturns = sortedReturns.slice(0, varIndex + 1);
    const expectedShortfall = tailReturns.reduce((sum, ret) => sum + ret, 0) / tailReturns.length;

    // Maximum drawdown
    let peak = portfolioPath[0].value;
    let maxDrawdown = 0;
    
    for (const point of portfolioPath) {
      if (point.value > peak) peak = point.value;
      const drawdown = (peak - point.value) / peak;
      if (drawdown > maxDrawdown) maxDrawdown = drawdown;
    }

    // Asset correlations (if multiple assets)
    const correlations = {};
    if (numAssets > 1) {
      for (let i = 0; i < numAssets; i++) {
        for (let j = i + 1; j < numAssets; j++) {
          const returns_i = [];
          const returns_j = [];
          
          for (let k = 1; k < path.length; k++) {
            const value_i = path[k][`asset_${i}`] || path[k][`process_${i}`] || 0;
            const prevValue_i = path[k-1][`asset_${i}`] || path[k-1][`process_${i}`] || 0;
            const value_j = path[k][`asset_${j}`] || path[k][`process_${j}`] || 0;
            const prevValue_j = path[k-1][`asset_${j}`] || path[k-1][`process_${j}`] || 0;
            
            if (value_i > 0 && prevValue_i > 0) returns_i.push(Math.log(value_i / prevValue_i));
            if (value_j > 0 && prevValue_j > 0) returns_j.push(Math.log(value_j / prevValue_j));
          }
          
          if (returns_i.length === returns_j.length && returns_i.length > 1) {
            const mean_i = returns_i.reduce((sum, ret) => sum + ret, 0) / returns_i.length;
            const mean_j = returns_j.reduce((sum, ret) => sum + ret, 0) / returns_j.length;
            
            let covariance = 0;
            let variance_i = 0;
            let variance_j = 0;
            
            for (let k = 0; k < returns_i.length; k++) {
              const dev_i = returns_i[k] - mean_i;
              const dev_j = returns_j[k] - mean_j;
              covariance += dev_i * dev_j;
              variance_i += dev_i ** 2;
              variance_j += dev_j ** 2;
            }
            
            const correlation = covariance / Math.sqrt(variance_i * variance_j);
            correlations[`asset_${i}_${j}`] = correlation;
          }
        }
      }
    }

    return {
      portfolioPath,
      meanReturn: meanReturn * 252, // Annualized
      volatility: volatility * Math.sqrt(252), // Annualized
      sharpeRatio: (meanReturn * Math.sqrt(252)) / (volatility * Math.sqrt(252)),
      valueAtRisk: var95,
      expectedShortfall,
      maxDrawdown,
      totalReturn: portfolioPath[portfolioPath.length - 1].value / portfolioPath[0].value - 1,
      correlations,
      diversificationRatio: this.calculateDiversificationRatio(weights, correlations)
    };
  }

  static calculateDiversificationRatio(weights, correlations) {
    if (!weights || weights.length <= 1) return 1;
    
    // Simplified diversification ratio calculation
    const weightedAvgVol = weights.reduce((sum, w) => sum + w, 0) / weights.length;
    const numAssets = weights.length;
    
    // Estimate based on number of assets and average correlations
    const avgCorrelation = Object.values(correlations).reduce((sum, corr) => sum + Math.abs(corr), 0) / Object.keys(correlations).length || 0;
    const effectiveNumAssets = numAssets / (1 + (numAssets - 1) * avgCorrelation);
    
    return Math.sqrt(effectiveNumAssets) / Math.sqrt(numAssets);
  }
}

class MultidimensionalStochasticMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'multidimensional-stochastic-mcp',
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
          name: 'generate_multi_gbm',
          description: 'Generate multiple correlated Geometric Brownian Motion paths',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              assets: {
                type: 'array',
                description: 'Array of asset specifications',
                items: {
                  type: 'object',
                  properties: {
                    mu: { type: 'number', description: 'Drift rate', default: 0.05 },
                    sigma: { type: 'number', description: 'Volatility', default: 0.2 },
                    initialPrice: { type: 'number', description: 'Initial price', default: 100 }
                  }
                }
              },
              correlations: {
                type: 'object',
                description: 'Correlation structure',
                properties: {
                  rho_xy: { type: 'number', description: 'Correlation between first two assets' },
                  rho_xz: { type: 'number', description: 'Correlation between first and third assets' },
                  rho_yz: { type: 'number', description: 'Correlation between second and third assets' }
                }
              }
            },
            required: ['steps', 'timeHorizon', 'assets']
          }
        },
        {
          name: 'generate_multi_ou',
          description: 'Generate multiple correlated Ornstein-Uhlenbeck processes',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              processes: {
                type: 'array',
                description: 'Array of OU process specifications',
                items: {
                  type: 'object',
                  properties: {
                    kappa: { type: 'number', description: 'Mean reversion speed', default: 2.0 },
                    theta: { type: 'number', description: 'Long-term mean', default: 0.04 },
                    sigma: { type: 'number', description: 'Volatility', default: 0.2 },
                    initialValue: { type: 'number', description: 'Initial value', default: 0 }
                  }
                }
              },
              correlations: {
                type: 'object',
                description: 'Correlation structure',
                properties: {
                  rho_xy: { type: 'number' },
                  rho_xz: { type: 'number' },
                  rho_yz: { type: 'number' }
                }
              }
            },
            required: ['steps', 'timeHorizon', 'processes']
          }
        },
        {
          name: 'generate_multi_heston',
          description: 'Generate multiple Heston stochastic volatility model paths',
          inputSchema: {
            type: 'object',
            properties: {
              steps: { type: 'number', description: 'Number of time steps', default: 1000 },
              timeHorizon: { type: 'number', description: 'Time horizon in years', default: 1.0 },
              assets: {
                type: 'array',
                description: 'Array of Heston model specifications',
                items: {
                  type: 'object',
                  properties: {
                    mu: { type: 'number', description: 'Drift rate', default: 0.05 },
                    kappa: { type: 'number', description: 'Vol mean reversion speed', default: 2.0 },
                    theta: { type: 'number', description: 'Long-term variance', default: 0.04 },
                    xi: { type: 'number', description: 'Vol of vol', default: 0.1 },
                    rho: { type: 'number', description: 'Price-vol correlation', default: -0.7 },
                    initialPrice: { type: 'number', description: 'Initial price', default: 100 },
                    initialVar: { type: 'number', description: 'Initial variance', default: 0.04 }
                  }
                }
              }
            },
            required: ['steps', 'timeHorizon', 'assets']
          }
        },
        {
          name: 'calculate_portfolio_metrics',
          description: 'Calculate comprehensive portfolio metrics from multidimensional path',
          inputSchema: {
            type: 'object',
            properties: {
              path: {
                type: 'array',
                description: 'Multidimensional path data',
                items: { type: 'object' }
              },
              weights: {
                type: 'array',
                description: 'Portfolio weights for each asset/process',
                items: { type: 'number' }
              }
            },
            required: ['path', 'weights']
          }
        },
        {
          name: 'analyze_correlations',
          description: 'Analyze correlation structure in multidimensional data',
          inputSchema: {
            type: 'object',
            properties: {
              path: {
                type: 'array',
                description: 'Multidimensional path data',
                items: { type: 'object' }
              },
              numAssets: { type: 'number', description: 'Number of assets to analyze', default: 2 }
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
          case 'generate_multi_gbm':
            // Add correlations to first asset for compatibility
            if (args.correlations && args.assets && args.assets.length > 0) {
              args.assets[0].correlations = args.correlations;
            }
            
            const multiGBMPath = MultidimensionalStochasticGenerator.generateMultiGBM(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.assets || []
            );
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'multi_geometric_brownian_motion',
                  parameters: args,
                  path: multiGBMPath.slice(0, 100), // Limit output size
                  summary: {
                    totalSteps: multiGBMPath.length,
                    numAssets: args.assets?.length || 0,
                    finalValues: multiGBMPath[multiGBMPath.length - 1]
                  }
                }, null, 2)
              }]
            };

          case 'generate_multi_ou':
            // Add correlations to first process for compatibility
            if (args.correlations && args.processes && args.processes.length > 0) {
              args.processes[0].correlations = args.correlations;
            }
            
            const multiOUPath = MultidimensionalStochasticGenerator.generateMultiOU(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.processes || []
            );
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'multi_ornstein_uhlenbeck',
                  parameters: args,
                  path: multiOUPath.slice(0, 100), // Limit output size
                  summary: {
                    totalSteps: multiOUPath.length,
                    numProcesses: args.processes?.length || 0,
                    finalValues: multiOUPath[multiOUPath.length - 1]
                  }
                }, null, 2)
              }]
            };

          case 'generate_multi_heston':
            const multiHestonPath = MultidimensionalStochasticGenerator.generateMultiHeston(
              args.steps || 1000,
              args.timeHorizon || 1.0,
              args.assets || []
            );
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  model: 'multi_heston_stochastic_volatility',
                  parameters: args,
                  path: multiHestonPath.slice(0, 100), // Limit output size
                  summary: {
                    totalSteps: multiHestonPath.length,
                    numAssets: args.assets?.length || 0,
                    finalValues: multiHestonPath[multiHestonPath.length - 1]
                  }
                }, null, 2)
              }]
            };

          case 'calculate_portfolio_metrics':
            const portfolioMetrics = MultidimensionalStochasticGenerator.calculatePortfolioMetrics(
              args.path,
              args.weights
            );
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  ...portfolioMetrics,
                  portfolioPath: portfolioMetrics.portfolioPath?.slice(0, 100) // Limit output size
                }, null, 2)
              }]
            };

          case 'analyze_correlations':
            const numAssets = args.numAssets || 2;
            const correlationAnalysis = {};
            
            if (args.path && args.path.length > 1) {
              // Calculate pairwise correlations
              for (let i = 0; i < numAssets; i++) {
                for (let j = i + 1; j < numAssets; j++) {
                  const returns_i = [];
                  const returns_j = [];
                  
                  for (let k = 1; k < args.path.length; k++) {
                    const value_i = args.path[k][`asset_${i}`] || args.path[k][`process_${i}`] || 0;
                    const prevValue_i = args.path[k-1][`asset_${i}`] || args.path[k-1][`process_${i}`] || 0;
                    const value_j = args.path[k][`asset_${j}`] || args.path[k][`process_${j}`] || 0;
                    const prevValue_j = args.path[k-1][`asset_${j}`] || args.path[k-1][`process_${j}`] || 0;
                    
                    if (value_i > 0 && prevValue_i > 0) returns_i.push(Math.log(value_i / prevValue_i));
                    if (value_j > 0 && prevValue_j > 0) returns_j.push(Math.log(value_j / prevValue_j));
                  }
                  
                  if (returns_i.length === returns_j.length && returns_i.length > 1) {
                    const mean_i = returns_i.reduce((sum, ret) => sum + ret, 0) / returns_i.length;
                    const mean_j = returns_j.reduce((sum, ret) => sum + ret, 0) / returns_j.length;
                    
                    let covariance = 0;
                    let variance_i = 0;
                    let variance_j = 0;
                    
                    for (let k = 0; k < returns_i.length; k++) {
                      const dev_i = returns_i[k] - mean_i;
                      const dev_j = returns_j[k] - mean_j;
                      covariance += dev_i * dev_j;
                      variance_i += dev_i ** 2;
                      variance_j += dev_j ** 2;
                    }
                    
                    const correlation = covariance / Math.sqrt(variance_i * variance_j);
                    correlationAnalysis[`correlation_${i}_${j}`] = correlation;
                  }
                }
              }
            }
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(correlationAnalysis, null, 2)
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
    console.error('Multidimensional Stochastic MCP server running on stdio');
  }
}

const server = new MultidimensionalStochasticMCPServer();
server.run().catch(console.error);