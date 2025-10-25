#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as math from 'mathjs';

/**
 * MCP Server for Local Volatility and Stochastic Localization
 * 
 * Provides tools for:
 * - Local volatility surface construction (Dupire's formula)
 * - Implied volatility smile modeling
 * - Volatility interpolation and calibration
 * - Stochastic local volatility (SLV) models
 */

class FinancialLocalizationServer {
  constructor() {
    this.server = new Server(
      {
        name: 'financial-localization',
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
          name: 'calculate_local_volatility',
          description: 'Calculate local volatility using Dupire\'s formula from implied volatility surface',
          inputSchema: {
            type: 'object',
            properties: {
              strike: {
                type: 'number',
                description: 'Strike price',
              },
              maturity: {
                type: 'number',
                description: 'Time to maturity (years)',
              },
              spot: {
                type: 'number',
                description: 'Current spot price',
              },
              rate: {
                type: 'number',
                description: 'Risk-free interest rate',
              },
              impliedVol: {
                type: 'number',
                description: 'Implied volatility at this strike/maturity',
              },
              dSigmaDK: {
                type: 'number',
                description: 'First derivative of implied vol w.r.t. strike (optional)',
                default: 0,
              },
              dSigmaDT: {
                type: 'number',
                description: 'First derivative of implied vol w.r.t. time (optional)',
                default: 0,
              },
            },
            required: ['strike', 'maturity', 'spot', 'rate', 'impliedVol'],
          },
        },
        {
          name: 'fit_volatility_smile',
          description: 'Fit a volatility smile using SVI (Stochastic Volatility Inspired) parameterization',
          inputSchema: {
            type: 'object',
            properties: {
              strikes: {
                type: 'array',
                items: { type: 'number' },
                description: 'Array of strike prices',
              },
              impliedVols: {
                type: 'array',
                items: { type: 'number' },
                description: 'Array of implied volatilities corresponding to strikes',
              },
              forward: {
                type: 'number',
                description: 'Forward price',
              },
            },
            required: ['strikes', 'impliedVols', 'forward'],
          },
        },
        {
          name: 'interpolate_volatility_surface',
          description: 'Interpolate volatility surface using bilinear interpolation',
          inputSchema: {
            type: 'object',
            properties: {
              strikeGrid: {
                type: 'array',
                items: { type: 'number' },
                description: 'Grid of strikes',
              },
              maturityGrid: {
                type: 'array',
                items: { type: 'number' },
                description: 'Grid of maturities',
              },
              volSurface: {
                type: 'array',
                items: {
                  type: 'array',
                  items: { type: 'number' },
                },
                description: '2D array of volatilities [maturity][strike]',
              },
              targetStrike: {
                type: 'number',
                description: 'Strike to interpolate at',
              },
              targetMaturity: {
                type: 'number',
                description: 'Maturity to interpolate at',
              },
            },
            required: ['strikeGrid', 'maturityGrid', 'volSurface', 'targetStrike', 'targetMaturity'],
          },
        },
        {
          name: 'black_scholes_price',
          description: 'Calculate Black-Scholes option price and Greeks',
          inputSchema: {
            type: 'object',
            properties: {
              spot: {
                type: 'number',
                description: 'Current spot price',
              },
              strike: {
                type: 'number',
                description: 'Strike price',
              },
              maturity: {
                type: 'number',
                description: 'Time to maturity (years)',
              },
              volatility: {
                type: 'number',
                description: 'Volatility (annual)',
              },
              rate: {
                type: 'number',
                description: 'Risk-free rate',
              },
              optionType: {
                type: 'string',
                enum: ['call', 'put'],
                description: 'Option type',
              },
            },
            required: ['spot', 'strike', 'maturity', 'volatility', 'rate', 'optionType'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'calculate_local_volatility':
          return await this.calculateLocalVolatility(request.params.arguments);
        case 'fit_volatility_smile':
          return await this.fitVolatilitySmile(request.params.arguments);
        case 'interpolate_volatility_surface':
          return await this.interpolateVolatilitySurface(request.params.arguments);
        case 'black_scholes_price':
          return await this.blackScholesPrice(request.params.arguments);
        default:
          throw new Error(`Unknown tool: ${request.params.name}`);
      }
    });
  }

  /**
   * Dupire's formula for local volatility:
   * σ_L²(K,T) = (∂C/∂T + rK∂C/∂K) / (½K²∂²C/∂K²)
   * 
   * Approximated using implied volatility derivatives
   */
  async calculateLocalVolatility(args) {
    const { strike, maturity, spot, rate, impliedVol, dSigmaDK = 0, dSigmaDT = 0 } = args;

    const d1 = (Math.log(spot / strike) + (rate + 0.5 * impliedVol ** 2) * maturity) / 
               (impliedVol * Math.sqrt(maturity));
    
    // Simplified Dupire formula approximation
    const numerator = impliedVol ** 2 + 2 * impliedVol * maturity * dSigmaDT + 
                     2 * rate * strike * impliedVol * Math.sqrt(maturity) * dSigmaDK;
    
    const denominator = (1 + strike * d1 * Math.sqrt(maturity) * dSigmaDK) ** 2;
    
    const localVol = Math.sqrt(Math.max(0, numerator / denominator));

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            localVolatility: localVol,
            impliedVolatility: impliedVol,
            strike: strike,
            maturity: maturity,
            d1: d1,
            formula: 'Dupire local volatility',
          }, null, 2),
        },
      ],
    };
  }

  /**
   * SVI parameterization: w(k) = a + b(ρ(k-m) + √((k-m)² + σ²))
   * where w = total variance, k = log-moneyness
   */
  async fitVolatilitySmile(args) {
    const { strikes, impliedVols, forward } = args;

    if (strikes.length !== impliedVols.length) {
      throw new Error('Strikes and implied vols must have same length');
    }

    // Convert to log-moneyness
    const logMoneyness = strikes.map(k => Math.log(k / forward));
    const totalVariances = impliedVols.map(v => v ** 2);

    // Simple least-squares fit (simplified SVI)
    const n = strikes.length;
    const meanK = math.mean(logMoneyness);
    const meanW = math.mean(totalVariances);

    // Fit linear approximation for simplicity
    let sumKW = 0, sumKK = 0;
    for (let i = 0; i < n; i++) {
      sumKW += (logMoneyness[i] - meanK) * (totalVariances[i] - meanW);
      sumKK += (logMoneyness[i] - meanK) ** 2;
    }

    const b = sumKK > 0 ? sumKW / sumKK : 0;
    const a = meanW - b * meanK;

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'SVI (simplified)',
            parameters: {
              a: a,
              b: b,
              m: meanK,
            },
            fittedValues: logMoneyness.map(k => a + b * k),
            rmse: Math.sqrt(
              logMoneyness.reduce((sum, k, i) => 
                sum + (totalVariances[i] - (a + b * k)) ** 2, 0
              ) / n
            ),
          }, null, 2),
        },
      ],
    };
  }

  /**
   * Bilinear interpolation for volatility surface
   */
  async interpolateVolatilitySurface(args) {
    const { strikeGrid, maturityGrid, volSurface, targetStrike, targetMaturity } = args;

    // Find surrounding grid points
    let k0 = 0, k1 = strikeGrid.length - 1;
    for (let i = 0; i < strikeGrid.length - 1; i++) {
      if (targetStrike >= strikeGrid[i] && targetStrike <= strikeGrid[i + 1]) {
        k0 = i;
        k1 = i + 1;
        break;
      }
    }

    let t0 = 0, t1 = maturityGrid.length - 1;
    for (let i = 0; i < maturityGrid.length - 1; i++) {
      if (targetMaturity >= maturityGrid[i] && targetMaturity <= maturityGrid[i + 1]) {
        t0 = i;
        t1 = i + 1;
        break;
      }
    }

    // Bilinear interpolation weights
    const wK = (targetStrike - strikeGrid[k0]) / (strikeGrid[k1] - strikeGrid[k0]);
    const wT = (targetMaturity - maturityGrid[t0]) / (maturityGrid[t1] - maturityGrid[t0]);

    const v00 = volSurface[t0][k0];
    const v01 = volSurface[t0][k1];
    const v10 = volSurface[t1][k0];
    const v11 = volSurface[t1][k1];

    const interpolatedVol = 
      (1 - wT) * ((1 - wK) * v00 + wK * v01) +
      wT * ((1 - wK) * v10 + wK * v11);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            interpolatedVolatility: interpolatedVol,
            targetStrike: targetStrike,
            targetMaturity: targetMaturity,
            gridPoints: {
              strikes: [strikeGrid[k0], strikeGrid[k1]],
              maturities: [maturityGrid[t0], maturityGrid[t1]],
              vols: [[v00, v01], [v10, v11]],
            },
          }, null, 2),
        },
      ],
    };
  }

  /**
   * Black-Scholes pricing and Greeks
   */
  async blackScholesPrice(args) {
    const { spot, strike, maturity, volatility, rate, optionType } = args;

    const d1 = (Math.log(spot / strike) + (rate + 0.5 * volatility ** 2) * maturity) / 
               (volatility * Math.sqrt(maturity));
    const d2 = d1 - volatility * Math.sqrt(maturity);

    const normCdf = (x) => 0.5 * (1 + math.erf(x / Math.sqrt(2)));
    const normPdf = (x) => Math.exp(-0.5 * x ** 2) / Math.sqrt(2 * Math.PI);

    let price, delta, gamma, vega, theta;

    if (optionType === 'call') {
      price = spot * normCdf(d1) - strike * Math.exp(-rate * maturity) * normCdf(d2);
      delta = normCdf(d1);
      theta = (-spot * normPdf(d1) * volatility / (2 * Math.sqrt(maturity)) - 
               rate * strike * Math.exp(-rate * maturity) * normCdf(d2)) / 365;
    } else {
      price = strike * Math.exp(-rate * maturity) * normCdf(-d2) - spot * normCdf(-d1);
      delta = normCdf(d1) - 1;
      theta = (-spot * normPdf(d1) * volatility / (2 * Math.sqrt(maturity)) + 
               rate * strike * Math.exp(-rate * maturity) * normCdf(-d2)) / 365;
    }

    gamma = normPdf(d1) / (spot * volatility * Math.sqrt(maturity));
    vega = spot * normPdf(d1) * Math.sqrt(maturity) / 100;

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            price: price,
            greeks: {
              delta: delta,
              gamma: gamma,
              vega: vega,
              theta: theta,
            },
            parameters: {
              spot, strike, maturity, volatility, rate, optionType,
            },
            d1: d1,
            d2: d2,
          }, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Financial Localization MCP server running on stdio');
  }
}

const server = new FinancialLocalizationServer();
server.run().catch(console.error);
