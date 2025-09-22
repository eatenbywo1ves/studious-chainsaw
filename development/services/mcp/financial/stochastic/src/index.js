#!/usr/bin/env node
const MCPServer = require('../../../base-server');

class FinancialStochasticServer extends MCPServer {
    constructor() {
        super('financial-stochastic', '1.0.0');

        // Register stochastic modeling methods
        this.registerMethod('monte_carlo_simulation', this.monteCarloSimulation.bind(this));
        this.registerMethod('calculate_volatility', this.calculateVolatility.bind(this));
    }

    async handleListTools() {
        return {
            tools: [
                {
                    name: 'monte_carlo_simulation',
                    description: 'Run Monte Carlo simulation for financial modeling',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            initialValue: { type: 'number' },
                            drift: { type: 'number' },
                            volatility: { type: 'number' },
                            steps: { type: 'integer' },
                            iterations: { type: 'integer' }
                        },
                        required: ['initialValue']
                    }
                },
                {
                    name: 'calculate_volatility',
                    description: 'Calculate historical volatility from price data',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            prices: { type: 'array', items: { type: 'number' } }
                        },
                        required: ['prices']
                    }
                }
            ]
        };
    }

    async monteCarloSimulation(params) {
        const {
            initialValue,
            drift = 0.05,
            volatility = 0.2,
            steps = 252,
            iterations = 1000
        } = params;

        const dt = 1 / steps;
        const results = [];

        for (let i = 0; i < iterations; i++) {
            let value = initialValue;
            for (let j = 0; j < steps; j++) {
                const randomShock = Math.sqrt(dt) * this.normalRandom();
                value = value * Math.exp((drift - 0.5 * volatility * volatility) * dt + volatility * randomShock);
            }
            results.push(value);
        }

        const mean = results.reduce((a, b) => a + b) / results.length;
        const variance = results.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / results.length;

        return {
            mean,
            variance,
            stdDev: Math.sqrt(variance),
            min: Math.min(...results),
            max: Math.max(...results),
            samples: iterations
        };
    }

    async calculateVolatility(params) {
        const { prices } = params;

        if (!prices || prices.length < 2) {
            throw new Error('Need at least 2 price points');
        }

        const returns = [];
        for (let i = 1; i < prices.length; i++) {
            returns.push(Math.log(prices[i] / prices[i - 1]));
        }

        const mean = returns.reduce((a, b) => a + b) / returns.length;
        const variance = returns.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / returns.length;
        const annualizedVol = Math.sqrt(variance * 252);

        return {
            dailyVolatility: Math.sqrt(variance),
            annualizedVolatility: annualizedVol,
            dataPoints: prices.length
        };
    }

    normalRandom() {
        let u = 0, v = 0;
        while (u === 0) u = Math.random();
        while (v === 0) v = Math.random();
        return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    }
}

// Start the server
const server = new FinancialStochasticServer();
server.start();