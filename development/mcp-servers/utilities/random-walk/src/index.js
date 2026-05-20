#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as math from 'mathjs';

/**
 * MCP Server for Random Walk Simulations and Analysis
 * 
 * Provides tools for:
 * - Simple random walk (1D, 2D, 3D)
 * - Biased random walk
 * - Self-avoiding random walk
 * - Lévy flights
 * - Random walk statistics and analysis
 */

class RandomWalkServer {
  constructor() {
    this.server = new Server(
      {
        name: 'random-walk',
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
          name: 'simple_random_walk',
          description: 'Simulate a simple random walk in 1D, 2D, or 3D',
          inputSchema: {
            type: 'object',
            properties: {
              dimensions: {
                type: 'number',
                enum: [1, 2, 3],
                description: 'Number of dimensions (1, 2, or 3)',
              },
              steps: {
                type: 'number',
                description: 'Number of steps',
              },
              stepSize: {
                type: 'number',
                description: 'Size of each step',
                default: 1,
              },
              paths: {
                type: 'number',
                description: 'Number of random walk paths to simulate',
                default: 1,
              },
            },
            required: ['dimensions', 'steps'],
          },
        },
        {
          name: 'biased_random_walk',
          description: 'Simulate a biased random walk with directional drift',
          inputSchema: {
            type: 'object',
            properties: {
              steps: {
                type: 'number',
                description: 'Number of steps',
              },
              bias: {
                type: 'array',
                items: { type: 'number' },
                description: 'Bias vector (e.g., [0.6, 0.4] means 60% right, 40% left in 1D)',
              },
              stepSize: {
                type: 'number',
                description: 'Size of each step',
                default: 1,
              },
              paths: {
                type: 'number',
                description: 'Number of paths',
                default: 1,
              },
            },
            required: ['steps', 'bias'],
          },
        },
        {
          name: 'levy_flight',
          description: 'Simulate a Lévy flight with heavy-tailed step distribution',
          inputSchema: {
            type: 'object',
            properties: {
              dimensions: {
                type: 'number',
                enum: [1, 2, 3],
                description: 'Number of dimensions',
              },
              steps: {
                type: 'number',
                description: 'Number of steps',
              },
              alpha: {
                type: 'number',
                description: 'Stability parameter (0 < alpha <= 2)',
              },
              paths: {
                type: 'number',
                description: 'Number of paths',
                default: 1,
              },
            },
            required: ['dimensions', 'steps', 'alpha'],
          },
        },
        {
          name: 'analyze_random_walk',
          description: 'Analyze random walk statistics (mean displacement, variance, etc.)',
          inputSchema: {
            type: 'object',
            properties: {
              positions: {
                type: 'array',
                items: {
                  type: 'array',
                  items: { type: 'number' },
                },
                description: 'Array of positions [step][dimension]',
              },
            },
            required: ['positions'],
          },
        },
        {
          name: 'first_passage_time',
          description: 'Calculate first passage time statistics for random walk',
          inputSchema: {
            type: 'object',
            properties: {
              barrier: {
                type: 'number',
                description: 'Barrier position to cross',
              },
              steps: {
                type: 'number',
                description: 'Maximum number of steps',
              },
              stepSize: {
                type: 'number',
                description: 'Size of each step',
                default: 1,
              },
              simulations: {
                type: 'number',
                description: 'Number of simulations',
                default: 1000,
              },
            },
            required: ['barrier', 'steps'],
          },
        },
        {
          name: 'brownian_bridge',
          description: 'Generate a Brownian bridge (random walk conditioned on endpoints)',
          inputSchema: {
            type: 'object',
            properties: {
              startValue: {
                type: 'number',
                description: 'Starting value',
              },
              endValue: {
                type: 'number',
                description: 'Ending value',
              },
              T: {
                type: 'number',
                description: 'Time horizon',
              },
              steps: {
                type: 'number',
                description: 'Number of steps',
              },
              paths: {
                type: 'number',
                description: 'Number of paths',
                default: 1,
              },
            },
            required: ['startValue', 'endValue', 'T', 'steps'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'simple_random_walk':
          return await this.simpleRandomWalk(request.params.arguments);
        case 'biased_random_walk':
          return await this.biasedRandomWalk(request.params.arguments);
        case 'levy_flight':
          return await this.levyFlight(request.params.arguments);
        case 'analyze_random_walk':
          return await this.analyzeRandomWalk(request.params.arguments);
        case 'first_passage_time':
          return await this.firstPassageTime(request.params.arguments);
        case 'brownian_bridge':
          return await this.brownianBridge(request.params.arguments);
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

  async simpleRandomWalk(args) {
    const { dimensions, steps, stepSize = 1, paths = 1 } = args;

    const results = [];

    for (let p = 0; p < paths; p++) {
      const positions = [Array(dimensions).fill(0)];
      let pos = Array(dimensions).fill(0);

      for (let s = 0; s < steps; s++) {
        // Random direction in each dimension
        for (let d = 0; d < dimensions; d++) {
          const direction = Math.random() < 0.5 ? -1 : 1;
          pos[d] += direction * stepSize;
        }
        positions.push([...pos]);
      }

      const displacement = Math.sqrt(pos.reduce((sum, x) => sum + x ** 2, 0));

      results.push({
        pathIndex: p,
        positions: positions,
        finalPosition: pos,
        displacement: displacement,
      });
    }

    const avgDisplacement = math.mean(results.map(r => r.displacement));
    const theoreticalStd = stepSize * Math.sqrt(steps * dimensions);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: `Simple Random Walk (${dimensions}D)`,
            parameters: { dimensions, steps, stepSize, paths },
            paths: results,
            statistics: {
              averageDisplacement: avgDisplacement,
              theoreticalStdDev: theoreticalStd,
            },
          }, null, 2),
        },
      ],
    };
  }

  async biasedRandomWalk(args) {
    const { steps, bias, stepSize = 1, paths = 1 } = args;

    const dimensions = bias.length;
    const results = [];

    for (let p = 0; p < paths; p++) {
      const positions = [Array(dimensions).fill(0)];
      let pos = Array(dimensions).fill(0);

      for (let s = 0; s < steps; s++) {
        for (let d = 0; d < dimensions; d++) {
          const direction = Math.random() < bias[d] ? 1 : -1;
          pos[d] += direction * stepSize;
        }
        positions.push([...pos]);
      }

      results.push({
        pathIndex: p,
        positions: positions,
        finalPosition: pos,
      });
    }

    const avgFinalPos = Array(dimensions).fill(0);
    for (let d = 0; d < dimensions; d++) {
      avgFinalPos[d] = math.mean(results.map(r => r.finalPosition[d]));
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Biased Random Walk',
            parameters: { steps, bias, stepSize, paths },
            paths: results,
            statistics: {
              averageFinalPosition: avgFinalPos,
              bias: bias,
            },
          }, null, 2),
        },
      ],
    };
  }

  async levyFlight(args) {
    const { dimensions, steps, alpha, paths = 1 } = args;

    if (alpha <= 0 || alpha > 2) {
      throw new Error('Alpha must be in range (0, 2]');
    }

    const results = [];

    for (let p = 0; p < paths; p++) {
      const positions = [Array(dimensions).fill(0)];
      let pos = Array(dimensions).fill(0);

      for (let s = 0; s < steps; s++) {
        // Generate Lévy-distributed step using approximation
        for (let d = 0; d < dimensions; d++) {
          const u = Math.random();
          const stepLength = Math.pow(u, -1 / alpha);
          const direction = Math.random() < 0.5 ? -1 : 1;
          pos[d] += direction * Math.min(stepLength, 100); // Cap extreme values
        }
        positions.push([...pos]);
      }

      const displacement = Math.sqrt(pos.reduce((sum, x) => sum + x ** 2, 0));

      results.push({
        pathIndex: p,
        positions: positions,
        finalPosition: pos,
        displacement: displacement,
      });
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: `Lévy Flight (${dimensions}D)`,
            parameters: { dimensions, steps, alpha, paths },
            paths: results,
            statistics: {
              averageDisplacement: math.mean(results.map(r => r.displacement)),
              alphaParameter: alpha,
            },
          }, null, 2),
        },
      ],
    };
  }

  async analyzeRandomWalk(args) {
    const { positions } = args;

    const numSteps = positions.length - 1;
    const dimensions = positions[0].length;

    // Calculate displacement from origin
    const displacements = positions.map(pos =>
      Math.sqrt(pos.reduce((sum, x) => sum + x ** 2, 0))
    );

    // Calculate step sizes
    const stepSizes = [];
    for (let i = 1; i < positions.length; i++) {
      const step = Math.sqrt(
        positions[i].reduce((sum, x, d) => sum + (x - positions[i - 1][d]) ** 2, 0)
      );
      stepSizes.push(step);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            analysis: 'Random Walk Statistics',
            numSteps: numSteps,
            dimensions: dimensions,
            finalPosition: positions[positions.length - 1],
            finalDisplacement: displacements[displacements.length - 1],
            statistics: {
              meanDisplacement: math.mean(displacements),
              maxDisplacement: Math.max(...displacements),
              meanStepSize: math.mean(stepSizes),
              stdStepSize: math.std(stepSizes),
            },
          }, null, 2),
        },
      ],
    };
  }

  async firstPassageTime(args) {
    const { barrier, steps, stepSize = 1, simulations = 1000 } = args;

    const passageTimes = [];

    for (let sim = 0; sim < simulations; sim++) {
      let pos = 0;
      let time = null;

      for (let s = 1; s <= steps; s++) {
        const direction = Math.random() < 0.5 ? -1 : 1;
        pos += direction * stepSize;

        if (Math.abs(pos) >= Math.abs(barrier)) {
          time = s;
          break;
        }
      }

      if (time !== null) {
        passageTimes.push(time);
      }
    }

    const crossingProbability = passageTimes.length / simulations;
    const avgPassageTime = passageTimes.length > 0 ? math.mean(passageTimes) : null;

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            analysis: 'First Passage Time',
            barrier: barrier,
            maxSteps: steps,
            simulations: simulations,
            crossings: passageTimes.length,
            crossingProbability: crossingProbability,
            statistics: {
              meanPassageTime: avgPassageTime,
              minPassageTime: passageTimes.length > 0 ? Math.min(...passageTimes) : null,
              maxPassageTime: passageTimes.length > 0 ? Math.max(...passageTimes) : null,
              stdPassageTime: passageTimes.length > 0 ? math.std(passageTimes) : null,
            },
          }, null, 2),
        },
      ],
    };
  }

  async brownianBridge(args) {
    const { startValue, endValue, T, steps, paths = 1 } = args;

    const dt = T / steps;
    const results = [];

    for (let p = 0; p < paths; p++) {
      const path = [startValue];

      for (let i = 1; i < steps; i++) {
        const t = i * dt;
        const remainingTime = T - t;
        
        // Brownian bridge formula
        const mean = path[i - 1] + (endValue - path[i - 1]) * (dt / remainingTime);
        const variance = dt * (remainingTime - dt) / remainingTime;
        
        const value = mean + this.boxMuller() * Math.sqrt(variance);
        path.push(value);
      }

      path.push(endValue);

      results.push({
        pathIndex: p,
        values: path,
      });
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            model: 'Brownian Bridge',
            parameters: { startValue, endValue, T, steps, paths },
            paths: results,
          }, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Random Walk MCP server running on stdio');
  }
}

const server = new RandomWalkServer();
server.run().catch(console.error);
