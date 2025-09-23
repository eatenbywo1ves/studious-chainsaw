#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

class RandomWalkGenerator {
  static generateSimpleWalk(steps, stepSize = 1.0, dimensions = 2) {
    const path = [{ x: 0, y: 0, z: 0, step: 0 }];
    let x = 0, y = 0, z = 0;
    
    for (let i = 1; i <= steps; i++) {
      const angle = Math.random() * 2 * Math.PI;
      x += stepSize * Math.cos(angle);
      y += stepSize * Math.sin(angle);
      
      if (dimensions === 3) {
        const phi = Math.random() * Math.PI;
        z += stepSize * Math.cos(phi);
      }
      
      path.push({ x, y, z, step: i });
    }
    return path;
  }

  static generateBiasedWalk(steps, bias = 0.1, stepSize = 1.0, dimensions = 2) {
    const path = [{ x: 0, y: 0, z: 0, step: 0 }];
    let x = 0, y = 0, z = 0;
    
    for (let i = 1; i <= steps; i++) {
      const angle = Math.random() * 2 * Math.PI + bias;
      x += stepSize * Math.cos(angle);
      y += stepSize * Math.sin(angle);
      
      if (dimensions === 3) {
        z += stepSize * (Math.random() - 0.5 + bias);
      }
      
      path.push({ x, y, z, step: i });
    }
    return path;
  }

  static generateLevyWalk(steps, alpha = 1.5, stepSize = 1.0, dimensions = 2) {
    const path = [{ x: 0, y: 0, z: 0, step: 0 }];
    let x = 0, y = 0, z = 0;
    
    for (let i = 1; i <= steps; i++) {
      // Levy flight step size using power law
      const u = Math.random();
      const levyStep = stepSize * Math.pow(u, -1/alpha);
      
      const angle = Math.random() * 2 * Math.PI;
      x += levyStep * Math.cos(angle);
      y += levyStep * Math.sin(angle);
      
      if (dimensions === 3) {
        const phi = Math.random() * Math.PI;
        z += levyStep * Math.cos(phi);
      }
      
      path.push({ x, y, z, step: i });
    }
    return path;
  }

  static generateCorrelatedWalk(steps, correlation = 0.7, stepSize = 1.0, dimensions = 2) {
    const path = [{ x: 0, y: 0, z: 0, step: 0 }];
    let x = 0, y = 0, z = 0;
    let prevAngle = 0;
    
    for (let i = 1; i <= steps; i++) {
      // Generate new angle with correlation to previous
      const newAngle = prevAngle * correlation + (1 - correlation) * Math.random() * 2 * Math.PI;
      
      x += stepSize * Math.cos(newAngle);
      y += stepSize * Math.sin(newAngle);
      
      if (dimensions === 3) {
        z += stepSize * (Math.random() - 0.5);
      }
      
      path.push({ x, y, z, step: i });
      prevAngle = newAngle;
    }
    return path;
  }

  static analyzeWalk(path) {
    if (path.length < 2) return {};

    const n = path.length - 1;
    const endPoint = path[path.length - 1];
    
    // End-to-end distance
    const endDistance = Math.sqrt(endPoint.x ** 2 + endPoint.y ** 2 + endPoint.z ** 2);
    
    // Mean squared displacement
    const msd = (endPoint.x ** 2 + endPoint.y ** 2 + endPoint.z ** 2) / n;
    
    // Total path length
    let totalLength = 0;
    for (let i = 1; i < path.length; i++) {
      const dx = path[i].x - path[i-1].x;
      const dy = path[i].y - path[i-1].y;
      const dz = path[i].z - path[i-1].z;
      totalLength += Math.sqrt(dx ** 2 + dy ** 2 + dz ** 2);
    }
    
    return {
      steps: n,
      endDistance,
      meanSquaredDisplacement: msd,
      totalPathLength: totalLength,
      efficiency: endDistance / totalLength,
      boundingBox: {
        minX: Math.min(...path.map(p => p.x)),
        maxX: Math.max(...path.map(p => p.x)),
        minY: Math.min(...path.map(p => p.y)),
        maxY: Math.max(...path.map(p => p.y)),
        minZ: Math.min(...path.map(p => p.z)),
        maxZ: Math.max(...path.map(p => p.z))
      }
    };
  }
}

class RandomWalkMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'random-walk-mcp',
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
          name: 'generate_simple_walk',
          description: 'Generate a simple random walk with uniform step sizes',
          inputSchema: {
            type: 'object',
            properties: {
              steps: {
                type: 'number',
                description: 'Number of steps in the walk',
                default: 1000
              },
              stepSize: {
                type: 'number',
                description: 'Size of each step',
                default: 1.0
              },
              dimensions: {
                type: 'number',
                description: 'Number of dimensions (2 or 3)',
                default: 2,
                enum: [2, 3]
              }
            },
            required: ['steps']
          }
        },
        {
          name: 'generate_biased_walk',
          description: 'Generate a biased random walk with directional preference',
          inputSchema: {
            type: 'object',
            properties: {
              steps: {
                type: 'number',
                description: 'Number of steps in the walk',
                default: 1000
              },
              bias: {
                type: 'number',
                description: 'Directional bias parameter',
                default: 0.1
              },
              stepSize: {
                type: 'number',
                description: 'Size of each step',
                default: 1.0
              },
              dimensions: {
                type: 'number',
                description: 'Number of dimensions (2 or 3)',
                default: 2,
                enum: [2, 3]
              }
            },
            required: ['steps']
          }
        },
        {
          name: 'generate_levy_walk',
          description: 'Generate a Levy flight/walk with power-law step distribution',
          inputSchema: {
            type: 'object',
            properties: {
              steps: {
                type: 'number',
                description: 'Number of steps in the walk',
                default: 1000
              },
              alpha: {
                type: 'number',
                description: 'Levy exponent (1 < alpha <= 2)',
                default: 1.5
              },
              stepSize: {
                type: 'number',
                description: 'Base step size scale',
                default: 1.0
              },
              dimensions: {
                type: 'number',
                description: 'Number of dimensions (2 or 3)',
                default: 2,
                enum: [2, 3]
              }
            },
            required: ['steps']
          }
        },
        {
          name: 'generate_correlated_walk',
          description: 'Generate a correlated random walk with memory of previous direction',
          inputSchema: {
            type: 'object',
            properties: {
              steps: {
                type: 'number',
                description: 'Number of steps in the walk',
                default: 1000
              },
              correlation: {
                type: 'number',
                description: 'Correlation with previous direction (0-1)',
                default: 0.7
              },
              stepSize: {
                type: 'number',
                description: 'Size of each step',
                default: 1.0
              },
              dimensions: {
                type: 'number',
                description: 'Number of dimensions (2 or 3)',
                default: 2,
                enum: [2, 3]
              }
            },
            required: ['steps']
          }
        },
        {
          name: 'analyze_walk',
          description: 'Analyze statistical properties of a random walk path',
          inputSchema: {
            type: 'object',
            properties: {
              path: {
                type: 'array',
                description: 'Array of path points with x, y, z coordinates',
                items: {
                  type: 'object',
                  properties: {
                    x: { type: 'number' },
                    y: { type: 'number' },
                    z: { type: 'number' },
                    step: { type: 'number' }
                  }
                }
              }
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
          case 'generate_simple_walk':
            const simplePath = RandomWalkGenerator.generateSimpleWalk(
              args.steps || 1000,
              args.stepSize || 1.0,
              args.dimensions || 2
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  walkType: 'simple',
                  path: simplePath,
                  analysis: RandomWalkGenerator.analyzeWalk(simplePath)
                }, null, 2)
              }]
            };

          case 'generate_biased_walk':
            const biasedPath = RandomWalkGenerator.generateBiasedWalk(
              args.steps || 1000,
              args.bias || 0.1,
              args.stepSize || 1.0,
              args.dimensions || 2
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  walkType: 'biased',
                  path: biasedPath,
                  analysis: RandomWalkGenerator.analyzeWalk(biasedPath)
                }, null, 2)
              }]
            };

          case 'generate_levy_walk':
            const levyPath = RandomWalkGenerator.generateLevyWalk(
              args.steps || 1000,
              args.alpha || 1.5,
              args.stepSize || 1.0,
              args.dimensions || 2
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  walkType: 'levy',
                  path: levyPath,
                  analysis: RandomWalkGenerator.analyzeWalk(levyPath)
                }, null, 2)
              }]
            };

          case 'generate_correlated_walk':
            const correlatedPath = RandomWalkGenerator.generateCorrelatedWalk(
              args.steps || 1000,
              args.correlation || 0.7,
              args.stepSize || 1.0,
              args.dimensions || 2
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  walkType: 'correlated',
                  path: correlatedPath,
                  analysis: RandomWalkGenerator.analyzeWalk(correlatedPath)
                }, null, 2)
              }]
            };

          case 'analyze_walk':
            const analysis = RandomWalkGenerator.analyzeWalk(args.path);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(analysis, null, 2)
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
    console.error('Random Walk MCP server running on stdio');
  }
}

const server = new RandomWalkMCPServer();
server.run().catch(console.error);