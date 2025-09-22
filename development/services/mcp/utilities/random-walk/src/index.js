#!/usr/bin/env node
const MCPServer = require('../../../base-server');

class RandomWalkServer extends MCPServer {
    constructor() {
        super('random-walk', '1.0.0');
        
        this.registerMethod('generate_walk', this.generateWalk.bind(this));
        this.registerMethod('analyze_path', this.analyzePath.bind(this));
    }

    async handleListTools() {
        return {
            tools: [
                {
                    name: 'generate_walk',
                    description: 'Generate a random walk simulation',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            steps: { type: 'integer' },
                            dimensions: { type: 'integer' },
                            stepSize: { type: 'number' }
                        },
                        required: ['steps']
                    }
                }
            ]
        };
    }

    async generateWalk(params) {
        const { steps = 100, dimensions = 1, stepSize = 1 } = params;
        
        const path = [];
        const position = new Array(dimensions).fill(0);
        
        for (let i = 0; i < steps; i++) {
            for (let d = 0; d < dimensions; d++) {
                position[d] += (Math.random() - 0.5) * 2 * stepSize;
            }
            path.push([...position]);
        }
        
        return {
            path,
            steps,
            dimensions,
            finalPosition: position,
            distance: Math.sqrt(position.reduce((sum, x) => sum + x * x, 0))
        };
    }

    async analyzePath(params) {
        const { path } = params;
        
        if (!path || path.length === 0) {
            throw new Error('Path is required');
        }
        
        const distances = path.map(p => Math.sqrt(p.reduce((sum, x) => sum + x * x, 0)));
        const maxDistance = Math.max(...distances);
        const avgDistance = distances.reduce((a, b) => a + b) / distances.length;
        
        return {
            maxDistance,
            avgDistance,
            pathLength: path.length,
            dimensions: path[0].length
        };
    }
}

const server = new RandomWalkServer();
server.start();