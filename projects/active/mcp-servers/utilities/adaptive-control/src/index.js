#!/usr/bin/env node

/**
 * MCP Server for Adaptive Control Systems
 * Provides tools for multi-agent coordination and adaptive algorithms
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { AdaptiveControlSystem } from './adaptive-algorithms.js';

class AdaptiveControlServer {
    constructor() {
        this.server = new Server(
            {
                name: 'adaptive-control',
                version: '1.0.0',
                description: 'Multi-agent adaptive coordination and control algorithms'
            },
            {
                capabilities: {
                    tools: {}
                }
            }
        );

        this.adaptiveSystem = new AdaptiveControlSystem();
        this.setupToolHandlers();
        this.setupErrorHandling();
    }

    setupToolHandlers() {
        this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
            tools: [
                {
                    name: 'coordinate_agents',
                    description: 'Apply adaptive coordination algorithm to multiple agents',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            agents: {
                                type: 'array',
                                items: {
                                    type: 'object',
                                    properties: {
                                        id: { type: 'string' },
                                        state: { type: 'array', items: { type: 'number' } },
                                        target: { type: 'array', items: { type: 'number' } }
                                    },
                                    required: ['id', 'state', 'target']
                                },
                                description: 'Array of agent objects with state and target vectors'
                            },
                            alpha: {
                                type: 'number',
                                default: 0.1,
                                description: 'Adaptation rate parameter'
                            }
                        },
                        required: ['agents']
                    }
                },
                {
                    name: 'lyapunov_stability_analysis',
                    description: 'Analyze system stability using Lyapunov methods',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            system_state: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Current system state vector'
                            },
                            reference_state: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Reference/desired state vector'
                            },
                            Q_matrix: {
                                type: 'array',
                                items: { type: 'array', items: { type: 'number' } },
                                description: 'Positive definite Q matrix for Lyapunov function'
                            }
                        },
                        required: ['system_state', 'reference_state']
                    }
                },
                {
                    name: 'mrac_adaptation',
                    description: 'Apply Model Reference Adaptive Control',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            plant_output: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Current plant output'
                            },
                            reference_output: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Reference model output'
                            },
                            current_parameters: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Current adaptive parameters'
                            },
                            learning_rate: {
                                type: 'number',
                                default: 0.01,
                                description: 'MRAC learning rate'
                            }
                        },
                        required: ['plant_output', 'reference_output', 'current_parameters']
                    }
                },
                {
                    name: 'consensus_algorithm',
                    description: 'Apply distributed consensus algorithm for multi-agent systems',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            agent_states: {
                                type: 'array',
                                items: { type: 'array', items: { type: 'number' } },
                                description: 'Current states of all agents'
                            },
                            adjacency_matrix: {
                                type: 'array',
                                items: { type: 'array', items: { type: 'number' } },
                                description: 'Network connectivity matrix'
                            },
                            consensus_gain: {
                                type: 'number',
                                default: 0.1,
                                description: 'Consensus algorithm gain'
                            }
                        },
                        required: ['agent_states', 'adjacency_matrix']
                    }
                },
                {
                    name: 'performance_optimization',
                    description: 'Optimize system performance using gradient descent',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            current_parameters: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Current system parameters'
                            },
                            gradient: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Performance gradient vector'
                            },
                            learning_rate: {
                                type: 'number',
                                default: 0.01,
                                description: 'Optimization learning rate'
                            },
                            momentum: {
                                type: 'number',
                                default: 0.9,
                                description: 'Momentum factor'
                            }
                        },
                        required: ['current_parameters', 'gradient']
                    }
                },
                {
                    name: 'adaptive_gain_scheduling',
                    description: 'Calculate adaptive gains based on system conditions',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            operating_point: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Current operating point'
                            },
                            system_parameters: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'System parameter estimates'
                            },
                            base_gains: {
                                type: 'array',
                                items: { type: 'number' },
                                description: 'Base control gains'
                            }
                        },
                        required: ['operating_point', 'system_parameters', 'base_gains']
                    }
                }
            ]
        }));

        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;

            try {
                switch (name) {
                    case 'coordinate_agents':
                        return await this.handleCoordinateAgents(args);
                    
                    case 'lyapunov_stability_analysis':
                        return await this.handleLyapunovAnalysis(args);
                    
                    case 'mrac_adaptation':
                        return await this.handleMracAdaptation(args);
                    
                    case 'consensus_algorithm':
                        return await this.handleConsensusAlgorithm(args);
                    
                    case 'performance_optimization':
                        return await this.handlePerformanceOptimization(args);
                    
                    case 'adaptive_gain_scheduling':
                        return await this.handleAdaptiveGainScheduling(args);
                    
                    default:
                        throw new Error(`Unknown tool: ${name}`);
                }
            } catch (error) {
                return {
                    content: [
                        {
                            type: 'text',
                            text: `Error executing ${name}: ${error.message}`
                        }
                    ]
                };
            }
        });
    }

    async handleCoordinateAgents(args) {
        const { agents, alpha = 0.1 } = args;
        
        const result = this.adaptiveSystem.coordinateAgents(agents, alpha);
        
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({
                        coordination_result: result,
                        timestamp: new Date().toISOString(),
                        algorithm: 'Multi-Agent Adaptive Coordination',
                        parameters: { alpha }
                    }, null, 2)
                }
            ]
        };
    }

    async handleLyapunovAnalysis(args) {
        const { system_state, reference_state, Q_matrix } = args;
        
        const result = this.adaptiveSystem.lyapunovStabilityAnalysis(
            system_state, 
            reference_state, 
            Q_matrix
        );
        
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({
                        stability_analysis: result,
                        timestamp: new Date().toISOString(),
                        algorithm: 'Lyapunov Stability Analysis'
                    }, null, 2)
                }
            ]
        };
    }

    async handleMracAdaptation(args) {
        const { plant_output, reference_output, current_parameters, learning_rate = 0.01 } = args;
        
        const result = this.adaptiveSystem.mracAdaptation(
            plant_output,
            reference_output,
            current_parameters,
            learning_rate
        );
        
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({
                        mrac_result: result,
                        timestamp: new Date().toISOString(),
                        algorithm: 'Model Reference Adaptive Control',
                        parameters: { learning_rate }
                    }, null, 2)
                }
            ]
        };
    }

    async handleConsensusAlgorithm(args) {
        const { agent_states, adjacency_matrix, consensus_gain = 0.1 } = args;
        
        const result = this.adaptiveSystem.consensusAlgorithm(
            agent_states,
            adjacency_matrix,
            consensus_gain
        );
        
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({
                        consensus_result: result,
                        timestamp: new Date().toISOString(),
                        algorithm: 'Distributed Consensus',
                        parameters: { consensus_gain }
                    }, null, 2)
                }
            ]
        };
    }

    async handlePerformanceOptimization(args) {
        const { current_parameters, gradient, learning_rate = 0.01, momentum = 0.9 } = args;
        
        const result = this.adaptiveSystem.performanceOptimization(
            current_parameters,
            gradient,
            learning_rate,
            momentum
        );
        
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({
                        optimization_result: result,
                        timestamp: new Date().toISOString(),
                        algorithm: 'Gradient Descent with Momentum',
                        parameters: { learning_rate, momentum }
                    }, null, 2)
                }
            ]
        };
    }

    async handleAdaptiveGainScheduling(args) {
        const { operating_point, system_parameters, base_gains } = args;
        
        const result = this.adaptiveSystem.adaptiveGainScheduling(
            operating_point,
            system_parameters,
            base_gains
        );
        
        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({
                        gain_scheduling_result: result,
                        timestamp: new Date().toISOString(),
                        algorithm: 'Adaptive Gain Scheduling'
                    }, null, 2)
                }
            ]
        };
    }

    setupErrorHandling() {
        this.server.onerror = (error) => {
            console.error('[MCP Error]', error);
        };

        process.on('SIGINT', async () => {
            await this.server.close();
            process.exit(0);
        });
    }

    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error('Adaptive Control MCP server running on stdio');
    }
}

const server = new AdaptiveControlServer();
server.run().catch(console.error);