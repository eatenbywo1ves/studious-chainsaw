#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as math from 'mathjs';

/**
 * MCP Server for Adaptive Control Systems and Optimization
 * 
 * Provides tools for:
 * - PID controller design and tuning
 * - Model Reference Adaptive Control (MRAC)
 * - Gradient descent optimization
 * - Kalman filtering
 * - System identification
 */

class AdaptiveControlServer {
  constructor() {
    this.server = new Server(
      {
        name: 'adaptive-control',
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
          name: 'pid_controller',
          description: 'Simulate a PID controller response',
          inputSchema: {
            type: 'object',
            properties: {
              kp: {
                type: 'number',
                description: 'Proportional gain',
              },
              ki: {
                type: 'number',
                description: 'Integral gain',
              },
              kd: {
                type: 'number',
                description: 'Derivative gain',
              },
              setpoint: {
                type: 'number',
                description: 'Target setpoint',
              },
              initialValue: {
                type: 'number',
                description: 'Initial process value',
                default: 0,
              },
              timesteps: {
                type: 'number',
                description: 'Number of simulation steps',
              },
              dt: {
                type: 'number',
                description: 'Time step size',
                default: 0.1,
              },
              processGain: {
                type: 'number',
                description: 'Process gain (plant transfer function)',
                default: 1,
              },
              processTimeConstant: {
                type: 'number',
                description: 'Process time constant',
                default: 1,
              },
            },
            required: ['kp', 'ki', 'kd', 'setpoint', 'timesteps'],
          },
        },
        {
          name: 'ziegler_nichols_tuning',
          description: 'Calculate PID parameters using Ziegler-Nichols tuning method',
          inputSchema: {
            type: 'object',
            properties: {
              ultimateGain: {
                type: 'number',
                description: 'Ultimate gain (Ku) - gain at sustained oscillation',
              },
              ultimatePeriod: {
                type: 'number',
                description: 'Ultimate period (Tu) - oscillation period',
              },
              controllerType: {
                type: 'string',
                enum: ['P', 'PI', 'PID'],
                description: 'Type of controller',
                default: 'PID',
              },
            },
            required: ['ultimateGain', 'ultimatePeriod'],
          },
        },
        {
          name: 'gradient_descent',
          description: 'Perform gradient descent optimization',
          inputSchema: {
            type: 'object',
            properties: {
              initialParams: {
                type: 'array',
                items: { type: 'number' },
                description: 'Initial parameter values',
              },
              gradient: {
                type: 'array',
                items: { type: 'number' },
                description: 'Gradient vector at current point',
              },
              learningRate: {
                type: 'number',
                description: 'Learning rate (step size)',
              },
              momentum: {
                type: 'number',
                description: 'Momentum coefficient (0-1)',
                default: 0,
              },
              iterations: {
                type: 'number',
                description: 'Number of iterations',
              },
            },
            required: ['initialParams', 'learningRate', 'iterations'],
          },
        },
        {
          name: 'kalman_filter',
          description: 'Apply Kalman filter for state estimation',
          inputSchema: {
            type: 'object',
            properties: {
              measurements: {
                type: 'array',
                items: { type: 'number' },
                description: 'Array of noisy measurements',
              },
              processNoise: {
                type: 'number',
                description: 'Process noise covariance (Q)',
              },
              measurementNoise: {
                type: 'number',
                description: 'Measurement noise covariance (R)',
              },
              initialEstimate: {
                type: 'number',
                description: 'Initial state estimate',
                default: 0,
              },
              initialCovariance: {
                type: 'number',
                description: 'Initial error covariance',
                default: 1,
              },
            },
            required: ['measurements', 'processNoise', 'measurementNoise'],
          },
        },
        {
          name: 'model_reference_adaptive',
          description: 'Simulate Model Reference Adaptive Control (MRAC)',
          inputSchema: {
            type: 'object',
            properties: {
              referenceModel: {
                type: 'object',
                properties: {
                  a: { type: 'number', description: 'Reference model parameter' },
                  b: { type: 'number', description: 'Reference model gain' },
                },
                required: ['a', 'b'],
              },
              plantParams: {
                type: 'object',
                properties: {
                  a: { type: 'number', description: 'Plant parameter (unknown)' },
                  b: { type: 'number', description: 'Plant gain (unknown)' },
                },
                required: ['a', 'b'],
              },
              adaptationGain: {
                type: 'number',
                description: 'Adaptation gain (gamma)',
              },
              reference: {
                type: 'number',
                description: 'Reference input',
              },
              timesteps: {
                type: 'number',
                description: 'Number of simulation steps',
              },
              dt: {
                type: 'number',
                description: 'Time step',
                default: 0.01,
              },
            },
            required: ['referenceModel', 'plantParams', 'adaptationGain', 'reference', 'timesteps'],
          },
        },
        {
          name: 'least_squares_identification',
          description: 'Identify system parameters using least squares',
          inputSchema: {
            type: 'object',
            properties: {
              inputs: {
                type: 'array',
                items: { type: 'number' },
                description: 'Input signal data',
              },
              outputs: {
                type: 'array',
                items: { type: 'number' },
                description: 'Output signal data',
              },
              order: {
                type: 'number',
                description: 'Model order (ARX model)',
              },
            },
            required: ['inputs', 'outputs', 'order'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'pid_controller':
          return await this.pidController(request.params.arguments);
        case 'ziegler_nichols_tuning':
          return await this.zieglerNicholsTuning(request.params.arguments);
        case 'gradient_descent':
          return await this.gradientDescent(request.params.arguments);
        case 'kalman_filter':
          return await this.kalmanFilter(request.params.arguments);
        case 'model_reference_adaptive':
          return await this.modelReferenceAdaptive(request.params.arguments);
        case 'least_squares_identification':
          return await this.leastSquaresIdentification(request.params.arguments);
        default:
          throw new Error(`Unknown tool: ${request.params.name}`);
      }
    });
  }

  async pidController(args) {
    const {
      kp, ki, kd, setpoint, initialValue = 0, timesteps, dt = 0.1,
      processGain = 1, processTimeConstant = 1
    } = args;

    const results = {
      time: [],
      processValue: [],
      error: [],
      controlSignal: [],
      proportional: [],
      integral: [],
      derivative: [],
    };

    let pv = initialValue;
    let integral = 0;
    let previousError = setpoint - initialValue;

    for (let t = 0; t < timesteps; t++) {
      const time = t * dt;
      const error = setpoint - pv;

      // PID calculation
      const proportional = kp * error;
      integral += error * dt;
      const integralTerm = ki * integral;
      const derivative = (error - previousError) / dt;
      const derivativeTerm = kd * derivative;

      const controlSignal = proportional + integralTerm + derivativeTerm;

      // First-order process model
      const dvdt = (processGain * controlSignal - pv) / processTimeConstant;
      pv += dvdt * dt;

      results.time.push(time);
      results.processValue.push(pv);
      results.error.push(error);
      results.controlSignal.push(controlSignal);
      results.proportional.push(proportional);
      results.integral.push(integralTerm);
      results.derivative.push(derivativeTerm);

      previousError = error;
    }

    // Calculate performance metrics
    const settlingTime = this.calculateSettlingTime(results.processValue, setpoint, 0.02);
    const overshoot = this.calculateOvershoot(results.processValue, setpoint);
    const steadyStateError = Math.abs(results.error[results.error.length - 1]);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            controller: 'PID',
            parameters: { kp, ki, kd, setpoint },
            simulation: results,
            performance: {
              settlingTime: settlingTime,
              overshoot: overshoot,
              steadyStateError: steadyStateError,
            },
          }, null, 2),
        },
      ],
    };
  }

  calculateSettlingTime(values, setpoint, tolerance) {
    const band = setpoint * tolerance;
    for (let i = values.length - 1; i >= 0; i--) {
      if (Math.abs(values[i] - setpoint) > band) {
        return i + 1;
      }
    }
    return 0;
  }

  calculateOvershoot(values, setpoint) {
    const maxValue = Math.max(...values);
    if (maxValue > setpoint) {
      return ((maxValue - setpoint) / setpoint) * 100;
    }
    return 0;
  }

  async zieglerNicholsTuning(args) {
    const { ultimateGain, ultimatePeriod, controllerType = 'PID' } = args;

    let kp, ki, kd;

    switch (controllerType) {
      case 'P':
        kp = 0.5 * ultimateGain;
        ki = 0;
        kd = 0;
        break;
      case 'PI':
        kp = 0.45 * ultimateGain;
        ki = 0.54 * ultimateGain / ultimatePeriod;
        kd = 0;
        break;
      case 'PID':
        kp = 0.6 * ultimateGain;
        ki = 1.2 * ultimateGain / ultimatePeriod;
        kd = 0.075 * ultimateGain * ultimatePeriod;
        break;
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            method: 'Ziegler-Nichols',
            controllerType: controllerType,
            input: {
              ultimateGain: ultimateGain,
              ultimatePeriod: ultimatePeriod,
            },
            tunedParameters: {
              kp: kp,
              ki: ki,
              kd: kd,
            },
          }, null, 2),
        },
      ],
    };
  }

  async gradientDescent(args) {
    const { initialParams, learningRate, momentum = 0, iterations } = args;

    const trajectory = [initialParams];
    let params = [...initialParams];
    let velocity = Array(params.length).fill(0);

    // Simple quadratic objective for demonstration
    const computeGradient = (p) => p.map(x => 2 * x);

    for (let i = 0; i < iterations; i++) {
      const grad = computeGradient(params);
      
      // Update with momentum
      velocity = velocity.map((v, idx) => 
        momentum * v - learningRate * grad[idx]
      );
      
      params = params.map((p, idx) => p + velocity[idx]);
      trajectory.push([...params]);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            algorithm: 'Gradient Descent',
            parameters: {
              learningRate: learningRate,
              momentum: momentum,
              iterations: iterations,
            },
            initialParams: initialParams,
            finalParams: params,
            trajectory: trajectory,
          }, null, 2),
        },
      ],
    };
  }

  async kalmanFilter(args) {
    const {
      measurements,
      processNoise,
      measurementNoise,
      initialEstimate = 0,
      initialCovariance = 1
    } = args;

    const estimates = [];
    const covariances = [];
    const kalmanGains = [];

    let x = initialEstimate;
    let P = initialCovariance;

    for (const z of measurements) {
      // Prediction
      const x_pred = x;
      const P_pred = P + processNoise;

      // Update
      const K = P_pred / (P_pred + measurementNoise);
      x = x_pred + K * (z - x_pred);
      P = (1 - K) * P_pred;

      estimates.push(x);
      covariances.push(P);
      kalmanGains.push(K);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            filter: 'Kalman Filter',
            parameters: {
              processNoise: processNoise,
              measurementNoise: measurementNoise,
            },
            measurements: measurements,
            estimates: estimates,
            covariances: covariances,
            kalmanGains: kalmanGains,
          }, null, 2),
        },
      ],
    };
  }

  async modelReferenceAdaptive(args) {
    const { referenceModel, plantParams, adaptationGain, reference, timesteps, dt = 0.01 } = args;

    const results = {
      time: [],
      plantOutput: [],
      modelOutput: [],
      error: [],
      theta: [],
    };

    let yp = 0; // Plant output
    let ym = 0; // Model output
    let theta = 0; // Adaptive parameter

    for (let t = 0; t < timesteps; t++) {
      const time = t * dt;

      // Control input
      const u = theta * reference;

      // Plant dynamics
      const dyp = -plantParams.a * yp + plantParams.b * u;
      yp += dyp * dt;

      // Reference model dynamics
      const dym = -referenceModel.a * ym + referenceModel.b * reference;
      ym += dym * dt;

      // Tracking error
      const e = yp - ym;

      // Adaptation law
      const dtheta = -adaptationGain * e * reference;
      theta += dtheta * dt;

      results.time.push(time);
      results.plantOutput.push(yp);
      results.modelOutput.push(ym);
      results.error.push(e);
      results.theta.push(theta);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            controller: 'Model Reference Adaptive Control (MRAC)',
            referenceModel: referenceModel,
            plantParams: plantParams,
            adaptationGain: adaptationGain,
            simulation: results,
            finalError: results.error[results.error.length - 1],
            finalTheta: results.theta[results.theta.length - 1],
          }, null, 2),
        },
      ],
    };
  }

  async leastSquaresIdentification(args) {
    const { inputs, outputs, order } = args;

    if (inputs.length !== outputs.length) {
      throw new Error('Inputs and outputs must have same length');
    }

    const n = inputs.length - order;
    const Phi = [];
    const Y = [];

    for (let i = order; i < inputs.length; i++) {
      const row = [];
      for (let j = 0; j < order; j++) {
        row.push(-outputs[i - j - 1]);
        row.push(inputs[i - j - 1]);
      }
      Phi.push(row);
      Y.push(outputs[i]);
    }

    // Least squares: theta = (Phi' * Phi)^-1 * Phi' * Y
    const PhiT = math.transpose(Phi);
    const PhiTPhi = math.multiply(PhiT, Phi);
    const PhiTPhiInv = math.inv(PhiTPhi);
    const theta = math.multiply(math.multiply(PhiTPhiInv, PhiT), Y);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            method: 'Least Squares System Identification',
            modelOrder: order,
            identifiedParameters: theta,
            numDataPoints: inputs.length,
          }, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Adaptive Control MCP server running on stdio');
  }
}

const server = new AdaptiveControlServer();
server.run().catch(console.error);
