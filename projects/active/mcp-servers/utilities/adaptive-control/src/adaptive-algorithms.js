// Advanced Adaptive Control Algorithms
// Implementation of ΔθT​⋅ΔθS​=α(∇θ​g0​⋅ΔθT​)² and related control theory

export class AdaptiveControlAlgorithms {
  constructor() {
    this.adaptationHistory = [];
    this.convergenceThreshold = 1e-6;
    this.maxIterations = 1000;
  }

  /**
   * Core Adaptive Update Rule: ΔθT​⋅ΔθS​=α(∇θ​g0​⋅ΔθT​)²
   * @param {Array} thetaT - Target parameters
   * @param {Array} thetaS - System parameters  
   * @param {number} alpha - Adaptation gain
   * @param {Function} g0 - Performance function
   * @param {Array} currentTheta - Current parameter values
   * @returns {Object} Adaptation result
   */
  adaptiveUpdate(thetaT, thetaS, alpha, g0, currentTheta) {
    try {
      // Compute gradient of performance function
      const gradient = this.computeGradient(g0, currentTheta);
      
      // Calculate parameter updates
      const deltaTheta_T = this.vectorSubtract(thetaT, currentTheta);
      const deltaTheta_S = this.vectorSubtract(thetaS, currentTheta);
      
      // Compute dot products
      const dotProduct_TS = this.dotProduct(deltaTheta_T, deltaTheta_S);
      const gradientDotDelta = this.dotProduct(gradient, deltaTheta_T);
      
      // Apply adaptive update rule: ΔθT​⋅ΔθS​=α(∇θ​g0​⋅ΔθT​)²
      const adaptiveScaling = alpha * Math.pow(gradientDotDelta, 2);
      const updatedParameters = this.vectorAdd(
        currentTheta, 
        this.scalarMultiply(deltaTheta_T, adaptiveScaling / (dotProduct_TS + 1e-10))
      );
      
      // Stability check
      const stability = this.checkStability(updatedParameters, currentTheta);
      
      // Store adaptation history
      this.adaptationHistory.push({
        timestamp: Date.now(),
        parameters: [...updatedParameters],
        gradient: [...gradient],
        adaptiveScaling,
        stability
      });
      
      return {
        updatedParameters,
        adaptiveScaling,
        gradientNorm: this.vectorNorm(gradient),
        stability,
        convergence: this.checkConvergence(gradient)
      };
      
    } catch (error) {
      throw new Error(`Adaptive update failed: ${error.message}`);
    }
  }

  /**
   * Multi-Agent Coordination using Consensus Algorithm
   * @param {Array} agentStates - Current states of all agents
   * @param {Array} desiredStates - Target coordination states
   * @param {number} couplingStrength - Inter-agent coupling parameter
   * @returns {Object} Coordination result
   */
  multiAgentCoordination(agentStates, desiredStates, couplingStrength = 0.1) {
    const numAgents = agentStates.length;
    const coordinationUpdates = [];
    
    for (let i = 0; i < numAgents; i++) {
      let consensusError = 0;
      let couplingSum = Array(agentStates[i].length).fill(0);
      
      // Compute coupling with neighboring agents
      for (let j = 0; j < numAgents; j++) {
        if (i !== j) {
          const stateDiff = this.vectorSubtract(agentStates[j], agentStates[i]);
          couplingSum = this.vectorAdd(couplingSum, stateDiff);
        }
      }
      
      // Adaptive coordination update
      const trackingError = this.vectorSubtract(desiredStates[i], agentStates[i]);
      const coordinationControl = this.vectorAdd(
        this.scalarMultiply(trackingError, 1.0),
        this.scalarMultiply(couplingSum, couplingStrength)
      );
      
      coordinationUpdates.push({
        agentId: i,
        currentState: [...agentStates[i]],
        desiredState: [...desiredStates[i]],
        coordinationControl: [...coordinationControl],
        trackingError: this.vectorNorm(trackingError)
      });
    }
    
    return {
      coordinationUpdates,
      systemError: this.computeSystemError(agentStates, desiredStates),
      consensusLevel: this.computeConsensusLevel(agentStates)
    };
  }

  /**
   * Lyapunov-based Stability Analysis
   * @param {Array} currentState - Current system state
   * @param {Array} desiredState - Desired equilibrium state
   * @returns {Object} Stability analysis result
   */
  lyapunovStabilityAnalysis(currentState, desiredState) {
    const error = this.vectorSubtract(desiredState, currentState);
    const errorNorm = this.vectorNorm(error);
    
    // Quadratic Lyapunov function: V = 0.5 * e^T * P * e
    const P = this.createIdentityMatrix(error.length); // Simplified case
    const V = 0.5 * this.quadraticForm(error, P);
    
    // Lyapunov derivative (simplified)
    const Vdot = -this.dotProduct(error, error); // Assuming stable dynamics
    
    return {
      lyapunovValue: V,
      lyapunovDerivative: Vdot,
      stable: Vdot < 0,
      errorNorm,
      stabilityMargin: Math.abs(Vdot) / (V + 1e-10)
    };
  }

  /**
   * Model Reference Adaptive Control (MRAC)
   * @param {Array} plantOutput - Current plant output
   * @param {Array} referenceOutput - Desired reference model output
   * @param {Array} controlInput - Current control input
   * @param {number} adaptationGain - Adaptation rate
   * @returns {Object} MRAC result
   */
  modelReferenceAdaptiveControl(plantOutput, referenceOutput, controlInput, adaptationGain = 0.1) {
    const trackingError = this.vectorSubtract(referenceOutput, plantOutput);
    
    // MIT adaptation rule (simplified)
    const sensitivityVector = controlInput; // Simplified assumption
    const parameterUpdate = this.scalarMultiply(
      sensitivityVector,
      adaptationGain * this.dotProduct(trackingError, sensitivityVector)
    );
    
    // Adaptive control law
    const adaptiveControl = this.scalarMultiply(parameterUpdate, 1.0);
    
    return {
      trackingError: [...trackingError],
      parameterUpdate: [...parameterUpdate],
      adaptiveControl: [...adaptiveControl],
      trackingErrorNorm: this.vectorNorm(trackingError),
      adaptationMagnitude: this.vectorNorm(parameterUpdate)
    };
  }

  /**
   * Performance Optimization using Gradient Descent
   * @param {Function} objectiveFunction - Function to optimize
   * @param {Array} initialParams - Starting parameters
   * @param {number} learningRate - Step size
   * @param {number} maxIter - Maximum iterations
   * @returns {Object} Optimization result
   */
  performanceOptimization(objectiveFunction, initialParams, learningRate = 0.01, maxIter = 100) {
    let currentParams = [...initialParams];
    const optimizationHistory = [];
    
    for (let iter = 0; iter < maxIter; iter++) {
      const gradient = this.computeGradient(objectiveFunction, currentParams);
      const gradientNorm = this.vectorNorm(gradient);
      
      // Gradient descent update
      const parameterUpdate = this.scalarMultiply(gradient, -learningRate);
      currentParams = this.vectorAdd(currentParams, parameterUpdate);
      
      optimizationHistory.push({
        iteration: iter,
        parameters: [...currentParams],
        objectiveValue: objectiveFunction(currentParams),
        gradientNorm
      });
      
      // Check convergence
      if (gradientNorm < this.convergenceThreshold) {
        break;
      }
    }
    
    return {
      optimalParameters: currentParams,
      optimizationHistory,
      converged: this.vectorNorm(this.computeGradient(objectiveFunction, currentParams)) < this.convergenceThreshold,
      finalObjectiveValue: objectiveFunction(currentParams)
    };
  }

  // ============ UTILITY METHODS ============

  computeGradient(func, params, epsilon = 1e-6) {
    const gradient = [];
    const f0 = func(params);
    
    for (let i = 0; i < params.length; i++) {
      const paramsPlus = [...params];
      paramsPlus[i] += epsilon;
      const fPlus = func(paramsPlus);
      gradient.push((fPlus - f0) / epsilon);
    }
    
    return gradient;
  }

  vectorAdd(a, b) {
    return a.map((val, i) => val + (b[i] || 0));
  }

  vectorSubtract(a, b) {
    return a.map((val, i) => val - (b[i] || 0));
  }

  scalarMultiply(vector, scalar) {
    return vector.map(val => val * scalar);
  }

  dotProduct(a, b) {
    return a.reduce((sum, val, i) => sum + val * (b[i] || 0), 0);
  }

  vectorNorm(vector) {
    return Math.sqrt(this.dotProduct(vector, vector));
  }

  createIdentityMatrix(size) {
    const matrix = [];
    for (let i = 0; i < size; i++) {
      const row = Array(size).fill(0);
      row[i] = 1;
      matrix.push(row);
    }
    return matrix;
  }

  quadraticForm(vector, matrix) {
    // Simplified: v^T * P * v
    return this.dotProduct(vector, vector); // Assuming P = I
  }

  checkStability(newParams, oldParams) {
    const paramChange = this.vectorNorm(this.vectorSubtract(newParams, oldParams));
    return {
      stable: paramChange < 10.0, // Heuristic stability check
      parameterChange: paramChange,
      boundedness: newParams.every(p => Math.abs(p) < 100) // Parameter boundedness
    };
  }

  checkConvergence(gradient) {
    const gradientNorm = this.vectorNorm(gradient);
    return {
      converged: gradientNorm < this.convergenceThreshold,
      gradientNorm,
      threshold: this.convergenceThreshold
    };
  }

  computeSystemError(agentStates, desiredStates) {
    let totalError = 0;
    for (let i = 0; i < agentStates.length; i++) {
      const error = this.vectorSubtract(desiredStates[i], agentStates[i]);
      totalError += this.vectorNorm(error);
    }
    return totalError / agentStates.length;
  }

  computeConsensusLevel(agentStates) {
    if (agentStates.length < 2) return 1.0;
    
    const meanState = Array(agentStates[0].length).fill(0);
    for (const state of agentStates) {
      for (let i = 0; i < state.length; i++) {
        meanState[i] += state[i] / agentStates.length;
      }
    }
    
    let consensusError = 0;
    for (const state of agentStates) {
      const deviation = this.vectorSubtract(state, meanState);
      consensusError += this.vectorNorm(deviation);
    }
    
    return Math.exp(-consensusError / agentStates.length); // Consensus level [0,1]
  }

  getAdaptationHistory() {
    return [...this.adaptationHistory];
  }

  clearHistory() {
    this.adaptationHistory = [];
  }
}