import React, { useState, useMemo, useCallback } from 'react';
import { XAxis, YAxis, CartesianGrid, Tooltip, Legend, ScatterChart, Scatter, ResponsiveContainer, BarChart, Bar } from 'recharts';

const AdvancedMultidimensionalStochasticAnalyzer = () => {
  const [activeModel, setActiveModel] = useState('gbm');
  const [dimensionMode, setDimensionMode] = useState('3D');
  const [analysisMode, setAnalysisMode] = useState('trajectory');
  const [projectionView, setProjectionView] = useState('xy');
  const [numSteps] = useState(1000);
  const [timeHorizon] = useState(1.0);
  const [parameters, setParameters] = useState({
    mu: 0.05,          // drift rate
    sigma: 0.2,        // volatility
    muZ: 0.02,         // z-direction drift
    sigmaZ: 0.15,      // z-direction volatility
    correlation: 0.3,   // XY correlation
    correlationXZ: 0.1, // XZ correlation
    correlationYZ: -0.2, // YZ correlation
    kappa: 2.0,        // mean reversion speed
    theta: 0.04,       // long-term variance
    xi: 0.1,           // vol of vol
    rho: -0.7,         // correlation
    lambda: 0.1,       // jump intensity
    muJ: -0.1,         // jump mean
    sigmaJ: 0.15,      // jump volatility
    hurst: 0.7,        // Hurst parameter
    nu: 0.2,           // variance gamma parameter
    alpha: 1.5,        // levy alpha
    r: 0.03            // risk-free rate
  });

  // Multi-dimensional stochastic process generators with correlated components
  const generateCorrelatedRandoms = useCallback((rho_xy: number, rho_xz: number, rho_yz: number) => {
    // Generate three independent standard normals
    const u1 = Math.random() * 2 - 1;
    const u2 = Math.random() * 2 - 1;
    const u3 = Math.random() * 2 - 1;
    
    // Box-Muller transformation approximation
    const z1 = u1 * Math.sqrt(3);
    const z2 = u2 * Math.sqrt(3);
    const z3 = u3 * Math.sqrt(3);
    
    // Construct correlated random variables using Cholesky decomposition approach
    const x = z1;
    const y = rho_xy * z1 + Math.sqrt(1 - rho_xy ** 2) * z2;
    const z = rho_xz * z1 + 
             (rho_yz - rho_xy * rho_xz) / Math.sqrt(1 - rho_xy ** 2) * z2 + 
             Math.sqrt(1 - rho_xz ** 2 - ((rho_yz - rho_xy * rho_xz) / Math.sqrt(1 - rho_xy ** 2)) ** 2) * z3;

    return { x, y, z };
  }, []);

  const generateMultidimensionalGBM = useCallback((steps: number, T: number) => {
    const dt = T / steps;
    const path = [{
      time: 0, x: 100, y: 100, z: 100, 
      logX: Math.log(100), logY: Math.log(100), logZ: Math.log(100),
      step: 0, displacement3D: 0, radiusVector: Math.sqrt(3 * 100 ** 2)
    }];
    
    let X = 100, Y = 100, Z = 100;
    
    for (let i = 1; i <= steps; i++) {
      const randoms = generateCorrelatedRandoms(
        parameters.correlation, 
        parameters.correlationXZ, 
        parameters.correlationYZ
      );
      
      const dWx = Math.sqrt(dt) * randoms.x;
      const dWy = Math.sqrt(dt) * randoms.y;
      const dWz = Math.sqrt(dt) * randoms.z;
      
      X *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * dWx);
      Y *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * dWy);
      Z *= Math.exp((parameters.muZ - 0.5 * parameters.sigmaZ ** 2) * dt + parameters.sigmaZ * dWz);
      
      const displacement3D = Math.sqrt((X - 100) ** 2 + (Y - 100) ** 2 + (Z - 100) ** 2);
      const radiusVector = Math.sqrt(X ** 2 + Y ** 2 + Z ** 2);
      
      path.push({
        time: i * dt,
        x: X, y: Y, z: Z,
        logX: Math.log(X), logY: Math.log(Y), logZ: Math.log(Z),
        step: i,
        displacement3D,
        radiusVector
      });
    }
    return path;
  }, [parameters, generateCorrelatedRandoms]);

  const generateMultidimensionalOU = useCallback((steps: number, T: number) => {
    const dt = T / steps;
    const equilibrium = { x: Math.log(100), y: Math.log(100), z: Math.log(100) };
    const path = [{
      time: 0, x: 100, y: 100, z: 100,
      logX: equilibrium.x, logY: equilibrium.y, logZ: equilibrium.z,
      step: 0, displacement3D: 0, radiusVector: Math.sqrt(3 * 100 ** 2)
    }];
    
    let logX = equilibrium.x, logY = equilibrium.y, logZ = equilibrium.z;
    
    for (let i = 1; i <= steps; i++) {
      const randoms = generateCorrelatedRandoms(
        parameters.correlation,
        parameters.correlationXZ,
        parameters.correlationYZ
      );
      
      const dWx = Math.sqrt(dt) * randoms.x;
      const dWy = Math.sqrt(dt) * randoms.y;
      const dWz = Math.sqrt(dt) * randoms.z;
      
      // Three-dimensional mean-reverting process
      logX += parameters.kappa * (equilibrium.x - logX) * dt + parameters.sigma * dWx;
      logY += parameters.kappa * (equilibrium.y - logY) * dt + parameters.sigma * dWy;
      logZ += parameters.kappa * (equilibrium.z - logZ) * dt + parameters.sigmaZ * dWz;
      
      const X = Math.exp(logX);
      const Y = Math.exp(logY);
      const Z = Math.exp(logZ);
      
      const displacement3D = Math.sqrt((X - 100) ** 2 + (Y - 100) ** 2 + (Z - 100) ** 2);
      const radiusVector = Math.sqrt(X ** 2 + Y ** 2 + Z ** 2);
      
      path.push({
        time: i * dt,
        x: X, y: Y, z: Z,
        logX, logY, logZ,
        step: i,
        displacement3D,
        radiusVector
      });
    }
    return path;
  }, [parameters, generateCorrelatedRandoms]);

  const generateMultidimensionalJumpDiffusion = useCallback((steps: number, T: number) => {
    const dt = T / steps;
    const path = [{
      time: 0, x: 100, y: 100, z: 100,
      logX: Math.log(100), logY: Math.log(100), logZ: Math.log(100),
      step: 0, displacement3D: 0, radiusVector: Math.sqrt(3 * 100 ** 2)
    }];
    
    let X = 100, Y = 100, Z = 100;
    
    for (let i = 1; i <= steps; i++) {
      const randoms = generateCorrelatedRandoms(
        parameters.correlation,
        parameters.correlationXZ,
        parameters.correlationYZ
      );
      
      const dWx = Math.sqrt(dt) * randoms.x;
      const dWy = Math.sqrt(dt) * randoms.y;
      const dWz = Math.sqrt(dt) * randoms.z;
      
      // Correlated jump events
      let jumpX = 0, jumpY = 0, jumpZ = 0;
      if (Math.random() < parameters.lambda * dt) {
        const jumpRandom = generateCorrelatedRandoms(0.8, 0.6, 0.4); // Strong jump correlation
        jumpX = Math.exp(parameters.muJ + parameters.sigmaJ * jumpRandom.x) - 1;
        jumpY = Math.exp(parameters.muJ + parameters.sigmaJ * jumpRandom.y) - 1;
        jumpZ = Math.exp(parameters.muJ + parameters.sigmaJ * jumpRandom.z) - 1;
      }
      
      X *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * dWx) * (1 + jumpX);
      Y *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * dWy) * (1 + jumpY);
      Z *= Math.exp((parameters.muZ - 0.5 * parameters.sigmaZ ** 2) * dt + parameters.sigmaZ * dWz) * (1 + jumpZ);
      
      X = Math.max(X, 0.01);
      Y = Math.max(Y, 0.01);
      Z = Math.max(Z, 0.01);
      
      const displacement3D = Math.sqrt((X - 100) ** 2 + (Y - 100) ** 2 + (Z - 100) ** 2);
      const radiusVector = Math.sqrt(X ** 2 + Y ** 2 + Z ** 2);
      
      path.push({
        time: i * dt,
        x: X, y: Y, z: Z,
        logX: Math.log(X), logY: Math.log(Y), logZ: Math.log(Z),
        step: i,
        displacement3D,
        radiusVector
      });
    }
    return path;
  }, [parameters, generateCorrelatedRandoms]);

  const generateMultidimensionalFractionalBrownian = useCallback((steps: number, T: number) => {
    const dt = T / steps;
    const path = [{
      time: 0, x: 100, y: 100, z: 100,
      logX: Math.log(100), logY: Math.log(100), logZ: Math.log(100),
      step: 0, displacement3D: 0, radiusVector: Math.sqrt(3 * 100 ** 2)
    }];
    
    let X = 100, Y = 100, Z = 100;
    let pastIncrementsX = [], pastIncrementsY = [], pastIncrementsZ = [];
    const memory = Math.min(50, steps);
    
    for (let i = 1; i <= steps; i++) {
      const randoms = generateCorrelatedRandoms(
        parameters.correlation,
        parameters.correlationXZ,
        parameters.correlationYZ
      );
      
      let incrementX = Math.sqrt(dt) * randoms.x;
      let incrementY = Math.sqrt(dt) * randoms.y;
      let incrementZ = Math.sqrt(dt) * randoms.z;
      
      // Apply fractional Brownian motion memory effects
      if (pastIncrementsX.length > 0 && parameters.hurst !== 0.5) {
        const memoryEffectX = pastIncrementsX.slice(-memory).reduce((sum, past, idx) => {
          const weight = Math.pow(idx + 1, parameters.hurst - 0.5);
          return sum + weight * past;
        }, 0) * (parameters.hurst - 0.5) * 0.1;
        
        const memoryEffectY = pastIncrementsY.slice(-memory).reduce((sum, past, idx) => {
          const weight = Math.pow(idx + 1, parameters.hurst - 0.5);
          return sum + weight * past;
        }, 0) * (parameters.hurst - 0.5) * 0.1;
        
        const memoryEffectZ = pastIncrementsZ.slice(-memory).reduce((sum, past, idx) => {
          const weight = Math.pow(idx + 1, parameters.hurst - 0.5);
          return sum + weight * past;
        }, 0) * (parameters.hurst - 0.5) * 0.1;
        
        incrementX += memoryEffectX;
        incrementY += memoryEffectY;
        incrementZ += memoryEffectZ;
      }
      
      pastIncrementsX.push(incrementX);
      pastIncrementsY.push(incrementY);
      pastIncrementsZ.push(incrementZ);
      
      if (pastIncrementsX.length > memory) {
        pastIncrementsX.shift();
        pastIncrementsY.shift();
        pastIncrementsZ.shift();
      }
      
      X *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * incrementX);
      Y *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * incrementY);
      Z *= Math.exp((parameters.muZ - 0.5 * parameters.sigmaZ ** 2) * dt + parameters.sigmaZ * incrementZ);
      
      const displacement3D = Math.sqrt((X - 100) ** 2 + (Y - 100) ** 2 + (Z - 100) ** 2);
      const radiusVector = Math.sqrt(X ** 2 + Y ** 2 + Z ** 2);
      
      path.push({
        time: i * dt,
        x: X, y: Y, z: Z,
        logX: Math.log(X), logY: Math.log(Y), logZ: Math.log(Z),
        step: i,
        displacement3D,
        radiusVector
      });
    }
    return path;
  }, [parameters, generateCorrelatedRandoms]);

  // Generate process data based on selected model
  const processData = useMemo(() => {
    if (dimensionMode === '2D') {
      // Use existing 2D implementations (simplified)
      switch (activeModel) {
        case 'gbm': return generateMultidimensionalGBM(numSteps, timeHorizon).map(p => ({...p, z: 100}));
        case 'ou': return generateMultidimensionalOU(numSteps, timeHorizon).map(p => ({...p, z: 100}));
        case 'jump': return generateMultidimensionalJumpDiffusion(numSteps, timeHorizon).map(p => ({...p, z: 100}));
        case 'fbm': return generateMultidimensionalFractionalBrownian(numSteps, timeHorizon).map(p => ({...p, z: 100}));
        default: return generateMultidimensionalGBM(numSteps, timeHorizon).map(p => ({...p, z: 100}));
      }
    } else {
      switch (activeModel) {
        case 'gbm': return generateMultidimensionalGBM(numSteps, timeHorizon);
        case 'ou': return generateMultidimensionalOU(numSteps, timeHorizon);
        case 'jump': return generateMultidimensionalJumpDiffusion(numSteps, timeHorizon);
        case 'fbm': return generateMultidimensionalFractionalBrownian(numSteps, timeHorizon);
        default: return generateMultidimensionalGBM(numSteps, timeHorizon);
      }
    }
  }, [activeModel, dimensionMode, numSteps, timeHorizon, generateMultidimensionalGBM, generateMultidimensionalOU, generateMultidimensionalJumpDiffusion, generateMultidimensionalFractionalBrownian]);

  // Multidimensional financial metrics
  const multidimensionalMetrics = useMemo(() => {
    if (processData.length < 2) return {};
    
    // Calculate returns for each dimension
    const returnsX: number[] = [], returnsY: number[] = [], returnsZ: number[] = [];
    for (let i = 1; i < processData.length; i++) {
      returnsX.push(Math.log(processData[i].x / processData[i-1].x));
      returnsY.push(Math.log(processData[i].y / processData[i-1].y));
      returnsZ.push(Math.log(processData[i].z / processData[i-1].z));
    }
    
    // Dimensional statistics
    const meanReturnX = returnsX.reduce((a, b) => a + b, 0) / returnsX.length;
    const meanReturnY = returnsY.reduce((a, b) => a + b, 0) / returnsY.length;
    const meanReturnZ = returnsZ.reduce((a, b) => a + b, 0) / returnsZ.length;
    
    const varianceX = returnsX.reduce((sum, r) => sum + (r - meanReturnX) ** 2, 0) / (returnsX.length - 1);
    const varianceY = returnsY.reduce((sum, r) => sum + (r - meanReturnY) ** 2, 0) / (returnsY.length - 1);
    const varianceZ = returnsZ.reduce((sum, r) => sum + (r - meanReturnZ) ** 2, 0) / (returnsZ.length - 1);
    
    // Cross-correlations
    const covarianceXY = returnsX.reduce((sum, rx, i) => sum + (rx - meanReturnX) * (returnsY[i] - meanReturnY), 0) / (returnsX.length - 1);
    const covarianceXZ = returnsX.reduce((sum, rx, i) => sum + (rx - meanReturnX) * (returnsZ[i] - meanReturnZ), 0) / (returnsX.length - 1);
    const covarianceYZ = returnsY.reduce((sum, ry, i) => sum + (ry - meanReturnY) * (returnsZ[i] - meanReturnZ), 0) / (returnsY.length - 1);
    
    const correlationXY = covarianceXY / Math.sqrt(varianceX * varianceY);
    const correlationXZ = covarianceXZ / Math.sqrt(varianceX * varianceZ);
    const correlationYZ = covarianceYZ / Math.sqrt(varianceY * varianceZ);
    
    // 3D displacement metrics
    const finalDisplacement = processData[processData.length - 1].displacement3D;
    const maxDisplacement = Math.max(...processData.map(p => p.displacement3D));
    const meanDisplacement = processData.reduce((sum, p) => sum + p.displacement3D, 0) / processData.length;
    
    // Portfolio-level metrics
    const portfolioReturns = returnsX.map((rx, i) => (rx + returnsY[i] + returnsZ[i]) / 3);
    const portfolioMean = portfolioReturns.reduce((a, b) => a + b, 0) / portfolioReturns.length;
    const portfolioVariance = portfolioReturns.reduce((sum, r) => sum + (r - portfolioMean) ** 2, 0) / (portfolioReturns.length - 1);
    
    return {
      // Dimensional returns
      annualizedReturnX: (meanReturnX * 252).toFixed(4),
      annualizedReturnY: (meanReturnY * 252).toFixed(4),
      annualizedReturnZ: (meanReturnZ * 252).toFixed(4),
      
      // Dimensional volatilities
      annualizedVolatilityX: (Math.sqrt(varianceX * 252)).toFixed(4),
      annualizedVolatilityY: (Math.sqrt(varianceY * 252)).toFixed(4),
      annualizedVolatilityZ: (Math.sqrt(varianceZ * 252)).toFixed(4),
      
      // Cross-correlations
      correlationXY: correlationXY.toFixed(4),
      correlationXZ: correlationXZ.toFixed(4),
      correlationYZ: correlationYZ.toFixed(4),
      
      // 3D spatial metrics
      finalDisplacement: finalDisplacement.toFixed(2),
      maxDisplacement: maxDisplacement.toFixed(2),
      meanDisplacement: meanDisplacement.toFixed(2),
      
      // Portfolio metrics
      portfolioReturn: (portfolioMean * 252).toFixed(4),
      portfolioVolatility: (Math.sqrt(portfolioVariance * 252)).toFixed(4),
      portfolioSharpe: ((portfolioMean * 252 - parameters.r) / Math.sqrt(portfolioVariance * 252)).toFixed(4)
    };
  }, [processData, parameters.r]);

  // Projection data for visualization
  const projectionData = useMemo(() => {
    return processData.slice(0, Math.min(1000, processData.length)).map(point => {
      switch (projectionView) {
        case 'xy': return { primary: point.x, secondary: point.y, time: point.time };
        case 'xz': return { primary: point.x, secondary: point.z, time: point.time };
        case 'yz': return { primary: point.y, secondary: point.z, time: point.time };
        case '3d': return { primary: point.displacement3D, secondary: point.radiusVector, time: point.time };
        default: return { primary: point.x, secondary: point.y, time: point.time };
      }
    });
  }, [processData, projectionView]);

  // Model configurations with 3D extensions
  const multidimensionalModelConfigurations = {
    gbm: {
      name: 'Multidimensional Geometric Brownian Motion',
      equation: 'dSᵢ = μᵢSᵢ dt + σᵢSᵢ dWᵢ, i ∈ {X,Y,Z}',
      application: 'Multi-Asset Portfolio Modeling',
      complexity: 'Medium',
      dimensionalAnalysis: 'Independent asset dynamics with correlation structure',
      spatialProperties: ['Lognormal marginals', 'Gaussian correlation', 'Markovian evolution']
    },
    ou: {
      name: 'Multidimensional Ornstein-Uhlenbeck Process',
      equation: 'dXᵢ = κᵢ(θᵢ - Xᵢ)dt + σᵢ dWᵢ',
      application: 'Multi-Factor Interest Rate Models',
      complexity: 'High',
      dimensionalAnalysis: 'Correlated mean-reverting factors',
      spatialProperties: ['Stationary distribution', 'Exponential correlation decay', 'Gaussian marginals']
    },
    jump: {
      name: 'Multidimensional Jump-Diffusion Process',
      equation: 'dSᵢ = μᵢSᵢ dt + σᵢSᵢ dWᵢ + Sᵢ(e^{Jᵢ} - 1)dNᵢ',
      application: 'Systemic Risk and Contagion Modeling',
      complexity: 'Very High',
      dimensionalAnalysis: 'Correlated jump events across dimensions',
      spatialProperties: ['Heavy-tailed marginals', 'Jump clustering', 'Regime-dependent correlation']
    },
    fbm: {
      name: 'Multidimensional Fractional Brownian Motion',
      equation: 'E[BᵢH(t)BⱼH(s)] = ½(|t|^{2H} + |s|^{2H} - |t-s|^{2H})δᵢⱼ',
      application: 'Long-Memory Multi-Asset Dynamics',
      complexity: 'Very High',
      dimensionalAnalysis: 'Cross-dimensional memory effects',
      spatialProperties: ['Self-similarity', 'Long-range dependence', 'Non-Markovian structure']
    }
  };

  return (
    <div className="w-full max-w-7xl mx-auto p-6 bg-white">
      {/* Header with Dimensional Analysis Framework */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-4">
          Multidimensional Stochastic Process Analysis Framework
        </h1>
        <p className="text-gray-600 max-w-5xl">
          Comprehensive analytical framework for investigating three-dimensional stochastic systems with 
          correlated dynamics, spatial statistics, and multifactor financial modeling applications.
        </p>
      </div>

      {/* Enhanced Control Panel */}
      <div className="bg-gray-50 p-6 rounded-lg mb-8">
        <h2 className="text-xl font-semibold mb-4">Dimensional Configuration Matrix</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
          {/* Model Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Stochastic Process Architecture
            </label>
            <select 
              value={activeModel}
              onChange={(e) => setActiveModel(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              {Object.entries(multidimensionalModelConfigurations).map(([key, config]) => (
                <option key={key} value={key}>{config.name}</option>
              ))}
            </select>
          </div>

          {/* Dimensional Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Spatial Dimensionality
            </label>
            <select 
              value={dimensionMode}
              onChange={(e) => setDimensionMode(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              <option value="2D">2D System (XY-Plane)</option>
              <option value="3D">3D System (XYZ-Space)</option>
            </select>
          </div>

          {/* Projection View */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Visualization Projection
            </label>
            <select 
              value={projectionView}
              onChange={(e) => setProjectionView(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              <option value="xy">XY-Plane Projection</option>
              <option value="xz">XZ-Plane Projection</option>
              <option value="yz">YZ-Plane Projection</option>
              <option value="3d">3D Displacement Analysis</option>
            </select>
          </div>

          {/* Analysis Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Analytical Framework
            </label>
            <select 
              value={analysisMode}
              onChange={(e) => setAnalysisMode(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              <option value="trajectory">Trajectory Evolution</option>
              <option value="correlation">Cross-Dimensional Correlation</option>
              <option value="displacement">3D Displacement Analysis</option>
              <option value="portfolio">Portfolio Dynamics</option>
            </select>
          </div>
        </div>

        {/* Advanced Parameter Configuration Matrix */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              X-Drift (μₓ): {parameters.mu.toFixed(3)}
            </label>
            <input
              type="range"
              min="-0.1"
              max="0.3"
              step="0.01"
              value={parameters.mu}
              onChange={(e) => setParameters(prev => ({...prev, mu: parseFloat(e.target.value)}))}
              className="w-full"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Y-Volatility (σᵧ): {parameters.sigma.toFixed(3)}
            </label>
            <input
              type="range"
              min="0.05"
              max="0.8"
              step="0.01"
              value={parameters.sigma}
              onChange={(e) => setParameters(prev => ({...prev, sigma: parseFloat(e.target.value)}))}
              className="w-full"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Z-Drift (μᵤ): {parameters.muZ.toFixed(3)}
            </label>
            <input
              type="range"
              min="-0.1"
              max="0.3"
              step="0.01"
              value={parameters.muZ}
              onChange={(e) => setParameters(prev => ({...prev, muZ: parseFloat(e.target.value)}))}
              className="w-full"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Z-Volatility (σᵤ): {parameters.sigmaZ.toFixed(3)}
            </label>
            <input
              type="range"
              min="0.05"
              max="0.8"
              step="0.01"
              value={parameters.sigmaZ}
              onChange={(e) => setParameters(prev => ({...prev, sigmaZ: parseFloat(e.target.value)}))}
              className="w-full"
            />
          </div>
        </div>

        {/* Correlation Structure Matrix */}
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              ρ(X,Y): {parameters.correlation.toFixed(3)}
            </label>
            <input
              type="range"
              min="-0.95"
              max="0.95"
              step="0.05"
              value={parameters.correlation}
              onChange={(e) => setParameters(prev => ({...prev, correlation: parseFloat(e.target.value)}))}
              className="w-full"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              ρ(X,Z): {parameters.correlationXZ.toFixed(3)}
            </label>
            <input
              type="range"
              min="-0.95"
              max="0.95"
              step="0.05"
              value={parameters.correlationXZ}
              onChange={(e) => setParameters(prev => ({...prev, correlationXZ: parseFloat(e.target.value)}))}
              className="w-full"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              ρ(Y,Z): {parameters.correlationYZ.toFixed(3)}
            </label>
            <input
              type="range"
              min="-0.95"
              max="0.95"
              step="0.05"
              value={parameters.correlationYZ}
              onChange={(e) => setParameters(prev => ({...prev, correlationYZ: parseFloat(e.target.value)}))}
              className="w-full"
            />
          </div>
        </div>
      </div>

      {/* Multidimensional Model Analysis Framework */}
      <div className="bg-blue-50 border border-blue-200 p-6 rounded-lg mb-8">
        <h3 className="text-lg font-semibold text-blue-900 mb-3">
          Dimensional Analysis: {multidimensionalModelConfigurations[activeModel as keyof typeof multidimensionalModelConfigurations].name}
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <p className="text-blue-800 font-mono text-sm mb-2">
              <strong>Mathematical Framework:</strong><br />
              {multidimensionalModelConfigurations[activeModel as keyof typeof multidimensionalModelConfigurations].equation}
            </p>
            <p className="text-blue-700 text-sm">
              <strong>Application Domain:</strong> {multidimensionalModelConfigurations[activeModel as keyof typeof multidimensionalModelConfigurations].application}
            </p>
          </div>
          <div>
            <p className="text-blue-700 text-sm mb-2">
              <strong>Dimensional Analysis:</strong><br />
              {multidimensionalModelConfigurations[activeModel as keyof typeof multidimensionalModelConfigurations].dimensionalAnalysis}
            </p>
            <p className="text-blue-700 text-sm">
              <strong>Complexity Assessment:</strong> {multidimensionalModelConfigurations[activeModel as keyof typeof multidimensionalModelConfigurations].complexity}
            </p>
          </div>
          <div className="bg-white p-4 rounded border">
            <h4 className="font-semibold text-gray-800 mb-2">Multidimensional Metrics</h4>
            <div className="text-sm space-y-1">
              <div>Portfolio Return: <span className="font-mono">{multidimensionalMetrics.portfolioReturn}</span></div>
              <div>Portfolio Vol: <span className="font-mono">{multidimensionalMetrics.portfolioVolatility}</span></div>
              <div>Portfolio Sharpe: <span className="font-mono">{multidimensionalMetrics.portfolioSharpe}</span></div>
              <div>3D Displacement: <span className="font-mono">{multidimensionalMetrics.finalDisplacement}</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Advanced Visualization Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {/* Primary Projection Visualization */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">
            {projectionView === 'xy' ? 'XY-Plane Trajectory' :
             projectionView === 'xz' ? 'XZ-Plane Trajectory' :
             projectionView === 'yz' ? 'YZ-Plane Trajectory' : '3D Displacement Evolution'}
          </h3>
          <ResponsiveContainer width="100%" height={400}>
            <ScatterChart data={projectionData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="primary"
                label={{ 
                  value: projectionView === 'xy' ? 'X-Component' :
                         projectionView === 'xz' ? 'X-Component' :
                         projectionView === 'yz' ? 'Y-Component' : '3D Displacement',
                  position: 'insideBottom', offset: -5 
                }}
              />
              <YAxis 
                dataKey="secondary"
                label={{ 
                  value: projectionView === 'xy' ? 'Y-Component' :
                         projectionView === 'xz' ? 'Z-Component' :
                         projectionView === 'yz' ? 'Z-Component' : 'Radius Vector',
                  angle: -90, position: 'insideLeft' 
                }}
              />
              <Tooltip
                formatter={(value: number | string, name: string) => [typeof value === 'number' ? value.toFixed(2) : value, name]}
                labelFormatter={(_label, payload) =>
                  payload?.[0] ? `t = ${payload[0].payload.time.toFixed(3)}` : ''
                }
              />
              <Scatter
                data={projectionData}
                fill="#2563eb"
                fillOpacity={0.6}
              />
            </ScatterChart>
          </ResponsiveContainer>
        </div>

        {/* Cross-Dimensional Correlation Analysis */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">Cross-Dimensional Correlation Matrix</h3>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={[
              { pair: 'ρ(X,Y)', empirical: parseFloat(multidimensionalMetrics.correlationXY || '0'), theoretical: parameters.correlation },
              { pair: 'ρ(X,Z)', empirical: parseFloat(multidimensionalMetrics.correlationXZ || '0'), theoretical: parameters.correlationXZ },
              { pair: 'ρ(Y,Z)', empirical: parseFloat(multidimensionalMetrics.correlationYZ || '0'), theoretical: parameters.correlationYZ }
            ]}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="pair" />
              <YAxis domain={[-1, 1]} />
              <Tooltip
                formatter={(value: number | string, name: string) => [typeof value === 'number' ? value.toFixed(3) : value, name]}
              />
              <Legend />
              <Bar dataKey="empirical" fill="#2563eb" name="Empirical Correlation" />
              <Bar dataKey="theoretical" fill="#6b7280" name="Theoretical Correlation" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Comprehensive Dimensional Analysis Table */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden mb-8">
        <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
          <h3 className="text-lg font-semibold">Multidimensional Statistical Analysis Framework</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Dimensional Component
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Annualized Return
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Annualized Volatility
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Risk Contribution
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Dimensional Weight
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              <tr>
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">X-Component</td>
                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{multidimensionalMetrics.annualizedReturnX}</td>
                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{multidimensionalMetrics.annualizedVolatilityX}</td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  {((parseFloat(multidimensionalMetrics.annualizedVolatilityX || '0') ** 2) /
                    (parseFloat(multidimensionalMetrics.annualizedVolatilityX || '0') ** 2 +
                     parseFloat(multidimensionalMetrics.annualizedVolatilityY || '0') ** 2 +
                     parseFloat(multidimensionalMetrics.annualizedVolatilityZ || '0') ** 2) * 100).toFixed(1)}%
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">33.3%</td>
              </tr>
              <tr>
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">Y-Component</td>
                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{multidimensionalMetrics.annualizedReturnY}</td>
                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{multidimensionalMetrics.annualizedVolatilityY}</td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  {((parseFloat(multidimensionalMetrics.annualizedVolatilityY || '0') ** 2) /
                    (parseFloat(multidimensionalMetrics.annualizedVolatilityX || '0') ** 2 +
                     parseFloat(multidimensionalMetrics.annualizedVolatilityY || '0') ** 2 +
                     parseFloat(multidimensionalMetrics.annualizedVolatilityZ || '0') ** 2) * 100).toFixed(1)}%
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">33.3%</td>
              </tr>
              <tr>
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">Z-Component</td>
                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{multidimensionalMetrics.annualizedReturnZ}</td>
                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{multidimensionalMetrics.annualizedVolatilityZ}</td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  {((parseFloat(multidimensionalMetrics.annualizedVolatilityZ || '0') ** 2) /
                    (parseFloat(multidimensionalMetrics.annualizedVolatilityX || '0') ** 2 +
                     parseFloat(multidimensionalMetrics.annualizedVolatilityY || '0') ** 2 +
                     parseFloat(multidimensionalMetrics.annualizedVolatilityZ || '0') ** 2) * 100).toFixed(1)}%
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">33.3%</td>
              </tr>
              <tr className="bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap font-bold text-gray-900">Portfolio Aggregate</td>
                <td className="px-6 py-4 text-sm text-gray-900 font-mono font-bold">{multidimensionalMetrics.portfolioReturn}</td>
                <td className="px-6 py-4 text-sm text-gray-900 font-mono font-bold">{multidimensionalMetrics.portfolioVolatility}</td>
                <td className="px-6 py-4 text-sm text-gray-900 font-bold">100.0%</td>
                <td className="px-6 py-4 text-sm text-gray-900 font-bold">100.0%</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Spatial Properties Analysis Framework */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
        <div className="bg-green-50 border border-green-200 p-6 rounded-lg">
          <h3 className="text-lg font-semibold text-green-900 mb-3">
            Dimensional Properties Analysis
          </h3>
          <div className="space-y-3">
            {multidimensionalModelConfigurations[activeModel as keyof typeof multidimensionalModelConfigurations].spatialProperties.map((property, idx) => (
              <div key={idx} className="text-green-800 text-sm flex items-start">
                <span className="text-green-600 mr-2 font-bold">•</span>
                <span>{property}</span>
              </div>
            ))}
          </div>
          
          <div className="mt-4 pt-4 border-t border-green-200">
            <h4 className="font-semibold text-green-900 mb-2">Spatial Metrics:</h4>
            <div className="text-sm text-green-800 space-y-1">
              <div>Max 3D Displacement: <span className="font-mono">{multidimensionalMetrics.maxDisplacement}</span></div>
              <div>Mean 3D Displacement: <span className="font-mono">{multidimensionalMetrics.meanDisplacement}</span></div>
              <div>Final Position Vector: <span className="font-mono">{multidimensionalMetrics.finalDisplacement}</span></div>
            </div>
          </div>
        </div>
        
        <div className="bg-blue-50 border border-blue-200 p-6 rounded-lg">
          <h3 className="text-lg font-semibold text-blue-900 mb-3">
            Correlation Structure Assessment
          </h3>
          
          <div className="space-y-3">
            <div className="bg-white p-3 rounded border">
              <div className="text-sm text-blue-800">
                <strong>XY-Correlation:</strong> {multidimensionalMetrics.correlationXY}
                <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                  <div 
                    className="bg-blue-600 h-2 rounded-full" 
                    style={{ width: `${(Math.abs(parseFloat(multidimensionalMetrics.correlationXY || '0')) * 100)}%` }}
                  ></div>
                </div>
              </div>
            </div>
            
            <div className="bg-white p-3 rounded border">
              <div className="text-sm text-blue-800">
                <strong>XZ-Correlation:</strong> {multidimensionalMetrics.correlationXZ}
                <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                  <div 
                    className="bg-blue-600 h-2 rounded-full" 
                    style={{ width: `${(Math.abs(parseFloat(multidimensionalMetrics.correlationXZ || '0')) * 100)}%` }}
                  ></div>
                </div>
              </div>
            </div>
            
            <div className="bg-white p-3 rounded border">
              <div className="text-sm text-blue-800">
                <strong>YZ-Correlation:</strong> {multidimensionalMetrics.correlationYZ}
                <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                  <div 
                    className="bg-blue-600 h-2 rounded-full" 
                    style={{ width: `${(Math.abs(parseFloat(multidimensionalMetrics.correlationYZ || '0')) * 100)}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Implementation Framework Insights */}
      <div className="bg-gray-50 border border-gray-200 p-6 rounded-lg">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Multidimensional Implementation Framework
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-sm">
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Computational Complexity Analysis:</h4>
            <p className="text-gray-700">
              Three-dimensional stochastic processes require O(N³) correlation matrix operations and specialized 
              Cholesky decomposition techniques. Memory requirements scale quadratically with dimensionality, 
              necessitating efficient numerical linear algebra implementations.
            </p>
          </div>
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Statistical Framework:</h4>
            <p className="text-gray-700">
              Cross-dimensional correlation estimation requires minimum 1000+ observations for stable results. 
              Portfolio-level risk decomposition enables identification of dominant risk factors and optimal 
              diversification strategies across spatial dimensions.
            </p>
          </div>
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Application Domains:</h4>
            <p className="text-gray-700">
              Multidimensional models excel in multi-asset portfolio optimization, systemic risk assessment, 
              and factor model construction. Spatial displacement metrics provide insights into diversification 
              effectiveness and regime-dependent correlation structures.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdvancedMultidimensionalStochasticAnalyzer;