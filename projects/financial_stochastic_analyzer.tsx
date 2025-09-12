import React, { useState, useEffect, useMemo } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ScatterChart, Scatter, ResponsiveContainer, AreaChart, Area, BarChart, Bar } from 'recharts';
import * as math from 'mathjs';

const AdvancedFinancialStochasticAnalyzer = () => {
  const [activeModel, setActiveModel] = useState('gbm');
  const [analysisMode, setAnalysisMode] = useState('trajectory');
  const [numSteps, setNumSteps] = useState(1000);
  const [timeHorizon, setTimeHorizon] = useState(1.0);
  const [parameters, setParameters] = useState({
    mu: 0.05,          // drift rate
    sigma: 0.2,        // volatility
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

  // Advanced stochastic process generators
  const generateGeometricBrownianMotion = (steps: number, T: number) => {
    const dt = T / steps;
    const path = [{time: 0, price: 100, logPrice: Math.log(100), variance: parameters.sigma ** 2, step: 0}];
    let S = 100;
    
    for (let i = 1; i <= steps; i++) {
      const dW = Math.sqrt(dt) * (Math.random() * 2 - 1) * Math.sqrt(3); // Box-Muller approx
      S *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * dW);
      path.push({
        time: i * dt,
        price: S,
        logPrice: Math.log(S),
        variance: parameters.sigma ** 2,
        step: i
      });
    }
    return path;
  };

  const generateOrnsteinUhlenbeck = (steps: number, T: number) => {
    const dt = T / steps;
    const path = [{time: 0, price: 100, logPrice: Math.log(100), variance: parameters.sigma ** 2, step: 0}];
    let X = Math.log(100);
    
    for (let i = 1; i <= steps; i++) {
      const dW = Math.sqrt(dt) * (Math.random() * 2 - 1) * Math.sqrt(3);
      X = X + parameters.kappa * (Math.log(100) - X) * dt + parameters.sigma * dW;
      const S = Math.exp(X);
      path.push({
        time: i * dt,
        price: S,
        logPrice: X,
        variance: parameters.sigma ** 2 / (2 * parameters.kappa),
        step: i
      });
    }
    return path;
  };

  const generateJumpDiffusion = (steps: number, T: number) => {
    const dt = T / steps;
    const path = [{time: 0, price: 100, logPrice: Math.log(100), variance: parameters.sigma ** 2, step: 0}];
    let S = 100;
    
    for (let i = 1; i <= steps; i++) {
      const dW = Math.sqrt(dt) * (Math.random() * 2 - 1) * Math.sqrt(3);
      let jump = 0;
      
      // Poisson jump process
      if (Math.random() < parameters.lambda * dt) {
        const J = Math.exp(parameters.muJ + parameters.sigmaJ * (Math.random() * 2 - 1) * Math.sqrt(3)) - 1;
        jump = J;
      }
      
      S *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * dW) * (1 + jump);
      path.push({
        time: i * dt,
        price: Math.max(S, 0.01),
        logPrice: Math.log(Math.max(S, 0.01)),
        variance: parameters.sigma ** 2 + parameters.lambda * ((Math.exp(parameters.sigmaJ ** 2) - 1) * Math.exp(2 * parameters.muJ + parameters.sigmaJ ** 2)),
        step: i
      });
    }
    return path;
  };

  const generateHestonModel = (steps: number, T: number) => {
    const dt = T / steps;
    const path = [{time: 0, price: 100, logPrice: Math.log(100), variance: parameters.sigma ** 2, step: 0}];
    let S = 100;
    let v = parameters.sigma ** 2;
    
    for (let i = 1; i <= steps; i++) {
      const dW1 = Math.sqrt(dt) * (Math.random() * 2 - 1) * Math.sqrt(3);
      const dW2_indep = Math.sqrt(dt) * (Math.random() * 2 - 1) * Math.sqrt(3);
      const dW2 = parameters.rho * dW1 + Math.sqrt(1 - parameters.rho ** 2) * dW2_indep;
      
      // Euler-Maruyama discretization with reflection for variance
      v = Math.max(v + parameters.kappa * (parameters.theta - v) * dt + parameters.xi * Math.sqrt(Math.max(v, 0)) * dW2, 0.001);
      S *= Math.exp((parameters.mu - 0.5 * v) * dt + Math.sqrt(Math.max(v, 0)) * dW1);
      
      path.push({
        time: i * dt,
        price: S,
        logPrice: Math.log(S),
        variance: v,
        step: i
      });
    }
    return path;
  };

  const generateFractionalBrownian = (steps: number, T: number) => {
    const dt = T / steps;
    const path = [{time: 0, price: 100, logPrice: Math.log(100), variance: parameters.sigma ** 2, step: 0}];
    let S = 100;
    
    // Simplified fBm using autoregressive approximation
    let pastIncrements = [];
    const memory = Math.min(50, steps);
    
    for (let i = 1; i <= steps; i++) {
      let increment = Math.sqrt(dt) * (Math.random() * 2 - 1) * Math.sqrt(3);
      
      // Add memory effect for H ≠ 0.5
      if (pastIncrements.length > 0 && parameters.hurst !== 0.5) {
        const memoryEffect = pastIncrements.slice(-memory).reduce((sum, past, idx) => {
          const weight = Math.pow(idx + 1, parameters.hurst - 0.5);
          return sum + weight * past;
        }, 0) * (parameters.hurst - 0.5) * 0.1;
        increment += memoryEffect;
      }
      
      pastIncrements.push(increment);
      if (pastIncrements.length > memory) pastIncrements.shift();
      
      S *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * increment);
      path.push({
        time: i * dt,
        price: S,
        logPrice: Math.log(S),
        variance: parameters.sigma ** 2,
        step: i
      });
    }
    return path;
  };

  const generateVarianceGamma = (steps: number, T: number) => {
    const dt = T / steps;
    const path = [{time: 0, price: 100, logPrice: Math.log(100), variance: parameters.sigma ** 2, step: 0}];
    let S = 100;
    
    for (let i = 1; i <= steps; i++) {
      // Gamma time subordinator approximation
      const gamma_increment = Math.max(0.001, dt + parameters.nu * dt * (Math.random() - 0.5));
      const dW = Math.sqrt(gamma_increment) * (Math.random() * 2 - 1) * Math.sqrt(3);
      
      S *= Math.exp((parameters.mu - 0.5 * parameters.sigma ** 2) * dt + parameters.sigma * dW);
      path.push({
        time: i * dt,
        price: S,
        logPrice: Math.log(S),
        variance: parameters.sigma ** 2 * (1 + parameters.nu),
        step: i
      });
    }
    return path;
  };

  // Generate process data based on selected model
  const processData = useMemo(() => {
    switch (activeModel) {
      case 'gbm': return generateGeometricBrownianMotion(numSteps, timeHorizon);
      case 'ou': return generateOrnsteinUhlenbeck(numSteps, timeHorizon);
      case 'jump': return generateJumpDiffusion(numSteps, timeHorizon);
      case 'heston': return generateHestonModel(numSteps, timeHorizon);
      case 'fbm': return generateFractionalBrownian(numSteps, timeHorizon);
      case 'vg': return generateVarianceGamma(numSteps, timeHorizon);
      default: return generateGeometricBrownianMotion(numSteps, timeHorizon);
    }
  }, [activeModel, numSteps, timeHorizon, parameters]);

  // Calculate financial metrics
  const financialMetrics = useMemo(() => {
    if (processData.length < 2) return {};
    
    const returns = [];
    for (let i = 1; i < processData.length; i++) {
      returns.push(Math.log(processData[i].price / processData[i-1].price));
    }
    
    const meanReturn = returns.reduce((a, b) => a + b, 0) / returns.length;
    const variance = returns.reduce((sum, r) => sum + (r - meanReturn) ** 2, 0) / (returns.length - 1);
    const skewness = returns.reduce((sum, r) => sum + Math.pow(r - meanReturn, 3), 0) / (returns.length - 1) / Math.pow(variance, 1.5);
    const kurtosis = returns.reduce((sum, r) => sum + Math.pow(r - meanReturn, 4), 0) / (returns.length - 1) / (variance ** 2) - 3;
    
    const finalPrice = processData[processData.length - 1].price;
    const maxPrice = Math.max(...processData.map(p => p.price));
    const minPrice = Math.min(...processData.map(p => p.price));
    
    // VaR calculation (95% confidence)
    const sortedReturns = [...returns].sort((a, b) => a - b);
    const var95 = sortedReturns[Math.floor(0.05 * sortedReturns.length)];
    
    return {
      annualizedReturn: (meanReturn * 252).toFixed(4),
      annualizedVolatility: (Math.sqrt(variance * 252)).toFixed(4),
      sharpeRatio: ((meanReturn * 252 - parameters.r) / Math.sqrt(variance * 252)).toFixed(4),
      skewness: skewness.toFixed(4),
      kurtosis: kurtosis.toFixed(4),
      maxDrawdown: ((maxPrice - minPrice) / maxPrice).toFixed(4),
      var95: (var95 * 100).toFixed(2),
      finalPrice: finalPrice.toFixed(2),
      priceRange: `${minPrice.toFixed(2)} - ${maxPrice.toFixed(2)}`
    };
  }, [processData, parameters.r]);

  // Model configurations with financial context
  const modelConfigurations: Record<string, {
    name: string;
    equation: string;
    application: string;
    complexity: string;
    regulatory: string;
    description: string;
    strengths: string[];
    limitations: string[];
  }> = {
    gbm: {
      name: 'Geometric Brownian Motion',
      equation: 'dS = μS dt + σS dW',
      application: 'Black-Scholes Foundation',
      complexity: 'Low',
      regulatory: 'Basel III Compliant',
      description: 'Classical continuous-time asset price model',
      strengths: ['Analytical tractability', 'Lognormal distribution', 'Market completeness'],
      limitations: ['Constant volatility', 'No jumps', 'Gaussian returns']
    },
    ou: {
      name: 'Ornstein-Uhlenbeck Process',
      equation: 'dX = κ(θ - X)dt + σ dW',
      application: 'Interest Rate Modeling',
      complexity: 'Medium',
      regulatory: 'FRTB Eligible',
      description: 'Mean-reverting process for rates and volatility',
      strengths: ['Mean reversion', 'Stationary distribution', 'Analytical solutions'],
      limitations: ['Normal distribution', 'Linear reversion', 'Constant parameters']
    },
    jump: {
      name: 'Merton Jump-Diffusion',
      equation: 'dS = μS dt + σS dW + S(e^J - 1)dN',
      application: 'Crash Risk Modeling',
      complexity: 'High',
      regulatory: 'Requires Validation',
      description: 'Incorporates sudden price jumps for tail risk',
      strengths: ['Tail risk capture', 'Asymmetric events', 'Crisis modeling'],
      limitations: ['Parameter instability', 'Computational complexity', 'Calibration challenges']
    },
    heston: {
      name: 'Heston Stochastic Volatility',
      equation: 'dS = rS dt + √v S dW₁, dv = κ(θ-v)dt + ξ√v dW₂',
      application: 'Options Trading',
      complexity: 'Very High',
      regulatory: 'Model Risk Intensive',
      description: 'Industry standard for volatility smile modeling',
      strengths: ['Volatility clustering', 'Leverage effect', 'Smile fitting'],
      limitations: ['Parameter correlation', 'Numerical challenges', 'Validation complexity']
    },
    fbm: {
      name: 'Fractional Brownian Motion',
      equation: 'E[B_H(t)B_H(s)] = ½(|t|^{2H} + |s|^{2H} - |t-s|^{2H})',
      application: 'Long Memory Effects',
      complexity: 'Very High',
      regulatory: 'Research Stage',
      description: 'Captures long-range dependence in financial data',
      strengths: ['Self-similarity', 'Long memory', 'Persistence modeling'],
      limitations: ['Non-Markovian', 'Arbitrage issues', 'Limited adoption']
    },
    vg: {
      name: 'Variance Gamma Process',
      equation: 'X^{VG}_t = θG_t + σW_{G_t}',
      application: 'High-Frequency Trading',
      complexity: 'High',
      regulatory: 'Specialized Use',
      description: 'Infinite activity process with finite variation',
      strengths: ['Independent control of skew/kurtosis', 'Pure jump process', 'Lévy process'],
      limitations: ['Infinite activity assumption', 'Parameter estimation', 'Model complexity']
    }
  };

  // Generate option pricing data for Black-Scholes comparison
  const optionPricingData = useMemo(() => {
    const S0 = 100;
    const K = 100;
    const T = timeHorizon;
    const r = parameters.r;
    const sigma = parameters.sigma;
    
    const strikes = [];
    for (let k = 80; k <= 120; k += 2) {
      const d1 = (Math.log(S0/k) + (r + 0.5*sigma**2)*T) / (sigma*Math.sqrt(T));
      const d2 = d1 - sigma*Math.sqrt(T);
      
      const normalCDF = (x: number) => 0.5 * (1 + math.erf(x / Math.sqrt(2)));
      
      const callPrice = S0 * normalCDF(d1) - k * Math.exp(-r*T) * normalCDF(d2);
      const putPrice = k * Math.exp(-r*T) * normalCDF(-d2) - S0 * normalCDF(-d1);
      
      strikes.push({
        strike: k,
        call: callPrice,
        put: putPrice,
        impliedVol: sigma,
        moneyness: k/S0
      });
    }
    return strikes;
  }, [timeHorizon, parameters.r, parameters.sigma]);

  return (
    <div className="w-full max-w-7xl mx-auto p-6 bg-white">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-4">
          Advanced Financial Stochastic Process Analyzer
        </h1>
        <p className="text-gray-600 max-w-5xl">
          Comprehensive framework for analyzing sophisticated random walk variants in quantitative finance, 
          incorporating regulatory compliance, computational efficiency, and practical implementation considerations.
        </p>
      </div>

      {/* Control Panel */}
      <div className="bg-gray-50 p-6 rounded-lg mb-8">
        <h2 className="text-xl font-semibold mb-4">Model Configuration Framework</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
          {/* Model Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Stochastic Process Type
            </label>
            <select 
              value={activeModel}
              onChange={(e) => setActiveModel(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              {Object.entries(modelConfigurations).map(([key, config]) => (
                <option key={key} value={key}>{config.name}</option>
              ))}
            </select>
          </div>

          {/* Analysis Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Analysis Framework
            </label>
            <select 
              value={analysisMode}
              onChange={(e) => setAnalysisMode(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              <option value="trajectory">Price Trajectory</option>
              <option value="returns">Return Distribution</option>
              <option value="volatility">Volatility Surface</option>
              <option value="options">Option Pricing</option>
              <option value="risk">Risk Metrics</option>
            </select>
          </div>

          {/* Time Parameters */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Time Horizon (Years): {timeHorizon}
            </label>
            <input
              type="range"
              min="0.25"
              max="5"
              step="0.25"
              value={timeHorizon}
              onChange={(e) => setTimeHorizon(parseFloat(e.target.value))}
              className="w-full"
            />
          </div>

          {/* Steps */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Steps: {numSteps}
            </label>
            <input
              type="range"
              min="250"
              max="2500"
              step="250"
              value={numSteps}
              onChange={(e) => setNumSteps(parseInt(e.target.value))}
              className="w-full"
            />
          </div>
        </div>

        {/* Model-Specific Parameters */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Drift (μ): {parameters.mu.toFixed(3)}
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
              Volatility (σ): {parameters.sigma.toFixed(3)}
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
          {(activeModel === 'ou' || activeModel === 'heston') && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Mean Reversion (κ): {parameters.kappa.toFixed(3)}
              </label>
              <input
                type="range"
                min="0.1"
                max="5"
                step="0.1"
                value={parameters.kappa}
                onChange={(e) => setParameters(prev => ({...prev, kappa: parseFloat(e.target.value)}))}
                className="w-full"
              />
            </div>
          )}
          {activeModel === 'jump' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Jump Intensity (λ): {parameters.lambda.toFixed(3)}
              </label>
              <input
                type="range"
                min="0.01"
                max="0.5"
                step="0.01"
                value={parameters.lambda}
                onChange={(e) => setParameters(prev => ({...prev, lambda: parseFloat(e.target.value)}))}
                className="w-full"
              />
            </div>
          )}
          {activeModel === 'fbm' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Hurst Parameter (H): {parameters.hurst.toFixed(3)}
              </label>
              <input
                type="range"
                min="0.1"
                max="0.9"
                step="0.05"
                value={parameters.hurst}
                onChange={(e) => setParameters(prev => ({...prev, hurst: parseFloat(e.target.value)}))}
                className="w-full"
              />
            </div>
          )}
        </div>
      </div>

      {/* Model Analysis Framework */}
      <div className="bg-blue-50 border border-blue-200 p-6 rounded-lg mb-8">
        <h3 className="text-lg font-semibold text-blue-900 mb-3">
          Model Specification: {modelConfigurations[activeModel].name}
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <p className="text-blue-800 font-mono text-sm mb-2">
              <strong>Mathematical Framework:</strong><br />
              {modelConfigurations[activeModel].equation}
            </p>
            <p className="text-blue-700 text-sm">
              <strong>Primary Application:</strong> {modelConfigurations[activeModel].application}
            </p>
          </div>
          <div>
            <p className="text-blue-700 text-sm mb-2">
              <strong>Implementation Complexity:</strong> {modelConfigurations[activeModel].complexity}
            </p>
            <p className="text-blue-700 text-sm">
              <strong>Regulatory Status:</strong> {modelConfigurations[activeModel].regulatory}
            </p>
          </div>
          <div className="bg-white p-4 rounded border">
            <h4 className="font-semibold text-gray-800 mb-2">Financial Metrics</h4>
            <div className="text-sm space-y-1">
              <div>Ann. Return: <span className="font-mono">{financialMetrics.annualizedReturn}</span></div>
              <div>Ann. Volatility: <span className="font-mono">{financialMetrics.annualizedVolatility}</span></div>
              <div>Sharpe Ratio: <span className="font-mono">{financialMetrics.sharpeRatio}</span></div>
              <div>VaR (95%): <span className="font-mono">{financialMetrics.var95}%</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Visualization Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {/* Primary Visualization */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">
            {analysisMode === 'trajectory' ? 'Price Evolution' :
             analysisMode === 'returns' ? 'Return Distribution' :
             analysisMode === 'volatility' ? 'Volatility Structure' :
             analysisMode === 'options' ? 'Option Pricing Surface' : 'Risk Profile'}
          </h3>
          <ResponsiveContainer width="100%" height={400}>
            {analysisMode === 'trajectory' ? (
              <LineChart data={processData.slice(0, Math.min(1000, processData.length))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="time" 
                  label={{ value: 'Time (Years)', position: 'insideBottom', offset: -5 }}
                />
                <YAxis 
                  label={{ value: 'Asset Price ($)', angle: -90, position: 'insideLeft' }}
                />
                <Tooltip 
                  formatter={(value, name) => [typeof value === 'number' ? value.toFixed(2) : value, name]}
                  labelFormatter={(label) => `t = ${typeof label === 'number' ? label.toFixed(3) : label}`}
                />
                <Line 
                  type="monotone" 
                  dataKey="price" 
                  stroke="#2563eb"
                  strokeWidth={2}
                  dot={false}
                  name="Asset Price"
                />
              </LineChart>
            ) : analysisMode === 'options' ? (
              <LineChart data={optionPricingData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="strike"
                  label={{ value: 'Strike Price', position: 'insideBottom', offset: -5 }}
                />
                <YAxis 
                  label={{ value: 'Option Value', angle: -90, position: 'insideLeft' }}
                />
                <Tooltip />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="call" 
                  stroke="#059669"
                  strokeWidth={2}
                  name="Call Options"
                />
                <Line 
                  type="monotone" 
                  dataKey="put" 
                  stroke="#dc2626"
                  strokeWidth={2}
                  name="Put Options"
                />
              </LineChart>
            ) : (
              <AreaChart data={processData.slice(0, Math.min(1000, processData.length))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="time"
                  label={{ value: 'Time', position: 'insideBottom', offset: -5 }}
                />
                <YAxis />
                <Tooltip />
                <Area 
                  type="monotone" 
                  dataKey="variance" 
                  stackId="1"
                  stroke="#7c3aed"
                  fill="#7c3aed"
                  fillOpacity={0.6}
                  name="Instantaneous Variance"
                />
              </AreaChart>
            )}
          </ResponsiveContainer>
        </div>

        {/* Statistical Analysis */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">Statistical Properties Analysis</h3>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={[
              { metric: 'Skewness', value: parseFloat(financialMetrics.skewness || '0'), benchmark: 0 },
              { metric: 'Kurtosis', value: parseFloat(financialMetrics.kurtosis || '0'), benchmark: 0 },
              { metric: 'Sharpe', value: parseFloat(financialMetrics.sharpeRatio || '0'), benchmark: 1 },
              { metric: 'Max DD', value: parseFloat(financialMetrics.maxDrawdown || '0') * 100, benchmark: 5 }
            ]}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="metric" />
              <YAxis />
              <Tooltip 
                formatter={(value, name) => [typeof value === 'number' ? value.toFixed(3) : value, name]}
              />
              <Legend />
              <Bar dataKey="value" fill="#2563eb" name="Observed Value" />
              <Bar dataKey="benchmark" fill="#6b7280" name="Benchmark" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Comparative Analysis Framework */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden mb-8">
        <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
          <h3 className="text-lg font-semibold">Model Comparative Analysis Framework</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Model Class
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Complexity
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Regulatory Compliance
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Computational Efficiency
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Financial Application
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {Object.entries(modelConfigurations).map(([key, config]) => (
                <tr key={key} className={activeModel === key ? 'bg-blue-50' : ''}>
                  <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">
                    {config.name}
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <span className={`px-2 py-1 rounded text-xs ${
                      config.complexity === 'Low' ? 'bg-green-100 text-green-800' :
                      config.complexity === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                      config.complexity === 'High' ? 'bg-orange-100 text-orange-800' :
                      'bg-red-100 text-red-800'
                    }`}>
                      {config.complexity}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {config.regulatory}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {key === 'gbm' ? 'Excellent' :
                     key === 'ou' ? 'Very Good' :
                     key === 'jump' ? 'Moderate' :
                     key === 'heston' ? 'Challenging' :
                     key === 'fbm' ? 'Poor' : 'Moderate'}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {config.application}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Model Strengths and Limitations Analysis */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
        <div className="bg-green-50 border border-green-200 p-6 rounded-lg">
          <h3 className="text-lg font-semibold text-green-900 mb-3">
            Model Strengths
          </h3>
          <ul className="space-y-2">
            {modelConfigurations[activeModel].strengths.map((strength, idx) => (
              <li key={idx} className="text-green-800 text-sm flex items-start">
                <span className="text-green-600 mr-2">•</span>
                {strength}
              </li>
            ))}
          </ul>
        </div>
        
        <div className="bg-red-50 border border-red-200 p-6 rounded-lg">
          <h3 className="text-lg font-semibold text-red-900 mb-3">
            Model Limitations
          </h3>
          <ul className="space-y-2">
            {modelConfigurations[activeModel].limitations.map((limitation, idx) => (
              <li key={idx} className="text-red-800 text-sm flex items-start">
                <span className="text-red-600 mr-2">•</span>
                {limitation}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Implementation Insights */}
      <div className="bg-gray-50 border border-gray-200 p-6 rounded-lg">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Implementation Framework Insights
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-sm">
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Computational Strategy:</h4>
            <p className="text-gray-700">
              Advanced stochastic processes require careful balance between mathematical sophistication and computational efficiency. 
              GPU acceleration provides 50-500x speedups for Monte Carlo applications, while variance reduction techniques 
              can improve efficiency by 30-90%.
            </p>
          </div>
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Regulatory Considerations:</h4>
            <p className="text-gray-700">
              FRTB and Basel III/IV requirements emphasize model interpretability and validation. Expected Shortfall 
              calculations mandate robust backtesting frameworks, with institutions favoring simpler models 
              for regulatory compliance.
            </p>
          </div>
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Industry Applications:</h4>
            <p className="text-gray-700">
              Financial institutions employ tiered modeling approaches: sophisticated processes for derivatives pricing 
              and risk management, while maintaining simpler models for real-time trading operations and 
              regulatory reporting requirements.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdvancedFinancialStochasticAnalyzer;