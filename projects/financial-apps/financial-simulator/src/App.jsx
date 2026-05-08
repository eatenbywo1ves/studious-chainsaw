import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Play, Pause, RotateCcw, TrendingUp, DollarSign, BarChart3, PieChart } from 'lucide-react';

const FinancialSimulation = () => {
  const canvasRef = useRef(null);
  const animationRef = useRef(null);
  const [isRunning, setIsRunning] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [paths, setPaths] = useState([]);
  const [parameters, setParameters] = useState({
    model: 'black-scholes',
    initialPrice: 100,
    volatility: 0.2,
    drift: 0.05,
    numPaths: 100,
    timeSteps: 252,
    timeHorizon: 1,
    meanReversion: 0.05,
    longTermMean: 100,
    jumpIntensity: 0.1,
    jumpMean: 0,
    jumpVolatility: 0.1
  });
  
  const [optionsData, setOptionsData] = useState({
    strike: 105,
    timeToExpiry: 0.25,
    riskFreeRate: 0.03,
    optionType: 'call'
  });

  const [riskMetrics, setRiskMetrics] = useState({
    var95: 0,
    cvar95: 0,
    sharpeRatio: 0,
    maxDrawdown: 0
  });

  const models = {
    'black-scholes': 'Black-Scholes (GBM)',
    'vasicek': 'Vasicek Interest Rate',
    'heston': 'Heston Stochastic Vol',
    'jump-diffusion': 'Merton Jump Diffusion'
  };

  // Mathematical Functions
  const normalRandom = () => {
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  };

  const blackScholesOptionPrice = (S, K, T, r, sigma, type = 'call') => {
    const d1 = (Math.log(S / K) + (r + 0.5 * sigma * sigma) * T) / (sigma * Math.sqrt(T));
    const d2 = d1 - sigma * Math.sqrt(T);
    
    const normCDF = (x) => {
      return 0.5 * (1 + erf(x / Math.sqrt(2)));
    };
    
    if (type === 'call') {
      return S * normCDF(d1) - K * Math.exp(-r * T) * normCDF(d2);
    } else {
      return K * Math.exp(-r * T) * normCDF(-d2) - S * normCDF(-d1);
    }
  };

  const erf = (x) => {
    const a1 =  0.254829592;
    const a2 = -0.284496736;
    const a3 =  1.421413741;
    const a4 = -1.453152027;
    const a5 =  1.061405429;
    const p  =  0.3275911;
    
    const sign = x >= 0 ? 1 : -1;
    x = Math.abs(x);
    
    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
    
    return sign * y;
  };

  const calculateGreeks = (S, K, T, r, sigma) => {
    const d1 = (Math.log(S / K) + (r + 0.5 * sigma * sigma) * T) / (sigma * Math.sqrt(T));
    const d2 = d1 - sigma * Math.sqrt(T);
    
    const normCDF = (x) => 0.5 * (1 + erf(x / Math.sqrt(2)));
    const normPDF = (x) => Math.exp(-0.5 * x * x) / Math.sqrt(2 * Math.PI);
    
    const delta = normCDF(d1);
    const gamma = normPDF(d1) / (S * sigma * Math.sqrt(T));
    const theta = -(S * normPDF(d1) * sigma) / (2 * Math.sqrt(T)) - r * K * Math.exp(-r * T) * normCDF(d2);
    const vega = S * normPDF(d1) * Math.sqrt(T);
    const rho = K * T * Math.exp(-r * T) * normCDF(d2);
    
    return { delta, gamma, theta: theta / 365, vega: vega / 100, rho: rho / 100 };
  };

  // Stochastic Process Generators
  const generateBlackScholesPaths = useCallback(() => {
    const dt = parameters.timeHorizon / parameters.timeSteps;
    const newPaths = [];
    
    for (let i = 0; i < parameters.numPaths; i++) {
      const path = [parameters.initialPrice];
      let currentPrice = parameters.initialPrice;
      
      for (let t = 1; t <= parameters.timeSteps; t++) {
        const dW = normalRandom() * Math.sqrt(dt);
        currentPrice *= Math.exp((parameters.drift - 0.5 * parameters.volatility * parameters.volatility) * dt + parameters.volatility * dW);
        path.push(currentPrice);
      }
      newPaths.push(path);
    }
    return newPaths;
  }, [parameters.timeHorizon, parameters.timeSteps, parameters.numPaths, parameters.initialPrice, parameters.drift, parameters.volatility]);

  const generateVasicekPaths = useCallback(() => {
    const dt = parameters.timeHorizon / parameters.timeSteps;
    const newPaths = [];
    
    for (let i = 0; i < parameters.numPaths; i++) {
      const path = [parameters.initialPrice];
      let currentRate = parameters.initialPrice;
      
      for (let t = 1; t <= parameters.timeSteps; t++) {
        const dW = normalRandom() * Math.sqrt(dt);
        currentRate += parameters.meanReversion * (parameters.longTermMean - currentRate) * dt + parameters.volatility * dW;
        path.push(Math.max(currentRate, 0)); // Ensure non-negative rates
      }
      newPaths.push(path);
    }
    return newPaths;
  }, [parameters.timeHorizon, parameters.timeSteps, parameters.numPaths, parameters.initialPrice, parameters.meanReversion, parameters.longTermMean, parameters.volatility]);

  const generateHestonPaths = useCallback(() => {
    const dt = parameters.timeHorizon / parameters.timeSteps;
    const newPaths = [];
    const correlation = -0.5; // Typical negative correlation between price and volatility
    
    for (let i = 0; i < parameters.numPaths; i++) {
      const path = [parameters.initialPrice];
      let currentPrice = parameters.initialPrice;
      let currentVol = parameters.volatility;
      
      for (let t = 1; t <= parameters.timeSteps; t++) {
        const dW1 = normalRandom();
        const dW2 = correlation * dW1 + Math.sqrt(1 - correlation * correlation) * normalRandom();
        
        // Heston volatility process
        const volDrift = parameters.meanReversion * (parameters.volatility - currentVol);
        currentVol += volDrift * dt + 0.3 * Math.sqrt(Math.max(currentVol, 0)) * dW2 * Math.sqrt(dt);
        currentVol = Math.max(currentVol, 0.01); // Floor for numerical stability
        
        // Price process
        currentPrice *= Math.exp((parameters.drift - 0.5 * currentVol) * dt + Math.sqrt(currentVol) * dW1 * Math.sqrt(dt));
        path.push(currentPrice);
      }
      newPaths.push(path);
    }
    return newPaths;
  }, [parameters.timeHorizon, parameters.timeSteps, parameters.numPaths, parameters.initialPrice, parameters.drift, parameters.volatility, parameters.meanReversion]);

  const generateJumpDiffusionPaths = useCallback(() => {
    const dt = parameters.timeHorizon / parameters.timeSteps;
    const newPaths = [];
    
    for (let i = 0; i < parameters.numPaths; i++) {
      const path = [parameters.initialPrice];
      let currentPrice = parameters.initialPrice;
      
      for (let t = 1; t <= parameters.timeSteps; t++) {
        const dW = normalRandom() * Math.sqrt(dt);
        
        // Poisson jump component
        const jumpOccurs = Math.random() < parameters.jumpIntensity * dt;
        const jumpSize = jumpOccurs ? Math.exp(parameters.jumpMean + parameters.jumpVolatility * normalRandom()) - 1 : 0;
        
        // Combined process
        const diffusion = (parameters.drift - 0.5 * parameters.volatility * parameters.volatility) * dt + parameters.volatility * dW;
        currentPrice *= Math.exp(diffusion) * (1 + jumpSize);
        path.push(currentPrice);
      }
      newPaths.push(path);
    }
    return newPaths;
  }, [parameters.timeHorizon, parameters.timeSteps, parameters.numPaths, parameters.initialPrice, parameters.drift, parameters.volatility, parameters.jumpIntensity, parameters.jumpMean, parameters.jumpVolatility]);

  const generatePaths = useCallback(() => {
    switch (parameters.model) {
      case 'black-scholes':
        return generateBlackScholesPaths();
      case 'vasicek':
        return generateVasicekPaths();
      case 'heston':
        return generateHestonPaths();
      case 'jump-diffusion':
        return generateJumpDiffusionPaths();
      default:
        return generateBlackScholesPaths();
    }
  }, [parameters.model, generateBlackScholesPaths, generateVasicekPaths, generateHestonPaths, generateJumpDiffusionPaths]);

  // Risk Calculations
  const calculateRiskMetrics = (pathsData) => {
    if (!pathsData.length) return;
    
    // const finalPrices = pathsData.map(path => path[path.length - 1]);
    const returns = pathsData.map(path => {
      const initial = path[0];
      const final = path[path.length - 1];
      return (final - initial) / initial;
    });
    
    // VaR and CVaR (95% confidence)
    const sortedReturns = [...returns].sort((a, b) => a - b);
    const var95Index = Math.floor(0.05 * sortedReturns.length);
    const var95 = -sortedReturns[var95Index] * 100;
    const cvar95 = -sortedReturns.slice(0, var95Index + 1).reduce((a, b) => a + b, 0) / (var95Index + 1) * 100;
    
    // Sharpe Ratio
    const meanReturn = returns.reduce((a, b) => a + b, 0) / returns.length;
    const returnVariance = returns.reduce((a, b) => a + (b - meanReturn) ** 2, 0) / returns.length;
    const returnStd = Math.sqrt(returnVariance);
    const sharpeRatio = meanReturn / returnStd * Math.sqrt(252); // Annualized
    
    // Max Drawdown
    let maxDrawdown = 0;
    pathsData.forEach(path => {
      let peak = path[0];
      for (let i = 1; i < path.length; i++) {
        if (path[i] > peak) peak = path[i];
        const drawdown = (peak - path[i]) / peak;
        if (drawdown > maxDrawdown) maxDrawdown = drawdown;
      }
    });
    
    setRiskMetrics({
      var95: var95.toFixed(2),
      cvar95: cvar95.toFixed(2),
      sharpeRatio: sharpeRatio.toFixed(3),
      maxDrawdown: (maxDrawdown * 100).toFixed(2)
    });
  };

  // Canvas Drawing
  const drawPaths = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    
    ctx.clearRect(0, 0, width, height);
    
    if (paths.length === 0) return;
    
    // Calculate bounds
    const allPrices = paths.flat();
    const minPrice = Math.min(...allPrices);
    const maxPrice = Math.max(...allPrices);
    const priceRange = maxPrice - minPrice;
    
    const padding = 40;
    const plotWidth = width - 2 * padding;
    const plotHeight = height - 2 * padding;
    
    // Draw axes
    ctx.strokeStyle = '#374151';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, height - padding);
    ctx.lineTo(width - padding, height - padding);
    ctx.stroke();
    
    // Draw grid
    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth = 0.5;
    for (let i = 1; i < 10; i++) {
      const y = padding + (plotHeight * i) / 10;
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(width - padding, y);
      ctx.stroke();
    }
    
    // Draw price paths
    const pathsToShow = Math.min(paths.length, currentTime);
    paths.slice(0, pathsToShow).forEach((path, index) => {
      const alpha = Math.max(0.1, 1 - index / parameters.numPaths);
      ctx.strokeStyle = `rgba(59, 130, 246, ${alpha})`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      
      const pointsToShow = Math.min(path.length, Math.floor(currentTime * parameters.timeSteps / parameters.numPaths) + 1);
      
      for (let i = 0; i < pointsToShow; i++) {
        const x = padding + (plotWidth * i) / (parameters.timeSteps - 1);
        const y = height - padding - ((path[i] - minPrice) / priceRange) * plotHeight;
        
        if (i === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      }
      ctx.stroke();
    });
    
    // Draw current price level
    if (paths.length > 0) {
      const currentPrices = paths.map(path => {
        const timeIndex = Math.min(Math.floor(currentTime * parameters.timeSteps / parameters.numPaths), path.length - 1);
        return path[timeIndex];
      });
      const avgPrice = currentPrices.reduce((a, b) => a + b, 0) / currentPrices.length;
      const y = height - padding - ((avgPrice - minPrice) / priceRange) * plotHeight;
      
      ctx.strokeStyle = '#ef4444';
      ctx.lineWidth = 2;
      ctx.setLineDash([5, 5]);
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(width - padding, y);
      ctx.stroke();
      ctx.setLineDash([]);
      
      // Price label
      ctx.fillStyle = '#ef4444';
      ctx.font = '12px monospace';
      ctx.fillText(`$${avgPrice.toFixed(2)}`, width - padding + 5, y + 4);
    }
    
    // Draw labels
    ctx.fillStyle = '#374151';
    ctx.font = '12px sans-serif';
    ctx.fillText('Time', width / 2 - 15, height - 10);
    ctx.save();
    ctx.translate(15, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Price', -20, 0);
    ctx.restore();
  }, [paths, currentTime, parameters.numPaths, parameters.timeSteps]);

  // Animation Loop
  const animate = useCallback(function animateFunc() {
    if (isRunning) {
      setCurrentTime(prev => {
        const newTime = prev + 1;
        if (newTime >= parameters.numPaths) {
          setIsRunning(false);
          return parameters.numPaths;
        }
        return newTime;
      });
      animationRef.current = requestAnimationFrame(animateFunc);
    }
  }, [isRunning, parameters.numPaths]);

  // Effects
  useEffect(() => {
    if (isRunning) {
      animationRef.current = requestAnimationFrame(animate);
    } else {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    }
    
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [isRunning, animate]);

  useEffect(() => {
    drawPaths();
  }, [paths, currentTime, drawPaths]);

  useEffect(() => {
    const newPaths = generatePaths();
    setPaths(newPaths);
    calculateRiskMetrics(newPaths);
    setCurrentTime(0);
  }, [parameters, generatePaths]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas) {
      canvas.width = 800;
      canvas.height = 400;
    }
  }, []);

  // Controls
  const handleStart = () => {
    setIsRunning(true);
  };

  const handlePause = () => {
    setIsRunning(false);
  };

  const handleReset = () => {
    setIsRunning(false);
    const newPaths = generatePaths();
    setPaths(newPaths);
    calculateRiskMetrics(newPaths);
    setCurrentTime(0);
  };

  const handleParameterChange = (key, value) => {
    setParameters(prev => ({
      ...prev,
      [key]: parseFloat(value) || value
    }));
  };

  const handleOptionsChange = (key, value) => {
    setOptionsData(prev => ({
      ...prev,
      [key]: parseFloat(value) || value
    }));
  };

  // Calculate current option price and Greeks
  const currentPrice = paths.length > 0 ? paths[0][Math.min(Math.floor(currentTime * parameters.timeSteps / parameters.numPaths), paths[0].length - 1)] : parameters.initialPrice;
  const optionPrice = blackScholesOptionPrice(currentPrice, optionsData.strike, optionsData.timeToExpiry, optionsData.riskFreeRate, parameters.volatility, optionsData.optionType);
  const greeks = calculateGreeks(currentPrice, optionsData.strike, optionsData.timeToExpiry, optionsData.riskFreeRate, parameters.volatility);

  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <div className="max-w-7xl mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex items-center gap-3 mb-6">
            <TrendingUp className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-800">Financial Stochastic Process Simulator</h1>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Control Panel */}
            <div className="bg-gray-50 rounded-lg p-4">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                Controls
              </h2>
              
              <div className="space-y-4">
                {/* Simulation Controls */}
                <div className="flex gap-2">
                  <button
                    onClick={handleStart}
                    disabled={isRunning}
                    className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
                  >
                    <Play className="h-4 w-4" />
                    Start
                  </button>
                  <button
                    onClick={handlePause}
                    disabled={!isRunning}
                    className="flex items-center gap-2 px-4 py-2 bg-yellow-600 text-white rounded hover:bg-yellow-700 disabled:opacity-50"
                  >
                    <Pause className="h-4 w-4" />
                    Pause
                  </button>
                  <button
                    onClick={handleReset}
                    className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
                  >
                    <RotateCcw className="h-4 w-4" />
                    Reset
                  </button>
                </div>

                {/* Model Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Model</label>
                  <select
                    value={parameters.model}
                    onChange={(e) => handleParameterChange('model', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md"
                  >
                    {Object.entries(models).map(([key, label]) => (
                      <option key={key} value={key}>{label}</option>
                    ))}
                  </select>
                </div>

                {/* Basic Parameters */}
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Initial Price</label>
                    <input
                      type="number"
                      value={parameters.initialPrice}
                      onChange={(e) => handleParameterChange('initialPrice', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Volatility</label>
                    <input
                      type="number"
                      step="0.01"
                      value={parameters.volatility}
                      onChange={(e) => handleParameterChange('volatility', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Drift</label>
                    <input
                      type="number"
                      step="0.01"
                      value={parameters.drift}
                      onChange={(e) => handleParameterChange('drift', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Paths</label>
                    <input
                      type="number"
                      value={parameters.numPaths}
                      onChange={(e) => handleParameterChange('numPaths', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    />
                  </div>
                </div>

                {/* Model-specific Parameters */}
                {(parameters.model === 'vasicek' || parameters.model === 'heston') && (
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Mean Reversion</label>
                      <input
                        type="number"
                        step="0.01"
                        value={parameters.meanReversion}
                        onChange={(e) => handleParameterChange('meanReversion', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Long Term Mean</label>
                      <input
                        type="number"
                        value={parameters.longTermMean}
                        onChange={(e) => handleParameterChange('longTermMean', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                      />
                    </div>
                  </div>
                )}

                {parameters.model === 'jump-diffusion' && (
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Jump Intensity</label>
                      <input
                        type="number"
                        step="0.01"
                        value={parameters.jumpIntensity}
                        onChange={(e) => handleParameterChange('jumpIntensity', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Jump Volatility</label>
                      <input
                        type="number"
                        step="0.01"
                        value={parameters.jumpVolatility}
                        onChange={(e) => handleParameterChange('jumpVolatility', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Visualization */}
            <div className="lg:col-span-2">
              <h2 className="text-xl font-semibold mb-4">Price Simulation</h2>
              <div className="bg-white border rounded-lg p-4">
                <canvas
                  ref={canvasRef}
                  className="w-full border rounded"
                  style={{ maxWidth: '100%', height: 'auto' }}
                />
              </div>
              
              <div className="mt-4 text-center">
                <div className="text-lg font-semibold">
                  Progress: {Math.round((currentTime / parameters.numPaths) * 100)}%
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${(currentTime / parameters.numPaths) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Analytics Dashboard */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Options Pricing */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <DollarSign className="h-5 w-5" />
              Options Pricing & Greeks
            </h2>
            
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Strike Price</label>
                <input
                  type="number"
                  value={optionsData.strike}
                  onChange={(e) => handleOptionsChange('strike', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Time to Expiry</label>
                <input
                  type="number"
                  step="0.01"
                  value={optionsData.timeToExpiry}
                  onChange={(e) => handleOptionsChange('timeToExpiry', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Risk-Free Rate</label>
                <input
                  type="number"
                  step="0.001"
                  value={optionsData.riskFreeRate}
                  onChange={(e) => handleOptionsChange('riskFreeRate', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Option Type</label>
                <select
                  value={optionsData.optionType}
                  onChange={(e) => handleOptionsChange('optionType', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md"
                >
                  <option value="call">Call</option>
                  <option value="put">Put</option>
                </select>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="font-medium">Current Price:</span>
                <span className="font-mono">${currentPrice.toFixed(2)}</span>
              </div>
              <div className="flex justify-between">
                <span className="font-medium">Option Price:</span>
                <span className="font-mono">${optionPrice.toFixed(4)}</span>
              </div>
              <hr className="my-2" />
              <div className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span>Delta:</span>
                  <span className="font-mono">{greeks.delta.toFixed(4)}</span>
                </div>
                <div className="flex justify-between">
                  <span>Gamma:</span>
                  <span className="font-mono">{greeks.gamma.toFixed(6)}</span>
                </div>
                <div className="flex justify-between">
                  <span>Theta:</span>
                  <span className="font-mono">{greeks.theta.toFixed(4)}</span>
                </div>
                <div className="flex justify-between">
                  <span>Vega:</span>
                  <span className="font-mono">{greeks.vega.toFixed(4)}</span>
                </div>
                <div className="flex justify-between">
                  <span>Rho:</span>
                  <span className="font-mono">{greeks.rho.toFixed(4)}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Risk Metrics */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <PieChart className="h-5 w-5" />
              Risk Analytics
            </h2>
            
            <div className="space-y-4">
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex justify-between items-center">
                  <span className="font-medium text-red-800">Value at Risk (95%)</span>
                  <span className="text-xl font-bold text-red-600">{riskMetrics.var95}%</span>
                </div>
                <p className="text-sm text-red-600 mt-1">Maximum expected loss in 95% of scenarios</p>
              </div>
              
              <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                <div className="flex justify-between items-center">
                  <span className="font-medium text-orange-800">Conditional VaR (95%)</span>
                  <span className="text-xl font-bold text-orange-600">{riskMetrics.cvar95}%</span>
                </div>
                <p className="text-sm text-orange-600 mt-1">Expected loss given loss exceeds VaR</p>
              </div>
              
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex justify-between items-center">
                  <span className="font-medium text-blue-800">Sharpe Ratio</span>
                  <span className="text-xl font-bold text-blue-600">{riskMetrics.sharpeRatio}</span>
                </div>
                <p className="text-sm text-blue-600 mt-1">Risk-adjusted return measure</p>
              </div>
              
              <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                <div className="flex justify-between items-center">
                  <span className="font-medium text-purple-800">Max Drawdown</span>
                  <span className="text-xl font-bold text-purple-600">{riskMetrics.maxDrawdown}%</span>
                </div>
                <p className="text-sm text-purple-600 mt-1">Largest peak-to-trough decline</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

function App() {
  return <FinancialSimulation />;
}

export default App;
