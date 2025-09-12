import React, { useState, useEffect, useMemo } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ScatterChart, Scatter, ResponsiveContainer } from 'recharts';
import * as math from 'mathjs';

const RandomWalkVisualizer = () => {
  const [activeWalkType, setActiveWalkType] = useState('simple');
  const [numSteps, setNumSteps] = useState(500);
  const [dimension, setDimension] = useState('2D');
  const [parameters, setParameters] = useState({
    bias: 0.1,
    correlation: 0.7,
    levyAlpha: 1.5,
    stepSize: 1.0
  });

  // Random walk generation algorithms
  const generateSimpleWalk = (steps: number, dim: string) => {
    const path = [{x: 0, y: 0, z: 0, step: 0}];
    let x = 0, y = 0, z = 0;
    
    for (let i = 1; i <= steps; i++) {
      const angle = Math.random() * 2 * Math.PI;
      x += parameters.stepSize * Math.cos(angle);
      y += parameters.stepSize * Math.sin(angle);
      
      if (dim === '3D') {
        const phi = Math.random() * Math.PI;
        z += parameters.stepSize * Math.cos(phi);
      }
      
      path.push({x, y, z, step: i});
    }
    return path;
  };

  const generateBiasedWalk = (steps: number, dim: string) => {
    const path = [{x: 0, y: 0, z: 0, step: 0}];
    let x = 0, y = 0, z = 0;
    
    for (let i = 1; i <= steps; i++) {
      const angle = Math.random() * 2 * Math.PI + parameters.bias;
      x += parameters.stepSize * Math.cos(angle);
      y += parameters.stepSize * Math.sin(angle);
      
      if (dim === '3D') {
        z += parameters.stepSize * (Math.random() - 0.5 + parameters.bias);
      }
      
      path.push({x, y, z, step: i});
    }
    return path;
  };

  const generateCorrelatedWalk = (steps: number, dim: string) => {
    const path = [{x: 0, y: 0, z: 0, step: 0}];
    let x = 0, y = 0, z = 0;
    let prevAngle = 0;
    
    for (let i = 1; i <= steps; i++) {
      const newAngle = prevAngle * parameters.correlation + 
                      (1 - parameters.correlation) * Math.random() * 2 * Math.PI;
      x += parameters.stepSize * Math.cos(newAngle);
      y += parameters.stepSize * Math.sin(newAngle);
      
      if (dim === '3D') {
        z += parameters.stepSize * (Math.random() - 0.5);
      }
      
      prevAngle = newAngle;
      path.push({x, y, z, step: i});
    }
    return path;
  };

  const generateLevyFlight = (steps: number, dim: string) => {
    const path = [{x: 0, y: 0, z: 0, step: 0}];
    let x = 0, y = 0, z = 0;
    
    for (let i = 1; i <= steps; i++) {
      // Levy distribution step size using Mantegna algorithm
      const u = (Math.random() - 0.5) * Math.PI;
      const v = Math.random();
      const stepLength = Math.tan(u) * Math.pow(v, -1/parameters.levyAlpha);
      const boundedStep = Math.min(Math.abs(stepLength), 10) * Math.sign(stepLength);
      
      const angle = Math.random() * 2 * Math.PI;
      x += boundedStep * Math.cos(angle);
      y += boundedStep * Math.sin(angle);
      
      if (dim === '3D') {
        z += boundedStep * (Math.random() - 0.5);
      }
      
      path.push({x, y, z, step: i});
    }
    return path;
  };

  // Generate walk data based on type
  const walkData = useMemo(() => {
    switch (activeWalkType) {
      case 'simple': return generateSimpleWalk(numSteps, dimension);
      case 'biased': return generateBiasedWalk(numSteps, dimension);
      case 'correlated': return generateCorrelatedWalk(numSteps, dimension);
      case 'levy': return generateLevyFlight(numSteps, dimension);
      default: return generateSimpleWalk(numSteps, dimension);
    }
  }, [activeWalkType, numSteps, dimension, parameters]);

  // Calculate statistical measures
  const statistics = useMemo(() => {
    if (walkData.length < 2) return {};
    
    const finalPoint = walkData[walkData.length - 1];
    const displacement = Math.sqrt(finalPoint.x ** 2 + finalPoint.y ** 2 + (dimension === '3D' ? finalPoint.z ** 2 : 0));
    
    const msd = walkData.reduce((sum, point, i) => {
      if (i === 0) return 0;
      const r2 = point.x ** 2 + point.y ** 2 + (dimension === '3D' ? point.z ** 2 : 0);
      return sum + r2;
    }, 0) / (walkData.length - 1);

    return {
      displacement: displacement.toFixed(2),
      meanSquaredDisplacement: msd.toFixed(2),
      steps: walkData.length - 1,
      diffusionCoefficient: (msd / (2 * (dimension === '3D' ? 3 : 2) * walkData.length)).toFixed(4)
    };
  }, [walkData, dimension]);

  // Walk type configurations
  const walkTypes: Record<string, { name: string; equation: string; color: string; description: string }> = {
    simple: {
      name: 'Simple Random Walk',
      equation: dimension === '2D' ? 'X(n) = ∑ξₖ, ⟨r²⟩ = 2Dt' : 'X(n) = ∑ξₖ, ⟨r²⟩ = 6Dt',
      color: '#2563eb',
      description: 'Unbiased isotropic diffusion'
    },
    biased: {
      name: 'Biased Random Walk',
      equation: 'dX = μdt + σdW(t), μ = drift coefficient',
      color: '#dc2626',
      description: 'Systematic drift with noise'
    },
    correlated: {
      name: 'Correlated Random Walk',
      equation: '⟨v(t)v(t+τ)⟩ = v₀²exp(-τ/τc)',
      color: '#059669',
      description: 'Directional persistence memory'
    },
    levy: {
      name: 'Lévy Flight',
      equation: 'P(ℓ) ∝ ℓ⁻ᵅ, 1 < α ≤ 3',
      color: '#7c3aed',
      description: 'Heavy-tailed step distribution'
    }
  };

  return (
    <div className="w-full max-w-7xl mx-auto p-6 bg-white">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-4">
          Random Walk Generation Methods: Visual Analysis Framework
        </h1>
        <p className="text-gray-600 max-w-4xl">
          Interactive demonstration of stochastic process generation algorithms with mathematical formulations and statistical analysis capabilities.
        </p>
      </div>

      {/* Control Panel */}
      <div className="bg-gray-50 p-6 rounded-lg mb-8">
        <h2 className="text-xl font-semibold mb-4">Experimental Parameters</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Walk Type Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Process Type
            </label>
            <select 
              value={activeWalkType}
              onChange={(e) => setActiveWalkType(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              {Object.entries(walkTypes).map(([key, config]) => (
                <option key={key} value={key}>{config.name}</option>
              ))}
            </select>
          </div>

          {/* Dimension */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Spatial Dimension
            </label>
            <select 
              value={dimension}
              onChange={(e) => setDimension(e.target.value)}
              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              <option value="2D">2D System</option>
              <option value="3D">3D System</option>
            </select>
          </div>

          {/* Number of Steps */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Steps (n = {numSteps})
            </label>
            <input
              type="range"
              min="100"
              max="2000"
              step="50"
              value={numSteps}
              onChange={(e) => setNumSteps(parseInt(e.target.value))}
              className="w-full"
            />
          </div>

          {/* Dynamic Parameters */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              {activeWalkType === 'biased' ? 'Bias Strength' :
               activeWalkType === 'correlated' ? 'Correlation' :
               activeWalkType === 'levy' ? 'Lévy α' : 'Step Size'}
            </label>
            <input
              type="range"
              min={activeWalkType === 'levy' ? "1.1" : "0.1"}
              max={activeWalkType === 'levy' ? "2.5" : "1.0"}
              step="0.1"
              value={activeWalkType === 'biased' ? parameters.bias :
                     activeWalkType === 'correlated' ? parameters.correlation :
                     activeWalkType === 'levy' ? parameters.levyAlpha : parameters.stepSize}
              onChange={(e) => {
                const value = parseFloat(e.target.value);
                setParameters(prev => ({
                  ...prev,
                  [activeWalkType === 'biased' ? 'bias' :
                   activeWalkType === 'correlated' ? 'correlation' :
                   activeWalkType === 'levy' ? 'levyAlpha' : 'stepSize']: value
                }));
              }}
              className="w-full"
            />
          </div>
        </div>
      </div>

      {/* Mathematical Framework */}
      <div className="bg-blue-50 border border-blue-200 p-6 rounded-lg mb-8">
        <h3 className="text-lg font-semibold text-blue-900 mb-3">
          Mathematical Framework: {walkTypes[activeWalkType].name}
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-blue-800 font-mono text-sm mb-2">
              <strong>Governing Equation:</strong> {walkTypes[activeWalkType].equation}
            </p>
            <p className="text-blue-700 text-sm">
              <strong>Characteristics:</strong> {walkTypes[activeWalkType].description}
            </p>
          </div>
          <div className="bg-white p-4 rounded border">
            <h4 className="font-semibold text-gray-800 mb-2">Statistical Properties</h4>
            <div className="text-sm space-y-1">
              <div>Displacement: <span className="font-mono">{statistics.displacement}</span></div>
              <div>MSD: <span className="font-mono">{statistics.meanSquaredDisplacement}</span></div>
              <div>D_eff: <span className="font-mono">{statistics.diffusionCoefficient}</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Visualization Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Trajectory Plot */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">
            Trajectory Visualization ({dimension})
          </h3>
          <ResponsiveContainer width="100%" height={400}>
            <ScatterChart data={walkData.slice(0, Math.min(500, walkData.length))}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="x" 
                domain={['dataMin', 'dataMax']}
                label={{ value: 'X Position', position: 'insideBottom', offset: -5 }}
              />
              <YAxis 
                dataKey="y" 
                domain={['dataMin', 'dataMax']}
                label={{ value: 'Y Position', angle: -90, position: 'insideLeft' }}
              />
              <Tooltip 
                formatter={(value, name) => [typeof value === 'number' ? value.toFixed(2) : value, name]}
                labelFormatter={(label, payload) => 
                  payload?.[0] ? `Step: ${payload[0].payload.step}` : ''
                }
              />
              <Scatter 
                data={walkData.slice(0, Math.min(500, walkData.length))}
                fill={walkTypes[activeWalkType].color}
                fillOpacity={0.6}
              />
              <Line 
                type="linear" 
                dataKey="y" 
                stroke={walkTypes[activeWalkType].color}
                strokeWidth={1}
                dot={false}
              />
            </ScatterChart>
          </ResponsiveContainer>
        </div>

        {/* Mean Squared Displacement */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">
            Mean Squared Displacement Analysis
          </h3>
          <ResponsiveContainer width="100%" height={400}>
            <LineChart data={walkData.map((point, i) => ({
              step: i,
              msd: point.x ** 2 + point.y ** 2 + (dimension === '3D' ? point.z ** 2 : 0),
              theoretical: 2 * (dimension === '3D' ? 3 : 2) * i * (parameters.stepSize ** 2)
            }))}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="step"
                label={{ value: 'Time Steps', position: 'insideBottom', offset: -5 }}
              />
              <YAxis 
                label={{ value: 'MSD', angle: -90, position: 'insideLeft' }}
              />
              <Tooltip 
                formatter={(value, name) => [typeof value === 'number' ? value.toFixed(2) : value, name]}
              />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="msd" 
                stroke={walkTypes[activeWalkType].color}
                strokeWidth={2}
                dot={false}
                name="Observed MSD"
              />
              <Line 
                type="monotone" 
                dataKey="theoretical" 
                stroke="#6b7280"
                strokeWidth={1}
                strokeDasharray="5 5"
                dot={false}
                name="Theoretical (Simple)"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Comparative Analysis Table */}
      <div className="mt-8 bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
          <h3 className="text-lg font-semibold">Comparative Analysis Framework</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Process Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Scaling Behavior
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Implementation Complexity
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Primary Applications
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              <tr>
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">
                  Simple Random Walk
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  ⟨r²⟩ ∝ t (Diffusive)
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Low
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Molecular diffusion, Brownian motion
                </td>
              </tr>
              <tr>
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">
                  Biased Random Walk
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  ⟨r⟩ ∝ t (Ballistic + Diffusive)
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Low-Medium
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Chemotaxis, financial trends
                </td>
              </tr>
              <tr>
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">
                  Correlated Random Walk
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Persistent → Diffusive
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Medium
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Animal migration, cell movement
                </td>
              </tr>
              <tr>
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">
                  Lévy Flight
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  ⟨r²⟩ ∝ t^(2/α) (Superdiffusive)
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  High
                </td>
                <td className="px-6 py-4 text-sm text-gray-600">
                  Foraging strategies, turbulence
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Key Insights */}
      <div className="mt-8 bg-green-50 border border-green-200 p-6 rounded-lg">
        <h3 className="text-lg font-semibold text-green-900 mb-3">
          Analytical Framework Insights
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-green-800">
          <div>
            <h4 className="font-semibold mb-2">Statistical Convergence:</h4>
            <p>Mean squared displacement provides robust measure of transport efficiency across process types, with clear signatures distinguishing diffusive (α=1) from anomalous (α≠1) scaling regimes.</p>
          </div>
          <div>
            <h4 className="font-semibold mb-2">Computational Strategy:</h4>
            <p>Algorithm selection depends on application requirements: simple walks for baseline comparison, correlated walks for biological systems, Lévy flights for optimization problems.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RandomWalkVisualizer;