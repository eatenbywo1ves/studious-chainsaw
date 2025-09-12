# Multidimensional Stochastic MCP Server

A Model Context Protocol (MCP) server for generating and analyzing multidimensional correlated stochastic processes. Based on the multidimensional stochastic framework from your TSX files.

## Features

### 🔗 Correlated Processes
- **Multi-Asset GBM**: Correlated stock price movements
- **Multi-Process OU**: Correlated mean-reverting processes
- **Multi-Asset Heston**: Correlated stochastic volatility models
- **Portfolio Analysis**: Comprehensive portfolio risk metrics

### 📊 Advanced Analytics
- **Correlation Analysis**: Dynamic correlation measurement
- **Portfolio Metrics**: Risk-adjusted performance analysis
- **Diversification Analysis**: Portfolio optimization insights
- **Multi-Asset Risk**: VaR and CVaR for portfolios

### 🌐 Dimensionality Support
- **2D Processes**: Pairwise correlated systems
- **3D Processes**: Three-asset correlation structures
- **N-D Extensions**: Scalable to multiple assets

## Available Tools

### 1. `generate_multi_gbm`
Generate multiple correlated Geometric Brownian Motion paths.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `assets` (array): Array of asset specifications
  - `mu` (number): Drift rate (default: 0.05)
  - `sigma` (number): Volatility (default: 0.2)
  - `initialPrice` (number): Initial price (default: 100)
- `correlations` (object): Correlation structure
  - `rho_xy` (number): Correlation between assets 0 and 1
  - `rho_xz` (number): Correlation between assets 0 and 2
  - `rho_yz` (number): Correlation between assets 1 and 2

**Mathematical Model:**
```
dS_i = μ_i S_i dt + σ_i S_i dW_i
corr(dW_i, dW_j) = ρ_{ij} dt
```

### 2. `generate_multi_ou`
Generate multiple correlated Ornstein-Uhlenbeck processes.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `processes` (array): Array of OU process specifications
  - `kappa` (number): Mean reversion speed (default: 2.0)
  - `theta` (number): Long-term mean (default: 0.04)
  - `sigma` (number): Volatility (default: 0.2)
  - `initialValue` (number): Initial value (default: 0)
- `correlations` (object): Correlation structure

**Mathematical Model:**
```
dX_i = κ_i(θ_i - X_i)dt + σ_i dW_i
corr(dW_i, dW_j) = ρ_{ij} dt
```

### 3. `generate_multi_heston`
Generate multiple Heston stochastic volatility model paths.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `assets` (array): Array of Heston model specifications
  - `mu` (number): Drift rate (default: 0.05)
  - `kappa` (number): Vol mean reversion speed (default: 2.0)
  - `theta` (number): Long-term variance (default: 0.04)
  - `xi` (number): Vol of vol (default: 0.1)
  - `rho` (number): Price-vol correlation (default: -0.7)
  - `initialPrice` (number): Initial price (default: 100)
  - `initialVar` (number): Initial variance (default: 0.04)

### 4. `calculate_portfolio_metrics`
Calculate comprehensive portfolio metrics from multidimensional path.

**Parameters:**
- `path` (array): Multidimensional path data
- `weights` (array): Portfolio weights for each asset/process

### 5. `analyze_correlations`
Analyze correlation structure in multidimensional data.

**Parameters:**
- `path` (array): Multidimensional path data
- `numAssets` (number): Number of assets to analyze (default: 2)

## Installation & Setup

### Prerequisites
- Node.js 18+
- MCP-compatible client

### Quick Start

1. **Install dependencies:**
```bash
npm install
```

2. **Run the server:**
```bash
npm start
```

3. **Test functionality:**
```bash
npm test
```

## MCP Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "multidimensional-stochastic": {
      "command": "node",
      "args": ["src/index.js"],
      "cwd": "/path/to/multidimensional-stochastic-mcp"
    }
  }
}
```

## Usage Examples

### Two-Asset Portfolio Simulation
```javascript
const result = await callTool('generate_multi_gbm', {
  steps: 252,
  timeHorizon: 1.0,
  assets: [
    { mu: 0.08, sigma: 0.2, initialPrice: 100 },   // Stock A
    { mu: 0.06, sigma: 0.25, initialPrice: 120 }   // Stock B
  ],
  correlations: { rho_xy: 0.6 }  // 60% correlation
});
```

### Three-Asset Correlation Structure
```javascript
const result = await callTool('generate_multi_gbm', {
  steps: 252,
  timeHorizon: 1.0,
  assets: [
    { mu: 0.08, sigma: 0.2, initialPrice: 100 },   // Stock A
    { mu: 0.06, sigma: 0.25, initialPrice: 120 },  // Stock B  
    { mu: 0.10, sigma: 0.3, initialPrice: 80 }     // Stock C
  ],
  correlations: {
    rho_xy: 0.6,   // A-B correlation
    rho_xz: 0.3,   // A-C correlation  
    rho_yz: 0.4    // B-C correlation
  }
});
```

### Portfolio Risk Analysis
```javascript
// After generating multi-asset path
const portfolioMetrics = await callTool('calculate_portfolio_metrics', {
  path: multiAssetPath,
  weights: [0.6, 0.3, 0.1]  // Portfolio allocation
});
```

### Interest Rate Curve Modeling
```javascript
const result = await callTool('generate_multi_ou', {
  steps: 252,
  timeHorizon: 1.0,
  processes: [
    { kappa: 2.0, theta: 0.02, sigma: 0.01, initialValue: 0.015 }, // Short rate
    { kappa: 1.0, theta: 0.04, sigma: 0.015, initialValue: 0.035 }, // Long rate
    { kappa: 0.5, theta: 0.05, sigma: 0.02, initialValue: 0.045 }   // Very long rate
  ],
  correlations: { rho_xy: 0.8, rho_xz: 0.6, rho_yz: 0.9 }
});
```

## Output Format

### Multi-Asset Path Generation
```json
{
  "model": "multi_geometric_brownian_motion",
  "parameters": { ... },
  "path": [
    {
      "time": 0,
      "asset_0": 100, "logPrice_0": 4.605,
      "asset_1": 120, "logPrice_1": 4.787,
      "step": 0
    },
    {
      "time": 0.004,
      "asset_0": 101.2, "logPrice_0": 4.617,
      "asset_1": 119.8, "logPrice_1": 4.785,
      "step": 1
    },
    ...
  ],
  "summary": {
    "totalSteps": 253,
    "numAssets": 2,
    "finalValues": { ... }
  }
}
```

### Portfolio Metrics
```json
{
  "portfolioPath": [
    {"time": 0, "value": 108, "step": 0},
    {"time": 0.004, "value": 108.84, "step": 1},
    ...
  ],
  "meanReturn": 0.074,              // Annualized portfolio return
  "volatility": 0.186,              // Annualized portfolio volatility
  "sharpeRatio": 0.398,             // Risk-adjusted return
  "valueAtRisk": -0.029,            // 95% portfolio VaR
  "expectedShortfall": -0.044,      // Portfolio CVaR
  "maxDrawdown": 0.134,             // Maximum portfolio drawdown
  "totalReturn": 0.067,             // Period portfolio return
  "correlations": {                 // Asset correlations
    "asset_0_1": 0.612
  },
  "diversificationRatio": 0.847     // Portfolio diversification benefit
}
```

## Mathematical Framework

### Correlation Generation
Uses Cholesky decomposition for generating correlated random variables:

For 3D case:
```
L = [ 1    0    0  ]
    [ρ₁₂  √(1-ρ₁₂²)  0 ]
    [ρ₁₃  (ρ₂₃-ρ₁₂ρ₁₃)/√(1-ρ₁₂²)  √(1-ρ₁₃²-((ρ₂₃-ρ₁₂ρ₁₃)/√(1-ρ₁₂²))²)]

[X₁]   [Z₁]
[X₂] = L[Z₂]
[X₃]   [Z₃]
```

### Portfolio Risk Decomposition
- **Individual Asset Risk**: σᵢ²wᵢ²
- **Pairwise Correlations**: 2σᵢσⱼρᵢⱼwᵢwⱼ
- **Total Portfolio Risk**: √(Σᵢσᵢ²wᵢ² + ΣᵢΣⱼ≠ᵢ2σᵢσⱼρᵢⱼwᵢwⱼ)

### Diversification Ratio
Measures the risk reduction benefit of diversification:
```
DR = (Σᵢwᵢσᵢ) / σₚ
```
Where σₚ is the portfolio volatility.

## Applications

### Portfolio Management
- **Asset Allocation**: Optimal portfolio weight determination
- **Risk Budgeting**: Risk contribution analysis
- **Performance Attribution**: Return source analysis

### Risk Management
- **Scenario Analysis**: Multi-asset stress testing
- **Correlation Risk**: Dynamic correlation monitoring
- **Tail Risk**: Portfolio extreme loss analysis

### Derivatives Pricing
- **Multi-Asset Options**: Rainbow options, basket options
- **Correlation Products**: Variance swaps, correlation swaps
- **Structured Products**: Multi-underlying derivatives

### Research Applications
- **Factor Models**: Multi-factor risk model development
- **Market Microstructure**: Cross-asset dependency analysis
- **Systemic Risk**: Financial contagion modeling

## Advanced Features

### Dynamic Correlation
- Time-varying correlation structures
- Regime-switching correlation models
- Non-linear dependency modeling

### High-Dimensional Extensions
- Principal Component Analysis (PCA) integration
- Factor model decomposition
- Dimensionality reduction techniques

### Performance Optimization
- Efficient correlation matrix generation
- Memory-optimized path storage
- Parallel processing capabilities

## License

MIT License - See LICENSE file for details.

---

Generated from TSX multidimensional stochastic framework components for defensive portfolio analysis and risk management purposes only. Not intended for investment advice.