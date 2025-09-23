# Financial Stochastic MCP Server

A Model Context Protocol (MCP) server for advanced financial stochastic process simulation and risk analysis. Based on the financial stochastic analyzer components from your TSX files.

## Features

### 📈 Financial Models
- **Geometric Brownian Motion (GBM)**: Standard stock price modeling
- **Ornstein-Uhlenbeck Process**: Mean-reverting processes (rates, volatility)
- **Heston Stochastic Volatility**: Advanced option pricing model
- **Merton Jump Diffusion**: Jump processes for sudden market moves
- **Cox-Ingersoll-Ross (CIR)**: Interest rate modeling

### 📊 Risk Analytics
- **Value at Risk (VaR)**: Market risk quantification
- **Expected Shortfall (CVaR)**: Tail risk analysis
- **Volatility Analysis**: Time-varying volatility modeling
- **Maximum Drawdown**: Peak-to-trough analysis
- **Sharpe Ratio**: Risk-adjusted return metrics

## Available Tools

### 1. `generate_gbm`
Generate Geometric Brownian Motion paths for stock price modeling.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `mu` (number): Drift rate (annual) (default: 0.05)
- `sigma` (number): Volatility (annual) (default: 0.2)
- `initialPrice` (number): Initial asset price (default: 100)

**Mathematical Model:**
```
dS_t = μS_t dt + σS_t dW_t
```

### 2. `generate_ou_process`
Generate Ornstein-Uhlenbeck mean-reverting process.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `kappa` (number): Mean reversion speed (default: 2.0)
- `theta` (number): Long-term mean level (default: 0.04)
- `sigma` (number): Volatility parameter (default: 0.2)
- `initialValue` (number): Initial value (default: 100)

**Mathematical Model:**
```
dX_t = κ(θ - X_t)dt + σ dW_t
```

### 3. `generate_heston_model`
Generate Heston stochastic volatility model paths.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `mu` (number): Drift rate (default: 0.05)
- `kappa` (number): Volatility mean reversion speed (default: 2.0)
- `theta` (number): Long-term variance (default: 0.04)
- `xi` (number): Vol of vol (default: 0.1)
- `rho` (number): Correlation between price and vol (default: -0.7)
- `initialPrice` (number): Initial asset price (default: 100)
- `initialVar` (number): Initial variance (default: 0.04)

**Mathematical Model:**
```
dS_t = μS_t dt + √v_t S_t dW_1
dv_t = κ(θ - v_t)dt + ξ√v_t dW_2
corr(dW_1, dW_2) = ρ dt
```

### 4. `generate_merton_jump`
Generate Merton jump diffusion model with discontinuous jumps.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `mu` (number): Drift rate (default: 0.05)
- `sigma` (number): Diffusion volatility (default: 0.2)
- `lambda` (number): Jump intensity (default: 0.1)
- `muJ` (number): Jump mean (default: -0.1)
- `sigmaJ` (number): Jump volatility (default: 0.15)
- `initialPrice` (number): Initial asset price (default: 100)

**Mathematical Model:**
```
dS_t = μS_t dt + σS_t dW_t + S_t(e^J - 1)dN_t
J ~ N(μ_J, σ_J²), N_t ~ Poisson(λt)
```

### 5. `generate_cir_process`
Generate Cox-Ingersoll-Ross interest rate model.

**Parameters:**
- `steps` (number): Number of time steps (default: 1000)
- `timeHorizon` (number): Time horizon in years (default: 1.0)
- `kappa` (number): Mean reversion speed (default: 2.0)
- `theta` (number): Long-term rate level (default: 0.04)
- `sigma` (number): Volatility parameter (default: 0.2)
- `initialRate` (number): Initial interest rate (default: 0.03)

**Mathematical Model:**
```
dr_t = κ(θ - r_t)dt + σ√r_t dW_t
```

### 6. `calculate_risk_metrics`
Calculate comprehensive risk metrics from price path.

**Parameters:**
- `path` (array): Array of price/rate path points
- `confidenceLevel` (number): VaR confidence level (default: 0.05)

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
    "financial-stochastic": {
      "command": "node",
      "args": ["src/index.js"],
      "cwd": "/path/to/financial-stochastic-mcp"
    }
  }
}
```

## Usage Examples

### Stock Price Simulation (GBM)
```javascript
const result = await callTool('generate_gbm', {
  steps: 252,        // Trading days in a year
  timeHorizon: 1.0,  // 1 year
  mu: 0.08,          // 8% annual return
  sigma: 0.2,        // 20% annual volatility
  initialPrice: 100
});
```

### Interest Rate Modeling (CIR)
```javascript
const result = await callTool('generate_cir_process', {
  steps: 252,
  timeHorizon: 1.0,
  kappa: 2.0,        // Fast mean reversion
  theta: 0.04,       // 4% long-term rate
  sigma: 0.2,        // 20% rate volatility
  initialRate: 0.03  // 3% starting rate
});
```

### Option Pricing (Heston Model)
```javascript
const result = await callTool('generate_heston_model', {
  steps: 252,
  timeHorizon: 1.0,
  mu: 0.05,
  kappa: 2.0,        // Vol mean reversion
  theta: 0.04,       // Long-term variance
  xi: 0.1,           // Vol of vol
  rho: -0.7,         // Negative correlation
  initialPrice: 100,
  initialVar: 0.04
});
```

## Output Format

Each tool returns comprehensive results including:

```json
{
  "model": "geometric_brownian_motion",
  "parameters": { ... },
  "path": [
    {"time": 0, "price": 100, "step": 0},
    {"time": 0.004, "price": 101.2, "step": 1},
    ...
  ],
  "riskMetrics": {
    "meanReturn": 0.082,           // Annualized
    "volatility": 0.203,           // Annualized  
    "sharpeRatio": 0.404,          // Risk-adjusted
    "valueAtRisk": -0.032,         // 95% VaR
    "expectedShortfall": -0.048,   // CVaR
    "maxDrawdown": 0.156,          // Peak-to-trough
    "totalReturn": 0.087           // Period return
  }
}
```

## Risk Metrics Explained

- **Mean Return**: Average logarithmic return (annualized)
- **Volatility**: Standard deviation of returns (annualized)
- **Sharpe Ratio**: Risk-adjusted performance metric
- **Value at Risk (VaR)**: Maximum expected loss at 95% confidence
- **Expected Shortfall**: Average loss beyond VaR threshold
- **Maximum Drawdown**: Largest peak-to-trough decline
- **Total Return**: Cumulative return over the period

## Applications

### Trading & Investment
- Portfolio optimization and risk management
- Option pricing and hedging strategies
- Asset allocation and diversification analysis

### Risk Management
- Market risk measurement (VaR, CVaR)
- Stress testing and scenario analysis
- Capital adequacy assessment

### Quantitative Research
- Model validation and backtesting
- Parameter estimation and calibration
- Academic research and education

## Mathematical Notes

### Random Number Generation
- Uses Box-Muller transformation for normal variates
- Ensures numerical stability for extreme parameters
- Handles boundary conditions (non-negative rates/variances)

### Numerical Schemes
- Euler-Maruyama discretization for SDEs
- Feller condition handling in CIR model
- Jump process simulation via Poisson distribution

## License

MIT License - See LICENSE file for details.

---

Generated from TSX financial stochastic analyzer components for defensive financial modeling and risk analysis purposes only. Not intended for investment advice.