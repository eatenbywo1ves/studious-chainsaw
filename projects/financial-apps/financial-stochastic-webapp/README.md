# Financial Stochastic Models Web Application

A Streamlit web application for visualizing financial stochastic models using MCP (Model Context Protocol) tools.

## Features

- **Multiple Stochastic Models:**
  - Geometric Brownian Motion (GBM)
  - Ornstein-Uhlenbeck Process
  - Heston Stochastic Volatility Model
  - Merton Jump Diffusion (planned)
  - Cox-Ingersoll-Ross (planned)
  - Multi-Asset Models (planned)

- **Interactive Parameters:** Adjust model parameters via intuitive sliders and inputs
- **Real-time Visualization:** Generate and plot stochastic paths using Plotly
- **Risk Metrics:** Calculate VaR, CVaR, Sharpe ratio, max drawdown, and volatility
- **Professional UI:** Clean, responsive dashboard with organized layouts

## Installation

1. Clone or download the project
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the Streamlit application:
```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

## Model Descriptions

### Geometric Brownian Motion (GBM)
Models stock price evolution with constant drift and volatility:
- Used for: Stock price modeling, options pricing
- Parameters: Initial price, drift (μ), volatility (σ), time horizon

### Ornstein-Uhlenbeck Process
Mean-reverting process commonly used for interest rates:
- Used for: Interest rate modeling, commodity prices
- Parameters: Initial value, long-term mean (θ), reversion speed (κ), volatility

### Heston Model
Stochastic volatility model with correlation between price and volatility:
- Used for: Options pricing with stochastic volatility
- Parameters: Initial price/variance, drift, volatility parameters, correlation (ρ)

## Architecture

- **Frontend:** Streamlit with Plotly for interactive charts
- **Backend:** MCP client for stochastic model generation
- **Models:** Numpy-based implementations with async support
- **Risk Metrics:** Comprehensive portfolio analytics

## File Structure

```
financial-stochastic-webapp/
├── app.py              # Main Streamlit application
├── mcp_client.py       # MCP client for model generation
├── requirements.txt    # Python dependencies
└── README.md          # This file
```