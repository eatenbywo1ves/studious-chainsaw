import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import asyncio
from typing import Dict, List, Any
from mcp_client import MCPFinancialClient

st.set_page_config(
    page_title="Financial Stochastic Models",
    page_icon="📈",
    layout="wide"
)

st.title("📈 Financial Stochastic Models Dashboard")

st.sidebar.header("Model Selection")
model_type = st.sidebar.selectbox(
    "Choose a stochastic model:",
    [
        "Geometric Brownian Motion (GBM)",
        "Ornstein-Uhlenbeck Process",
        "Heston Model",
        "Merton Jump Diffusion",
        "Cox-Ingersoll-Ross (CIR)",
        "Multi-Asset GBM",
        "Multi-Asset Heston"
    ]
)

@st.cache_resource
def get_mcp_client():
    """Get MCP client instance"""
    return MCPFinancialClient()

async def run_simulation(client, model_type, params):
    """Run simulation based on model type"""
    if model_type == "gbm":
        return await client.generate_gbm(**params)
    elif model_type == "ou":
        return await client.generate_ou_process(**params)
    elif model_type == "heston":
        return await client.generate_heston_model(**params)
    else:
        raise ValueError(f"Unknown model type: {model_type}")

def create_price_chart(data, title="Price Path"):
    """Create price chart using Plotly"""
    df = pd.DataFrame(data)
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['time'],
        y=df['price'],
        mode='lines',
        name='Price Path'
    ))
    fig.update_layout(
        title=title,
        xaxis_title="Time",
        yaxis_title="Price",
        height=400
    )
    return fig

if model_type == "Geometric Brownian Motion (GBM)":
    st.header("Geometric Brownian Motion Parameters")
    
    col1, col2 = st.columns(2)
    
    with col1:
        initial_price = st.number_input("Initial Price", value=100.0, min_value=0.1)
        mu = st.slider("Drift Rate (μ)", -0.5, 0.5, 0.05, 0.01)
        sigma = st.slider("Volatility (σ)", 0.01, 1.0, 0.2, 0.01)
    
    with col2:
        steps = st.number_input("Number of Steps", value=1000, min_value=100, max_value=10000)
        time_horizon = st.number_input("Time Horizon (years)", value=1.0, min_value=0.1, max_value=5.0)
    
    if st.button("Generate GBM Path"):
        params = {
            'initial_price': initial_price,
            'mu': mu,
            'sigma': sigma,
            'steps': int(steps),
            'time_horizon': time_horizon
        }
        
        with st.spinner("Generating path..."):
            client = get_mcp_client()
            data = asyncio.run(run_simulation(client, "gbm", params))
            
            fig = create_price_chart(data, "Geometric Brownian Motion")
            st.plotly_chart(fig, use_container_width=True)
            
            # Calculate and display risk metrics
            risk_metrics = asyncio.run(client.calculate_risk_metrics(data))
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Final Price", f"${risk_metrics['final_price']:.2f}")
            with col2:
                st.metric("Total Return", f"{risk_metrics['total_return']:.2%}")
            with col3:
                st.metric("Volatility", f"{risk_metrics['volatility']:.2%}")
            with col4:
                st.metric("Sharpe Ratio", f"{risk_metrics['sharpe_ratio']:.2f}")
            
            # Risk metrics section
            st.subheader("Risk Metrics")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("VaR (95%)", f"{risk_metrics['var_95']:.2%}")
            with col2:
                st.metric("CVaR (95%)", f"{risk_metrics['cvar_95']:.2%}")
            with col3:
                st.metric("Max Drawdown", f"{risk_metrics['max_drawdown']:.2%}")

elif model_type == "Ornstein-Uhlenbeck Process":
    st.header("Ornstein-Uhlenbeck Process Parameters")
    
    col1, col2 = st.columns(2)
    
    with col1:
        initial_value = st.number_input("Initial Value", value=100.0)
        theta = st.number_input("Long-term Mean (θ)", value=0.04, step=0.01)
        kappa = st.slider("Mean Reversion Speed (κ)", 0.1, 5.0, 2.0, 0.1)
    
    with col2:
        sigma_ou = st.slider("Volatility (σ)", 0.01, 1.0, 0.2, 0.01)
        steps_ou = st.number_input("Number of Steps", value=1000, min_value=100, max_value=10000, key="ou_steps")
        time_horizon_ou = st.number_input("Time Horizon (years)", value=1.0, min_value=0.1, max_value=5.0, key="ou_time")
    
    st.info("OU Process simulates mean-reverting behavior, commonly used for interest rates.")
    
    if st.button("Generate OU Process"):
        params = {
            'initial_value': initial_value,
            'theta': theta,
            'kappa': kappa,
            'sigma': sigma_ou,
            'steps': int(steps_ou),
            'time_horizon': time_horizon_ou
        }
        
        with st.spinner("Generating path..."):
            client = get_mcp_client()
            data = asyncio.run(run_simulation(client, "ou", params))
            
            # Convert to price format for chart
            chart_data = [{"time": d["time"], "price": d["value"]} for d in data]
            fig = create_price_chart(chart_data, "Ornstein-Uhlenbeck Process")
            st.plotly_chart(fig, use_container_width=True)
            
            # Calculate and display metrics
            risk_metrics = asyncio.run(client.calculate_risk_metrics(chart_data))
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Final Value", f"{risk_metrics['final_price']:.4f}")
            with col2:
                st.metric("Mean Reversion", f"{abs(risk_metrics['final_price'] - theta):.4f}")
            with col3:
                st.metric("Volatility", f"{risk_metrics['volatility']:.4f}")

elif model_type == "Heston Model":
    st.header("Heston Stochastic Volatility Model Parameters")
    
    col1, col2 = st.columns(2)
    
    with col1:
        initial_price_h = st.number_input("Initial Price", value=100.0, key="heston_price")
        initial_var = st.number_input("Initial Variance", value=0.04, step=0.01)
        mu_h = st.slider("Drift Rate (μ)", -0.5, 0.5, 0.05, 0.01, key="heston_mu")
        rho = st.slider("Price-Vol Correlation (ρ)", -1.0, 1.0, -0.7, 0.1)
    
    with col2:
        kappa_h = st.slider("Vol Mean Reversion (κ)", 0.1, 5.0, 2.0, 0.1, key="heston_kappa")
        theta_h = st.number_input("Long-term Variance (θ)", value=0.04, step=0.01, key="heston_theta")
        xi = st.slider("Vol of Vol (ξ)", 0.01, 1.0, 0.1, 0.01)
        steps_h = st.number_input("Number of Steps", value=1000, min_value=100, max_value=10000, key="heston_steps")
    
    st.info("Heston Model incorporates stochastic volatility with correlation between price and volatility.")
    
    if st.button("Generate Heston Model"):
        params = {
            'initial_price': initial_price_h,
            'initial_var': initial_var,
            'mu': mu_h,
            'kappa': kappa_h,
            'theta': theta_h,
            'xi': xi,
            'rho': rho,
            'steps': int(steps_h),
            'time_horizon': 1.0
        }
        
        with st.spinner("Generating paths..."):
            client = get_mcp_client()
            result = asyncio.run(run_simulation(client, "heston", params))
            
            # Plot price and variance
            col1, col2 = st.columns(2)
            
            with col1:
                price_fig = create_price_chart(result["prices"], "Heston Model - Price Path")
                st.plotly_chart(price_fig, use_container_width=True)
            
            with col2:
                var_data = [{"time": d["time"], "price": d["variance"]} for d in result["variances"]]
                var_fig = create_price_chart(var_data, "Heston Model - Variance Path")
                var_fig.update_yaxis(title="Variance")
                st.plotly_chart(var_fig, use_container_width=True)
            
            # Calculate and display risk metrics
            risk_metrics = asyncio.run(client.calculate_risk_metrics(result["prices"]))
            
            st.subheader("Risk Metrics")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Final Price", f"${risk_metrics['final_price']:.2f}")
            with col2:
                st.metric("Total Return", f"{risk_metrics['total_return']:.2%}")
            with col3:
                st.metric("Volatility", f"{risk_metrics['volatility']:.2%}")
            with col4:
                st.metric("Sharpe Ratio", f"{risk_metrics['sharpe_ratio']:.2f}")

else:
    st.header(f"{model_type} Parameters")
    st.info("Parameter controls for this model will be implemented when MCP integration is complete.")

st.sidebar.markdown("---")
st.sidebar.markdown("**About**")
st.sidebar.markdown("This dashboard demonstrates financial stochastic models using MCP tools.")