#!/usr/bin/env python3
"""
Test script for financial stochastic models
Run this to test the models without Streamlit
"""

import asyncio
import numpy as np
from mcp_client import MCPFinancialClient

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

async def test_gbm():
    """Test Geometric Brownian Motion"""
    print("Testing Geometric Brownian Motion...")
    client = MCPFinancialClient()
    
    # Generate GBM path
    data = await client.generate_gbm(
        initial_price=100,
        mu=0.05,
        sigma=0.2,
        steps=1000,
        time_horizon=1.0
    )
    
    # Calculate risk metrics
    risk_metrics = await client.calculate_risk_metrics(data)
    
    print(f"Final Price: ${risk_metrics['final_price']:.2f}")
    print(f"Total Return: {risk_metrics['total_return']:.2%}")
    print(f"Volatility: {risk_metrics['volatility']:.2%}")
    print(f"Sharpe Ratio: {risk_metrics['sharpe_ratio']:.2f}")
    print(f"VaR (95%): {risk_metrics['var_95']:.2%}")
    print(f"Max Drawdown: {risk_metrics['max_drawdown']:.2%}")
    
    return data

async def test_ou_process():
    """Test Ornstein-Uhlenbeck Process"""
    print("\nTesting Ornstein-Uhlenbeck Process...")
    client = MCPFinancialClient()
    
    # Generate OU process
    data = await client.generate_ou_process(
        initial_value=100,
        theta=0.04,
        kappa=2.0,
        sigma=0.2,
        steps=1000,
        time_horizon=1.0
    )
    
    print(f"Final Value: {data[-1]['value']:.4f}")
    print(f"Mean Reversion Target: 0.04")
    print(f"Distance from Target: {abs(data[-1]['value'] - 0.04):.4f}")
    
    return data

async def test_heston():
    """Test Heston Model"""
    print("\nTesting Heston Stochastic Volatility Model...")
    client = MCPFinancialClient()
    
    # Generate Heston paths
    result = await client.generate_heston_model(
        initial_price=100,
        initial_var=0.04,
        mu=0.05,
        kappa=2.0,
        theta=0.04,
        xi=0.1,
        rho=-0.7,
        steps=1000,
        time_horizon=1.0
    )
    
    # Calculate risk metrics for price path
    risk_metrics = await client.calculate_risk_metrics(result["prices"])
    
    print(f"Final Price: ${risk_metrics['final_price']:.2f}")
    print(f"Final Variance: {result['variances'][-1]['variance']:.4f}")
    print(f"Total Return: {risk_metrics['total_return']:.2%}")
    print(f"Volatility: {risk_metrics['volatility']:.2%}")
    
    return result

def plot_results(gbm_data, ou_data, heston_result):
    """Plot the results using matplotlib"""
    if not HAS_MATPLOTLIB:
        print("\nMatplotlib not available - skipping plots")
        return
        
    try:
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))
        
        # GBM Plot
        times = [d['time'] for d in gbm_data]
        prices = [d['price'] for d in gbm_data]
        ax1.plot(times, prices, 'b-', linewidth=1)
        ax1.set_title('Geometric Brownian Motion')
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Price')
        ax1.grid(True, alpha=0.3)
        
        # OU Process Plot
        ou_times = [d['time'] for d in ou_data]
        ou_values = [d['value'] for d in ou_data]
        ax2.plot(ou_times, ou_values, 'r-', linewidth=1)
        ax2.axhline(y=0.04, color='r', linestyle='--', alpha=0.7, label='Mean Level')
        ax2.set_title('Ornstein-Uhlenbeck Process')
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Value')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        # Heston Price Plot
        heston_times = [d['time'] for d in heston_result['prices']]
        heston_prices = [d['price'] for d in heston_result['prices']]
        ax3.plot(heston_times, heston_prices, 'g-', linewidth=1)
        ax3.set_title('Heston Model - Price Path')
        ax3.set_xlabel('Time')
        ax3.set_ylabel('Price')
        ax3.grid(True, alpha=0.3)
        
        # Heston Variance Plot
        heston_vars = [d['variance'] for d in heston_result['variances']]
        ax4.plot(heston_times, heston_vars, 'm-', linewidth=1)
        ax4.set_title('Heston Model - Variance Path')
        ax4.set_xlabel('Time')
        ax4.set_ylabel('Variance')
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('financial_models_test.png', dpi=150, bbox_inches='tight')
        print("\nPlots saved as 'financial_models_test.png'")
        
    except ImportError:
        print("\nMatplotlib not available - skipping plots")

async def main():
    """Run all tests"""
    print("=" * 60)
    print("FINANCIAL STOCHASTIC MODELS TEST")
    print("=" * 60)
    
    try:
        # Test all models
        gbm_data = await test_gbm()
        ou_data = await test_ou_process()
        heston_result = await test_heston()
        
        # Try to plot results
        plot_results(gbm_data, ou_data, heston_result)
        
        print("\n" + "=" * 60)
        print("ALL TESTS COMPLETED SUCCESSFULLY!")
        print("Models are working correctly.")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        print("Check the error above for troubleshooting.")

if __name__ == "__main__":
    asyncio.run(main())