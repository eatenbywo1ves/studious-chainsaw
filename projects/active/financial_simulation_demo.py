import numpy as np
import matplotlib.pyplot as plt
import json
from datetime import datetime
import pandas as pd
from matplotlib.gridspec import GridSpec
import seaborn as sns

# Set style for better visualizations
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

class FinancialSimulation:
    def __init__(self):
        self.results = {}
        
    def plot_gbm_simulation(self, gbm_data):
        """Visualize Geometric Brownian Motion path"""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        # Extract path data
        path = gbm_data['path']
        times = [p['time'] for p in path]
        prices = [p['price'] for p in path]
        
        # Plot price path
        ax1.plot(times, prices, linewidth=2, alpha=0.8)
        ax1.set_title('Stock Price Evolution (Geometric Brownian Motion)', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Time (years)')
        ax1.set_ylabel('Price ($)')
        ax1.grid(True, alpha=0.3)
        
        # Calculate and plot returns
        returns = np.diff(prices) / prices[:-1]
        ax2.hist(returns, bins=50, alpha=0.7, edgecolor='black')
        ax2.set_title('Return Distribution', fontsize=12)
        ax2.set_xlabel('Returns')
        ax2.set_ylabel('Frequency')
        ax2.axvline(np.mean(returns), color='red', linestyle='--', label=f'Mean: {np.mean(returns):.4f}')
        ax2.axvline(np.median(returns), color='green', linestyle='--', label=f'Median: {np.median(returns):.4f}')
        ax2.legend()
        
        plt.tight_layout()
        return fig
    
    def plot_heston_model(self, heston_data):
        """Visualize Heston stochastic volatility model"""
        fig = plt.figure(figsize=(14, 10))
        gs = GridSpec(3, 2, figure=fig)
        
        # Extract data
        path = heston_data['path']
        times = [p['time'] for p in path]
        prices = [p['price'] for p in path]
        variances = [p['variance'] for p in path]
        
        # Price path
        ax1 = fig.add_subplot(gs[0, :])
        ax1.plot(times, prices, linewidth=2, color='navy', alpha=0.8)
        ax1.set_title('Asset Price with Stochastic Volatility (Heston Model)', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Time (years)')
        ax1.set_ylabel('Price ($)')
        ax1.grid(True, alpha=0.3)
        
        # Variance path
        ax2 = fig.add_subplot(gs[1, :])
        ax2.plot(times, np.sqrt(variances) * 100, linewidth=2, color='darkred', alpha=0.8)
        ax2.set_title('Implied Volatility Evolution', fontsize=12)
        ax2.set_xlabel('Time (years)')
        ax2.set_ylabel('Volatility (%)')
        ax2.grid(True, alpha=0.3)
        
        # Price vs Volatility scatter
        ax3 = fig.add_subplot(gs[2, 0])
        scatter = ax3.scatter(np.sqrt(variances) * 100, prices, c=times, cmap='viridis', alpha=0.6, s=1)
        ax3.set_title('Price-Volatility Relationship', fontsize=12)
        ax3.set_xlabel('Volatility (%)')
        ax3.set_ylabel('Price ($)')
        plt.colorbar(scatter, ax=ax3, label='Time')
        
        # Return distribution
        ax4 = fig.add_subplot(gs[2, 1])
        returns = np.diff(prices) / prices[:-1]
        ax4.hist(returns, bins=50, alpha=0.7, color='teal', edgecolor='black')
        ax4.set_title('Return Distribution (with stochastic vol)', fontsize=12)
        ax4.set_xlabel('Returns')
        ax4.set_ylabel('Frequency')
        
        plt.tight_layout()
        return fig
    
    def plot_multi_asset_correlation(self, multi_gbm_data):
        """Visualize multiple correlated assets"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Extract paths for each asset
        path = multi_gbm_data['paths']
        times = [p['time'] for p in path]
        
        # Assuming 3 assets
        asset1_prices = [p['asset1']['price'] for p in path]
        asset2_prices = [p['asset2']['price'] for p in path]
        asset3_prices = [p['asset3']['price'] for p in path]
        
        # Plot all three assets
        ax1 = axes[0, 0]
        ax1.plot(times, asset1_prices, label='Asset 1', linewidth=2, alpha=0.8)
        ax1.plot(times, asset2_prices, label='Asset 2', linewidth=2, alpha=0.8)
        ax1.plot(times, asset3_prices, label='Asset 3', linewidth=2, alpha=0.8)
        ax1.set_title('Correlated Asset Prices', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Time (years)')
        ax1.set_ylabel('Price ($)')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Correlation heatmap
        ax2 = axes[0, 1]
        prices_df = pd.DataFrame({
            'Asset 1': asset1_prices,
            'Asset 2': asset2_prices,
            'Asset 3': asset3_prices
        })
        corr_matrix = prices_df.corr()
        sns.heatmap(corr_matrix, annot=True, fmt='.3f', cmap='coolwarm', 
                    center=0, ax=ax2, vmin=-1, vmax=1)
        ax2.set_title('Asset Correlation Matrix', fontsize=12)
        
        # Scatter plots
        ax3 = axes[1, 0]
        ax3.scatter(asset1_prices, asset2_prices, alpha=0.5, s=2)
        ax3.set_title('Asset 1 vs Asset 2', fontsize=12)
        ax3.set_xlabel('Asset 1 Price')
        ax3.set_ylabel('Asset 2 Price')
        
        ax4 = axes[1, 1]
        # Calculate cumulative returns
        cum_ret1 = np.array(asset1_prices) / asset1_prices[0] - 1
        cum_ret2 = np.array(asset2_prices) / asset2_prices[0] - 1
        cum_ret3 = np.array(asset3_prices) / asset3_prices[0] - 1
        
        ax4.plot(times, cum_ret1 * 100, label='Asset 1', linewidth=2, alpha=0.8)
        ax4.plot(times, cum_ret2 * 100, label='Asset 2', linewidth=2, alpha=0.8)
        ax4.plot(times, cum_ret3 * 100, label='Asset 3', linewidth=2, alpha=0.8)
        ax4.set_title('Cumulative Returns', fontsize=12)
        ax4.set_xlabel('Time (years)')
        ax4.set_ylabel('Cumulative Return (%)')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_random_walks(self, simple_walk, levy_walk, biased_walk):
        """Compare different random walk types"""
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        
        # Simple Random Walk
        ax1 = axes[0, 0]
        simple_x = [p['x'] for p in simple_walk['path']]
        simple_y = [p['y'] for p in simple_walk['path']]
        ax1.plot(simple_x, simple_y, alpha=0.7, linewidth=1)
        ax1.scatter(simple_x[0], simple_y[0], color='green', s=100, marker='o', label='Start')
        ax1.scatter(simple_x[-1], simple_y[-1], color='red', s=100, marker='s', label='End')
        ax1.set_title('Simple Random Walk', fontsize=12, fontweight='bold')
        ax1.set_xlabel('X Position')
        ax1.set_ylabel('Y Position')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Levy Flight
        ax2 = axes[0, 1]
        levy_x = [p['x'] for p in levy_walk['path']]
        levy_y = [p['y'] for p in levy_walk['path']]
        ax2.plot(levy_x, levy_y, alpha=0.7, linewidth=1, color='orange')
        ax2.scatter(levy_x[0], levy_y[0], color='green', s=100, marker='o', label='Start')
        ax2.scatter(levy_x[-1], levy_y[-1], color='red', s=100, marker='s', label='End')
        ax2.set_title('Levy Flight (Heavy-tailed jumps)', fontsize=12, fontweight='bold')
        ax2.set_xlabel('X Position')
        ax2.set_ylabel('Y Position')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        # Biased Walk
        ax3 = axes[0, 2]
        biased_x = [p['x'] for p in biased_walk['path']]
        biased_y = [p['y'] for p in biased_walk['path']]
        ax3.plot(biased_x, biased_y, alpha=0.7, linewidth=1, color='purple')
        ax3.scatter(biased_x[0], biased_y[0], color='green', s=100, marker='o', label='Start')
        ax3.scatter(biased_x[-1], biased_y[-1], color='red', s=100, marker='s', label='End')
        ax3.set_title('Biased Random Walk', fontsize=12, fontweight='bold')
        ax3.set_xlabel('X Position')
        ax3.set_ylabel('Y Position')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        # Distance from origin over time
        ax4 = axes[1, 0]
        simple_dist = [np.sqrt(p['x']**2 + p['y']**2) for p in simple_walk['path']]
        levy_dist = [np.sqrt(p['x']**2 + p['y']**2) for p in levy_walk['path']]
        biased_dist = [np.sqrt(p['x']**2 + p['y']**2) for p in biased_walk['path']]
        
        steps = list(range(len(simple_dist)))
        ax4.plot(steps, simple_dist, label='Simple', alpha=0.7)
        ax4.plot(steps, levy_dist, label='Levy', alpha=0.7)
        ax4.plot(steps, biased_dist, label='Biased', alpha=0.7)
        ax4.set_title('Distance from Origin', fontsize=12)
        ax4.set_xlabel('Step')
        ax4.set_ylabel('Distance')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        
        # Step size distributions
        ax5 = axes[1, 1]
        simple_steps = [np.sqrt((simple_x[i]-simple_x[i-1])**2 + (simple_y[i]-simple_y[i-1])**2) 
                       for i in range(1, len(simple_x))]
        levy_steps = [np.sqrt((levy_x[i]-levy_x[i-1])**2 + (levy_y[i]-levy_y[i-1])**2) 
                     for i in range(1, len(levy_x))]
        
        ax5.hist(simple_steps, bins=30, alpha=0.5, label='Simple', density=True)
        ax5.hist(levy_steps, bins=30, alpha=0.5, label='Levy', density=True)
        ax5.set_title('Step Size Distribution', fontsize=12)
        ax5.set_xlabel('Step Size')
        ax5.set_ylabel('Density')
        ax5.legend()
        ax5.set_yscale('log')
        
        # Mean squared displacement
        ax6 = axes[1, 2]
        ax6.loglog(steps[:100], np.array(simple_dist[:100])**2, label='Simple', alpha=0.7)
        ax6.loglog(steps[:100], np.array(levy_dist[:100])**2, label='Levy', alpha=0.7)
        ax6.loglog(steps[:100], np.array(biased_dist[:100])**2, label='Biased', alpha=0.7)
        ax6.set_title('Mean Squared Displacement (log-log)', fontsize=12)
        ax6.set_xlabel('Steps (log)')
        ax6.set_ylabel('MSD (log)')
        ax6.legend()
        ax6.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_risk_metrics(self, metrics):
        """Visualize comprehensive risk metrics"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        
        # Risk metrics bar chart
        ax1 = axes[0, 0]
        metric_names = ['VaR (5%)', 'CVaR (5%)', 'Max Drawdown', 'Sharpe Ratio']
        metric_values = [
            metrics.get('var', 0),
            metrics.get('cvar', 0),
            metrics.get('maxDrawdown', 0),
            metrics.get('sharpe', 0)
        ]
        colors = ['red' if v < 0 else 'green' for v in metric_values]
        bars = ax1.bar(metric_names, metric_values, color=colors, alpha=0.7, edgecolor='black')
        ax1.set_title('Risk Metrics Summary', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Value')
        ax1.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for bar, val in zip(bars, metric_values):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{val:.4f}', ha='center', va='bottom' if val >= 0 else 'top')
        
        # Statistics summary
        ax2 = axes[0, 1]
        stats_text = f"""
        Statistics Summary:
        ─────────────────
        Mean Return: {metrics.get('meanReturn', 0):.4f}
        Std Deviation: {metrics.get('stdDev', 0):.4f}
        Skewness: {metrics.get('skewness', 0):.4f}
        Kurtosis: {metrics.get('kurtosis', 0):.4f}
        Min Return: {metrics.get('minReturn', 0):.4f}
        Max Return: {metrics.get('maxReturn', 0):.4f}
        """
        ax2.text(0.1, 0.5, stats_text, transform=ax2.transAxes, fontsize=11,
                verticalalignment='center', fontfamily='monospace')
        ax2.set_title('Statistical Measures', fontsize=12)
        ax2.axis('off')
        
        # Drawdown chart (if available)
        ax3 = axes[1, 0]
        if 'drawdowns' in metrics and metrics['drawdowns']:
            drawdown_indices = list(range(len(metrics['drawdowns'])))
            ax3.fill_between(drawdown_indices, 
                            0, metrics['drawdowns'], 
                            color='red', alpha=0.4)
            ax3.plot(metrics['drawdowns'], color='darkred', linewidth=2)
            ax3.set_title('Drawdown Analysis', fontsize=12)
            ax3.set_xlabel('Time')
            ax3.set_ylabel('Drawdown (%)')
            ax3.grid(True, alpha=0.3)
        else:
            ax3.text(0.5, 0.5, 'Drawdown data not available', 
                    transform=ax3.transAxes, ha='center')
            ax3.axis('off')
        
        # Risk-Return scatter (placeholder for portfolio context)
        ax4 = axes[1, 1]
        ax4.scatter([metrics.get('stdDev', 0)], [metrics.get('meanReturn', 0)], 
                   s=200, color='blue', alpha=0.6, edgecolor='black', linewidth=2)
        ax4.set_title('Risk-Return Profile', fontsize=12)
        ax4.set_xlabel('Risk (Std Dev)')
        ax4.set_ylabel('Expected Return')
        ax4.grid(True, alpha=0.3)
        
        # Add efficient frontier reference line
        x_range = np.linspace(0, metrics.get('stdDev', 1) * 2, 100)
        ax4.plot(x_range, x_range * metrics.get('sharpe', 0.5), 
                'g--', alpha=0.5, label='Sharpe Reference')
        ax4.legend()
        
        plt.tight_layout()
        return fig

# Initialize simulation
sim = FinancialSimulation()
print("Financial Simulation Framework initialized")
print("=" * 60)