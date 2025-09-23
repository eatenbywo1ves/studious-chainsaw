"""
Financial Stochastic Modeling Demonstration
Using MCP servers for various financial simulations
"""

import json
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime


class FinancialStochasticModeler:
    def __init__(self):
        self.results = {}

    def generate_gbm(
        self, initial_price=100, mu=0.05, sigma=0.2, steps=252, time_horizon=1
    ):
        """Generate Geometric Brownian Motion for stock price modeling"""
        print(f"\n{'='*60}")
        print("Generating Geometric Brownian Motion (GBM)")
        print(f"{'='*60}")
        print(f"Initial Price: ${initial_price}")
        print(f"Drift (μ): {mu*100:.1f}% annual")
        print(f"Volatility (σ): {sigma*100:.1f}% annual")
        print(f"Time Steps: {steps} (daily for {time_horizon} year)")

        # This would call the MCP tool in real implementation
        # For demo, we'll simulate the expected output structure
        dt = time_horizon / steps
        t = np.linspace(0, time_horizon, steps)

        # Simulate GBM path
        np.random.seed(42)
        Z = np.random.standard_normal(steps)
        W = np.cumsum(Z) * np.sqrt(dt)

        prices = initial_price * np.exp((mu - 0.5 * sigma**2) * t + sigma * W)

        path = [{"time": time_val, "price": price_val} for time_val, price_val in zip(t, prices)]

        self.results["gbm"] = {
            "path": path,
            "final_price": prices[-1],
            "max_price": np.max(prices),
            "min_price": np.min(prices),
            "returns": np.diff(np.log(prices)),
        }

        print("\nResults:")
        print(f"  Final Price: ${prices[-1]:.2f}")
        print(f"  Max Price: ${np.max(prices):.2f}")
        print(f"  Min Price: ${np.min(prices):.2f}")
        print(f"  Return: {((prices[-1]/initial_price - 1)*100):.2f}%")

        return path

    def generate_heston_model(
        self,
        initial_price=100,
        initial_var=0.04,
        kappa=2,
        theta=0.04,
        xi=0.1,
        rho=-0.7,
        mu=0.05,
        steps=252,
        time_horizon=1,
    ):
        """Generate Heston stochastic volatility model"""
        print(f"\n{'='*60}")
        print("Generating Heston Stochastic Volatility Model")
        print(f"{'='*60}")
        print(f"Initial Price: ${initial_price}")
        print(f"Initial Variance: {initial_var}")
        print(f"Mean Reversion Speed (κ): {kappa}")
        print(f"Long-term Variance (θ): {theta}")
        print(f"Vol of Vol (ξ): {xi}")
        print(f"Correlation (ρ): {rho}")

        # Simulate Heston model
        dt = time_horizon / steps
        t = np.linspace(0, time_horizon, steps)

        np.random.seed(43)
        prices = np.zeros(steps)
        variances = np.zeros(steps)
        prices[0] = initial_price
        variances[0] = initial_var

        for i in range(1, steps):
            dW1 = np.random.normal(0, np.sqrt(dt))
            dW2 = rho * dW1 + np.sqrt(1 - rho**2) * np.random.normal(0, np.sqrt(dt))

            variances[i] = (
                variances[i - 1]
                + kappa * (theta - variances[i - 1]) * dt
                + xi * np.sqrt(max(variances[i - 1], 0)) * dW2
            )
            variances[i] = max(variances[i], 0)

            prices[i] = prices[i - 1] * np.exp(
                (mu - 0.5 * variances[i - 1]) * dt
                + np.sqrt(max(variances[i - 1], 0)) * dW1
            )

        path = [
            {"time": time_val, "price": price_val, "variance": var_val}
            for time_val, price_val, var_val in zip(t, prices, variances)
        ]

        self.results["heston"] = {
            "path": path,
            "final_price": prices[-1],
            "avg_variance": np.mean(variances),
            "implied_vol": np.sqrt(np.mean(variances)),
        }

        print("\nResults:")
        print(f"  Final Price: ${prices[-1]:.2f}")
        print(f"  Average Variance: {np.mean(variances):.4f}")
        print(f"  Implied Volatility: {np.sqrt(np.mean(variances))*100:.2f}%")

        return path

    def generate_ou_process(
        self,
        initial_value=0.05,
        kappa=2,
        theta=0.04,
        sigma=0.02,
        steps=252,
        time_horizon=1,
    ):
        """Generate Ornstein-Uhlenbeck mean-reverting process (e.g., for interest rates)"""
        print(f"\n{'='*60}")
        print("Generating Ornstein-Uhlenbeck Process")
        print(f"{'='*60}")
        print(f"Initial Value: {initial_value*100:.2f}%")
        print(f"Mean Reversion Speed (κ): {kappa}")
        print(f"Long-term Mean (θ): {theta*100:.2f}%")
        print(f"Volatility (σ): {sigma*100:.2f}%")

        dt = time_horizon / steps
        t = np.linspace(0, time_horizon, steps)

        np.random.seed(44)
        values = np.zeros(steps)
        values[0] = initial_value

        for i in range(1, steps):
            dW = np.random.normal(0, np.sqrt(dt))
            values[i] = (
                values[i - 1] + kappa * (theta - values[i - 1]) * dt + sigma * dW
            )

        path = [{"time": time_val, "rate": rate_val} for time_val, rate_val in zip(t, values)]

        self.results["ou"] = {
            "path": path,
            "final_value": values[-1],
            "mean": np.mean(values),
            "std": np.std(values),
        }

        print("\nResults:")
        print(f"  Final Rate: {values[-1]*100:.2f}%")
        print(f"  Mean Rate: {np.mean(values)*100:.2f}%")
        print(f"  Std Dev: {np.std(values)*100:.2f}%")

        return path

    def generate_multi_asset_gbm(
        self, n_assets=3, correlation=0.5, steps=252, time_horizon=1
    ):
        """Generate multiple correlated GBM paths"""
        print(f"\n{'='*60}")
        print("Generating Multi-Asset Correlated GBM")
        print(f"{'='*60}")
        print(f"Number of Assets: {n_assets}")
        print(f"Pairwise Correlation: {correlation}")

        # Create correlation matrix
        corr_matrix = np.full((n_assets, n_assets), correlation)
        np.fill_diagonal(corr_matrix, 1.0)

        dt = time_horizon / steps
        t = np.linspace(0, time_horizon, steps)

        # Asset parameters
        initial_prices = [100, 150, 80][:n_assets]
        mus = [0.05, 0.07, 0.04][:n_assets]
        sigmas = [0.20, 0.25, 0.15][:n_assets]

        # Generate correlated random numbers
        np.random.seed(45)
        L = np.linalg.cholesky(corr_matrix)
        Z = np.random.standard_normal((steps, n_assets))
        corr_random = Z @ L.T

        # Generate paths
        prices = np.zeros((steps, n_assets))
        for j in range(n_assets):
            prices[0, j] = initial_prices[j]
            W = np.cumsum(corr_random[:, j]) * np.sqrt(dt)
            prices[:, j] = initial_prices[j] * np.exp(
                (mus[j] - 0.5 * sigmas[j] ** 2) * t + sigmas[j] * W
            )

        paths = []
        for i in range(steps):
            point = {"time": t[i]}
            for j in range(n_assets):
                point[f"asset_{j+1}"] = prices[i, j]
            paths.append(point)

        # Calculate portfolio metrics (equal weights)
        portfolio_values = np.mean(prices, axis=1)
        portfolio_returns = np.diff(np.log(portfolio_values))

        self.results["multi_gbm"] = {
            "paths": paths,
            "final_prices": prices[-1, :].tolist(),
            "portfolio_value": portfolio_values[-1],
            "portfolio_return": (portfolio_values[-1] / portfolio_values[0] - 1),
            "portfolio_volatility": np.std(portfolio_returns) * np.sqrt(252),
        }

        print("\nResults:")
        for j in range(n_assets):
            print(f"  Asset {j+1} Final Price: ${prices[-1, j]:.2f}")
        print(f"  Portfolio Value (equal weights): ${portfolio_values[-1]:.2f}")
        print(
            f"  Portfolio Return: {(portfolio_values[-1]/portfolio_values[0] - 1)*100:.2f}%"
        )
        print(
            f"  Portfolio Volatility: {np.std(portfolio_returns) * np.sqrt(252)*100:.2f}%"
        )

        return paths

    def calculate_risk_metrics(self, path_data, confidence_level=0.05):
        """Calculate comprehensive risk metrics"""
        print(f"\n{'='*60}")
        print("Risk Metrics Analysis")
        print(f"{'='*60}")

        # Extract prices from path
        if isinstance(path_data, list) and "price" in path_data[0]:
            prices = [p["price"] for p in path_data]
        else:
            return None

        returns = np.diff(np.log(prices))

        # Calculate metrics
        var_percentile = confidence_level * 100
        var = np.percentile(returns, var_percentile)
        cvar = np.mean(returns[returns <= var])

        sharpe = (np.mean(returns) * 252) / (np.std(returns) * np.sqrt(252))
        max_drawdown = self._calculate_max_drawdown(prices)

        metrics = {
            "annualized_return": np.mean(returns) * 252,
            "annualized_volatility": np.std(returns) * np.sqrt(252),
            "sharpe_ratio": sharpe,
            "var_95": var,
            "cvar_95": cvar,
            "max_drawdown": max_drawdown,
            "skewness": self._calculate_skewness(returns),
            "kurtosis": self._calculate_kurtosis(returns),
        }

        print(f"  Annualized Return: {metrics['annualized_return']*100:.2f}%")
        print(f"  Annualized Volatility: {metrics['annualized_volatility']*100:.2f}%")
        print(f"  Sharpe Ratio: {metrics['sharpe_ratio']:.3f}")
        print(f"  VaR (95%): {metrics['var_95']*100:.2f}%")
        print(f"  CVaR (95%): {metrics['cvar_95']*100:.2f}%")
        print(f"  Max Drawdown: {metrics['max_drawdown']*100:.2f}%")
        print(f"  Skewness: {metrics['skewness']:.3f}")
        print(f"  Kurtosis: {metrics['kurtosis']:.3f}")

        return metrics

    def _calculate_max_drawdown(self, prices):
        """Calculate maximum drawdown"""
        cummax = np.maximum.accumulate(prices)
        drawdown = (prices - cummax) / cummax
        return np.min(drawdown)

    def _calculate_skewness(self, returns):
        """Calculate skewness of returns"""
        mean = np.mean(returns)
        std = np.std(returns)
        return np.mean(((returns - mean) / std) ** 3)

    def _calculate_kurtosis(self, returns):
        """Calculate excess kurtosis of returns"""
        mean = np.mean(returns)
        std = np.std(returns)
        return np.mean(((returns - mean) / std) ** 4) - 3

    def visualize_paths(self):
        """Create visualizations of all generated paths"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle(
            "Financial Stochastic Process Simulations", fontsize=16, fontweight="bold"
        )

        # GBM Plot
        if "gbm" in self.results:
            ax = axes[0, 0]
            path = self.results["gbm"]["path"]
            times = [p["time"] for p in path]
            prices = [p["price"] for p in path]
            ax.plot(times, prices, "b-", linewidth=2, label="GBM Path")
            ax.axhline(
                y=100, color="r", linestyle="--", alpha=0.3, label="Initial Price"
            )
            ax.set_title("Geometric Brownian Motion")
            ax.set_xlabel("Time (years)")
            ax.set_ylabel("Price ($)")
            ax.grid(True, alpha=0.3)
            ax.legend()

        # Heston Model Plot
        if "heston" in self.results:
            ax = axes[0, 1]
            path = self.results["heston"]["path"]
            times = [p["time"] for p in path]
            prices = [p["price"] for p in path]
            ax.plot(times, prices, "g-", linewidth=2, label="Heston Path")
            ax.axhline(
                y=100, color="r", linestyle="--", alpha=0.3, label="Initial Price"
            )
            ax.set_title("Heston Stochastic Volatility Model")
            ax.set_xlabel("Time (years)")
            ax.set_ylabel("Price ($)")
            ax.grid(True, alpha=0.3)
            ax.legend()

        # OU Process Plot
        if "ou" in self.results:
            ax = axes[1, 0]
            path = self.results["ou"]["path"]
            times = [p["time"] for p in path]
            rates = [p["rate"] * 100 for p in path]
            ax.plot(times, rates, "r-", linewidth=2, label="OU Process")
            ax.axhline(
                y=4, color="b", linestyle="--", alpha=0.3, label="Long-term Mean"
            )
            ax.set_title("Ornstein-Uhlenbeck Process (Interest Rates)")
            ax.set_xlabel("Time (years)")
            ax.set_ylabel("Rate (%)")
            ax.grid(True, alpha=0.3)
            ax.legend()

        # Multi-Asset GBM Plot
        if "multi_gbm" in self.results:
            ax = axes[1, 1]
            paths = self.results["multi_gbm"]["paths"]
            times = [p["time"] for p in paths]

            # Plot each asset
            n_assets = len([k for k in paths[0].keys() if k.startswith("asset_")])
            colors = ["b", "g", "r", "c", "m", "y"]
            for j in range(n_assets):
                prices = [p[f"asset_{j+1}"] for p in paths]
                ax.plot(
                    times,
                    prices,
                    colors[j % len(colors)],
                    linewidth=1.5,
                    alpha=0.7,
                    label=f"Asset {j+1}",
                )

            ax.set_title("Multi-Asset Correlated GBM")
            ax.set_xlabel("Time (years)")
            ax.set_ylabel("Price ($)")
            ax.grid(True, alpha=0.3)
            ax.legend()

        plt.tight_layout()
        plt.savefig(
            "C:/Users/Corbin/development/financial_stochastic_models.png",
            dpi=150,
            bbox_inches="tight",
        )
        print(f"\n{'='*60}")
        print("Visualization saved as 'financial_stochastic_models.png'")
        print(f"{'='*60}")
        plt.show()

    def save_results(
        self, filename="C:/Users/Corbin/development/financial_results.json"
    ):
        """Save all results to JSON file"""
        # Convert numpy arrays to lists for JSON serialization
        json_results = {}
        for key, value in self.results.items():
            if isinstance(value, dict):
                json_results[key] = {}
                for k, v in value.items():
                    if isinstance(v, np.ndarray):
                        json_results[key][k] = v.tolist()
                    elif isinstance(v, (np.float32, np.float64)):
                        json_results[key][k] = float(v)
                    else:
                        json_results[key][k] = v
            else:
                json_results[key] = value

        with open(filename, "w") as f:
            json.dump(json_results, f, indent=2)

        print(f"\nResults saved to '{filename}'")


def main():
    print("=" * 60)
    print("FINANCIAL STOCHASTIC MODELING DEMONSTRATION")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Initialize modeler
    modeler = FinancialStochasticModeler()

    # 1. Generate Geometric Brownian Motion
    gbm_path = modeler.generate_gbm(
        initial_price=100,
        mu=0.08,  # 8% annual drift
        sigma=0.25,  # 25% annual volatility
        steps=252,  # Daily steps for one year
        time_horizon=1,
    )

    # 2. Generate Heston Model
    heston_path = modeler.generate_heston_model(
        initial_price=100,
        initial_var=0.04,
        kappa=2,
        theta=0.04,
        xi=0.1,
        rho=-0.7,
        mu=0.05,
        steps=252,
        time_horizon=1,
    )

    # 3. Generate Ornstein-Uhlenbeck Process (for interest rates)
    ou_path = modeler.generate_ou_process(
        initial_value=0.05,  # 5% initial rate
        kappa=2,
        theta=0.04,  # 4% long-term mean
        sigma=0.02,
        steps=252,
        time_horizon=1,
    )

    # 4. Generate Multi-Asset Correlated GBM
    multi_path = modeler.generate_multi_asset_gbm(
        n_assets=3, correlation=0.6, steps=252, time_horizon=1
    )

    # 5. Calculate Risk Metrics for GBM
    if gbm_path:
        modeler.calculate_risk_metrics(gbm_path, confidence_level=0.05)

    # 6. Visualize all paths
    modeler.visualize_paths()

    # 7. Save results
    modeler.save_results()

    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)
    print("\nGenerated Files:")
    print("  - financial_stochastic_models.png (visualization)")
    print("  - financial_results.json (numerical results)")
    print("\nKey Insights:")
    print("  • GBM: Standard model for stock prices with constant volatility")
    print("  • Heston: Captures volatility clustering and leverage effect")
    print("  • OU Process: Mean-reverting, suitable for interest rates")
    print("  • Multi-Asset: Portfolio diversification with correlations")


if __name__ == "__main__":
    main()
