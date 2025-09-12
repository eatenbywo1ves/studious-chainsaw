import asyncio
from typing import Dict, List, Any, Optional

class MCPFinancialClient:
    """Client for interacting with MCP financial stochastic tools"""
    
    def __init__(self):
        self.tools = {}
    
    async def generate_gbm(self, initial_price: float = 100, mu: float = 0.05, 
                          sigma: float = 0.2, steps: int = 1000, 
                          time_horizon: float = 1.0) -> List[Dict[str, float]]:
        """Generate Geometric Brownian Motion path"""
        try:
            # This would normally call the MCP tool
            # For now, using numpy simulation as fallback
            import numpy as np
            
            np.random.seed(None)
            dt = time_horizon / steps
            returns = np.random.normal(
                (mu - 0.5 * sigma**2) * dt,
                sigma * np.sqrt(dt),
                steps
            )
            
            prices = [initial_price]
            for ret in returns:
                prices.append(prices[-1] * np.exp(ret))
            
            time_points = np.linspace(0, time_horizon, len(prices))
            return [{"time": float(t), "price": float(p)} for t, p in zip(time_points, prices)]
            
        except Exception as e:
            raise Exception(f"Error generating GBM: {str(e)}")
    
    async def generate_ou_process(self, initial_value: float = 100, theta: float = 0.04,
                                 kappa: float = 2.0, sigma: float = 0.2, 
                                 steps: int = 1000, time_horizon: float = 1.0) -> List[Dict[str, float]]:
        """Generate Ornstein-Uhlenbeck process"""
        try:
            import numpy as np
            
            np.random.seed(None)
            dt = time_horizon / steps
            values = [initial_value]
            
            for _ in range(steps):
                dw = np.random.normal(0, np.sqrt(dt))
                dv = kappa * (theta - values[-1]) * dt + sigma * dw
                values.append(values[-1] + dv)
            
            time_points = np.linspace(0, time_horizon, len(values))
            return [{"time": float(t), "value": float(v)} for t, v in zip(time_points, values)]
            
        except Exception as e:
            raise Exception(f"Error generating OU process: {str(e)}")
    
    async def generate_heston_model(self, initial_price: float = 100, initial_var: float = 0.04,
                                   mu: float = 0.05, kappa: float = 2.0, theta: float = 0.04,
                                   xi: float = 0.1, rho: float = -0.7, steps: int = 1000,
                                   time_horizon: float = 1.0) -> Dict[str, List[Dict[str, float]]]:
        """Generate Heston model paths for both price and variance"""
        try:
            import numpy as np
            
            np.random.seed(None)
            dt = time_horizon / steps
            
            prices = [initial_price]
            variances = [initial_var]
            
            for _ in range(steps):
                # Correlated random variables
                z1 = np.random.normal(0, 1)
                z2 = rho * z1 + np.sqrt(1 - rho**2) * np.random.normal(0, 1)
                
                # Variance process (CIR)
                dv = kappa * (theta - max(variances[-1], 0)) * dt + xi * np.sqrt(max(variances[-1], 0)) * np.sqrt(dt) * z2
                new_var = max(variances[-1] + dv, 1e-6)  # Ensure positive
                variances.append(new_var)
                
                # Price process
                dp = prices[-1] * (mu * dt + np.sqrt(variances[-2]) * np.sqrt(dt) * z1)
                prices.append(prices[-1] + dp)
            
            time_points = np.linspace(0, time_horizon, len(prices))
            
            return {
                "prices": [{"time": float(t), "price": float(p)} for t, p in zip(time_points, prices)],
                "variances": [{"time": float(t), "variance": float(v)} for t, v in zip(time_points, variances)]
            }
            
        except Exception as e:
            raise Exception(f"Error generating Heston model: {str(e)}")
    
    async def calculate_risk_metrics(self, path: List[Dict[str, float]], confidence_level: float = 0.05) -> Dict[str, float]:
        """Calculate risk metrics from a price path"""
        try:
            import numpy as np
            
            prices = [p.get("price", p.get("value", 0)) for p in path]
            returns = [(prices[i]/prices[i-1] - 1) for i in range(1, len(prices))]
            
            # Basic risk metrics
            mean_return = np.mean(returns)
            volatility = np.std(returns)
            var_95 = np.percentile(returns, confidence_level * 100)
            cvar_95 = np.mean([r for r in returns if r <= var_95])
            max_drawdown = self._calculate_max_drawdown(prices)
            sharpe_ratio = mean_return / volatility if volatility > 0 else 0
            
            return {
                "mean_return": float(mean_return),
                "volatility": float(volatility),
                "var_95": float(var_95),
                "cvar_95": float(cvar_95),
                "max_drawdown": float(max_drawdown),
                "sharpe_ratio": float(sharpe_ratio),
                "final_price": float(prices[-1]),
                "total_return": float((prices[-1] / prices[0]) - 1)
            }
            
        except Exception as e:
            raise Exception(f"Error calculating risk metrics: {str(e)}")
    
    def _calculate_max_drawdown(self, prices: List[float]) -> float:
        """Calculate maximum drawdown"""
        peak = prices[0]
        max_dd = 0
        
        for price in prices:
            if price > peak:
                peak = price
            drawdown = (peak - price) / peak
            if drawdown > max_dd:
                max_dd = drawdown
                
        return max_dd