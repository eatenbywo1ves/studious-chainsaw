"""
Von Neumann Weather Modeling with Claude Code
Demonstrating how von Neumann would approach computational meteorology

Based on his 1950 pioneering work with ENIAC solving the barotropic vorticity equation
"""

import numpy as np
from typing import Dict, Any
import time
from dataclasses import dataclass


@dataclass
class WeatherGrid:
    """Represents atmospheric data on a grid - von Neumann's discretization approach"""

    latitude: np.ndarray
    longitude: np.ndarray
    pressure: np.ndarray  # 500mb level (von Neumann's choice)
    vorticity: np.ndarray  # Key variable in barotropic model
    streamfunction: np.ndarray
    time_step: float
    grid_spacing: float


class VonNeumannWeatherModel:
    """
    Weather model following von Neumann's 1950 approach

    Implements the barotropic vorticity equation:
    ∂ζ/∂t + J(ψ, ζ + f) = 0

    Where:
    - ζ is relative vorticity
    - ψ is streamfunction
    - f is Coriolis parameter
    - J is Jacobian operator
    """

    def __init__(self, grid_size: int = 32, domain_size: float = 5000.0):
        """Initialize following von Neumann's computational principles"""

        self.grid_size = grid_size
        self.domain_size = domain_size  # km
        self.dx = domain_size / grid_size
        self.dy = domain_size / grid_size

        # Time step - von Neumann emphasized numerical stability
        self.dt = 300.0  # 5 minutes (stable for this resolution)

        # Physical parameters
        self.earth_rotation = 7.27e-5  # rad/s
        self.latitude_center = 45.0  # degrees

        # Von Neumann's emphasis on mathematical rigor
        self.coriolis_param = (
            2 * self.earth_rotation * np.sin(np.radians(self.latitude_center))
        )

        # Initialize grid
        self.grid = self._initialize_grid()

        print("🌍 Von Neumann Weather Model Initialized")
        print(f"   Grid: {grid_size}x{grid_size}")
        print(f"   Domain: {domain_size} km")
        print(f"   Time Step: {self.dt / 60:.1f} minutes")
        print(f"   Coriolis: {self.coriolis_param:.2e} rad/s")

    def _initialize_grid(self) -> WeatherGrid:
        """Initialize atmospheric grid with realistic values"""

        # Create coordinate arrays
        x = np.linspace(-self.domain_size / 2, self.domain_size / 2, self.grid_size)
        y = np.linspace(-self.domain_size / 2, self.domain_size / 2, self.grid_size)
        X, Y = np.meshgrid(x, y)

        # Initialize with a simple vortex (like von Neumann's test case)
        center_x, center_y = 0.0, 0.0
        radius = self.domain_size / 6

        r = np.sqrt((X - center_x) ** 2 + (Y - center_y) ** 2)

        # Gaussian vorticity distribution
        vorticity = 1e-4 * np.exp(-((r / radius) ** 2))

        # Solve for streamfunction using Poisson equation: ∇²ψ = ζ
        streamfunction = self._solve_poisson(vorticity)

        # Pressure field (simplified)
        pressure = 50000 + 1000 * streamfunction  # 500mb level

        return WeatherGrid(
            latitude=Y,
            longitude=X,
            pressure=pressure,
            vorticity=vorticity,
            streamfunction=streamfunction,
            time_step=self.dt,
            grid_spacing=self.dx,
        )

    def _solve_poisson(self, source: np.ndarray) -> np.ndarray:
        """
        Solve Poisson equation ∇²ψ = ζ
        Von Neumann would use finite differences on ENIAC
        """

        # Simple finite difference Poisson solver
        # In practice, von Neumann used more sophisticated methods

        psi = np.zeros_like(source)

        # Iterative solver (Gauss-Seidel - von Neumann era method)
        for iteration in range(1000):
            psi_old = psi.copy()

            # Interior points
            psi[1:-1, 1:-1] = 0.25 * (
                psi[2:, 1:-1]
                + psi[:-2, 1:-1]
                + psi[1:-1, 2:]
                + psi[1:-1, :-2]
                - self.dx**2 * source[1:-1, 1:-1]
            )

            # Convergence check
            if np.max(np.abs(psi - psi_old)) < 1e-6:
                break

        return psi

    def _compute_jacobian(self, psi: np.ndarray, zeta: np.ndarray) -> np.ndarray:
        """
        Compute Jacobian J(ψ, ζ) = ∂ψ/∂x * ∂ζ/∂y - ∂ψ/∂y * ∂ζ/∂x
        This is the nonlinear advection term von Neumann had to handle
        """

        # Finite difference derivatives
        dpsi_dx = np.zeros_like(psi)
        dpsi_dy = np.zeros_like(psi)
        dzeta_dx = np.zeros_like(zeta)
        dzeta_dy = np.zeros_like(zeta)

        # Central differences (interior points)
        dpsi_dx[1:-1, 1:-1] = (psi[1:-1, 2:] - psi[1:-1, :-2]) / (2 * self.dx)
        dpsi_dy[1:-1, 1:-1] = (psi[2:, 1:-1] - psi[:-2, 1:-1]) / (2 * self.dy)

        dzeta_dx[1:-1, 1:-1] = (zeta[1:-1, 2:] - zeta[1:-1, :-2]) / (2 * self.dx)
        dzeta_dy[1:-1, 1:-1] = (zeta[2:, 1:-1] - zeta[:-2, 1:-1]) / (2 * self.dy)

        # Jacobian
        jacobian = dpsi_dx * dzeta_dy - dpsi_dy * dzeta_dx

        return jacobian

    def time_step_forward(self) -> Dict[str, Any]:
        """
        Advance one time step using von Neumann's barotropic vorticity equation

        ∂ζ/∂t + J(ψ, ζ + f) = 0
        """

        start_time = time.time()

        # Current state
        zeta = self.grid.vorticity.copy()
        psi = self.grid.streamfunction.copy()

        # Add planetary vorticity (Coriolis)
        absolute_vorticity = zeta + self.coriolis_param

        # Compute Jacobian (advection term)
        jacobian = self._compute_jacobian(psi, absolute_vorticity)

        # Time derivative: ∂ζ/∂t = -J(ψ, ζ + f)
        dzeta_dt = -jacobian

        # Forward time step (Euler method - von Neumann used this)
        zeta_new = zeta + self.dt * dzeta_dt

        # Solve for new streamfunction
        psi_new = self._solve_poisson(zeta_new)

        # Update pressure (diagnostic)
        pressure_new = 50000 + 1000 * psi_new

        # Update grid
        self.grid.vorticity = zeta_new
        self.grid.streamfunction = psi_new
        self.grid.pressure = pressure_new

        computation_time = time.time() - start_time

        return {
            "computation_time": computation_time,
            "max_vorticity": np.max(np.abs(zeta_new)),
            "energy": np.sum(psi_new**2) * self.dx * self.dy,  # Kinetic energy proxy
            "von_neumann_insight": "Numerical integration advances atmospheric state forward in time",
        }

    def forecast(self, hours: int = 24) -> Dict[str, Any]:
        """
        Generate weather forecast - von Neumann's 24-hour goal
        """

        print(f"\n🌩️ Starting {hours}-hour weather forecast...")
        print("   Following von Neumann's 1950 ENIAC approach")

        start_time = time.time()

        # Number of time steps
        total_seconds = hours * 3600
        num_steps = int(total_seconds / self.dt)

        # Storage for analysis
        vorticity_evolution = []
        energy_evolution = []
        max_vorticity_evolution = []

        # Time integration loop (like ENIAC's 24-hour calculation)
        for step in range(num_steps):
            step_result = self.time_step_forward()

            # Record evolution every hour
            if step % (3600 // int(self.dt)) == 0:
                vorticity_evolution.append(self.grid.vorticity.copy())
                energy_evolution.append(step_result["energy"])
                max_vorticity_evolution.append(step_result["max_vorticity"])

                current_hour = step * self.dt / 3600
                print(
                    f"   Hour {current_hour:2.0f}: Max vorticity = {step_result['max_vorticity']:.2e}"
                )

        total_time = time.time() - start_time

        # Von Neumann's comparison: ENIAC took 24 hours for 24-hour forecast
        eniac_speedup = (24 * 3600) / total_time if total_time > 0 else float("inf")

        forecast_result = {
            "forecast_hours": hours,
            "computation_time": total_time,
            "eniac_comparison": f"{eniac_speedup:.0f}x faster than ENIAC",
            "final_state": {
                "vorticity": self.grid.vorticity,
                "streamfunction": self.grid.streamfunction,
                "pressure": self.grid.pressure,
            },
            "evolution": {
                "vorticity_snapshots": vorticity_evolution,
                "energy_evolution": energy_evolution,
                "max_vorticity_evolution": max_vorticity_evolution,
            },
            "von_neumann_achievement": "Successfully computed atmospheric evolution using numerical methods",
        }

        print("\n✅ Forecast Complete!")
        print(f"   Computation Time: {total_time:.2f} seconds")
        print(f"   ENIAC Comparison: {eniac_speedup:.0f}x faster than 1950 ENIAC")
        print(f"   Final Max Vorticity: {max_vorticity_evolution[-1]:.2e}")

        return forecast_result

    def analyze_forecast_quality(self, forecast_result: Dict) -> Dict[str, Any]:
        """
        Analyze forecast quality using von Neumann's mathematical rigor
        """

        print("\n📊 Von Neumann Forecast Analysis")
        print("-" * 40)

        evolution = forecast_result["evolution"]

        # Energy conservation check (fundamental physics)
        energy_change = (
            evolution["energy_evolution"][-1] - evolution["energy_evolution"][0]
        ) / evolution["energy_evolution"][0]
        energy_conserved = abs(energy_change) < 0.1  # 10% threshold

        # Numerical stability check
        vorticity_growth = (
            evolution["max_vorticity_evolution"][-1]
            / evolution["max_vorticity_evolution"][0]
        )
        numerically_stable = vorticity_growth < 10  # Reasonable growth

        # Forecast skill metrics
        skill_metrics = {
            "energy_conservation": {
                "change_percent": energy_change * 100,
                "conserved": energy_conserved,
                "quality": "Good" if energy_conserved else "Poor",
            },
            "numerical_stability": {
                "growth_factor": vorticity_growth,
                "stable": numerically_stable,
                "quality": "Stable" if numerically_stable else "Unstable",
            },
            "overall_quality": (
                "Excellent"
                if energy_conserved and numerically_stable
                else "Needs improvement"
            ),
        }

        print(f"Energy Conservation: {skill_metrics['energy_conservation']['quality']}")
        print(f"  Change: {energy_change * 100:.1f}%")
        print(f"Numerical Stability: {skill_metrics['numerical_stability']['quality']}")
        print(f"  Growth Factor: {vorticity_growth:.2f}")
        print(f"Overall Quality: {skill_metrics['overall_quality']}")

        return {
            "skill_metrics": skill_metrics,
            "von_neumann_principle": "Mathematical rigor ensures forecast reliability",
            "eniac_legacy": "Building on von Neumann's 1950 breakthrough",
        }


def demonstrate_von_neumann_weather_modeling():
    """Demonstrate von Neumann's approach to computational weather prediction"""

    print("🌍 VON NEUMANN WEATHER MODELING WITH CLAUDE CODE")
    print("=" * 60)
    print("Recreating the 1950 ENIAC weather forecast breakthrough")
    print("Based on the barotropic vorticity equation")

    # Initialize model
    model = VonNeumannWeatherModel(grid_size=32, domain_size=3000.0)

    # Run forecast
    forecast = model.forecast(hours=24)

    # Analyze results
    analysis = model.analyze_forecast_quality(forecast)

    print("\n" + "=" * 60)
    print("🎯 VON NEUMANN'S WEATHER MODELING LEGACY")
    print("=" * 60)
    print()
    print("Historical Achievement (1950):")
    print("• First computer weather forecast using ENIAC")
    print("• 24 hours computation for 24-hour forecast")
    print("• Solved barotropic vorticity equation numerically")
    print("• Founded modern computational meteorology")
    print()
    print("Modern Claude Code Implementation:")
    print(f"• {forecast['eniac_comparison']} performance improvement")
    print(
        f"• Mathematical rigor maintained: {analysis['skill_metrics']['overall_quality']}"
    )
    print("• Same fundamental equations von Neumann pioneered")
    print("• Demonstrates universality of computational approach")
    print()
    print("Von Neumann's Vision Realized:")
    print("• Weather as computational problem")
    print("• Mathematical modeling of complex systems")
    print("• Numerical methods for differential equations")
    print("• Foundation for modern climate science")

    return {
        "model": model,
        "forecast": forecast,
        "analysis": analysis,
        "von_neumann_legacy": "Computational meteorology pioneer",
    }


if __name__ == "__main__":
    results = demonstrate_von_neumann_weather_modeling()

    print("\n🧠 Von Neumann's words: 'The influence of the mathematical")
    print("   theory of weather on the actual art of weather prediction")
    print("   promises to be considerable.'")
    print("\n✨ Claude Code continues that computational legacy!")
