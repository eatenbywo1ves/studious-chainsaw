"""
Von Neumann Weather Modeling - Simplified Demo
Demonstrates his 1950 ENIAC breakthrough in computational meteorology
"""

import numpy as np
import time

class VonNeumannWeatherModel:
    """Simplified version of von Neumann's 1950 barotropic model"""
    
    def __init__(self):
        self.grid_size = 16
        self.dx = 100.0  # km
        self.dt = 300.0  # 5 minutes
        self.coriolis = 1e-4  # Coriolis parameter
        
        # Initialize with simple vortex
        x = np.arange(self.grid_size)
        y = np.arange(self.grid_size) 
        X, Y = np.meshgrid(x, y)
        
        center = self.grid_size // 2
        r = np.sqrt((X - center)**2 + (Y - center)**2)
        
        # Gaussian vorticity
        self.vorticity = 1e-4 * np.exp(-(r/4)**2)
        
        print(f"Weather Model Initialized: {self.grid_size}x{self.grid_size} grid")
    
    def time_step(self):
        """Advance one time step - simplified barotropic equation"""
        
        # Simple advection (von Neumann's core challenge)
        vort_new = np.zeros_like(self.vorticity)
        
        # Interior points - simplified finite difference
        for i in range(1, self.grid_size-1):
            for j in range(1, self.grid_size-1):
                # Simplified vorticity equation
                dvdt = -0.1 * (self.vorticity[i+1,j] - self.vorticity[i-1,j]) / (2*self.dx)
                vort_new[i,j] = self.vorticity[i,j] + self.dt * dvdt
        
        self.vorticity = vort_new
        return np.max(np.abs(self.vorticity))
    
    def forecast(self, hours=24):
        """Run forecast like von Neumann's 24-hour ENIAC calculation"""
        
        print(f"\nStarting {hours}-hour forecast...")
        print("Following von Neumann's 1950 ENIAC approach")
        
        start_time = time.time()
        steps = int(hours * 3600 / self.dt)
        
        max_vorticity = []
        
        for step in range(steps):
            max_vort = self.time_step()
            
            if step % (steps // 4) == 0:  # Print 4 times during forecast
                hour = step * self.dt / 3600
                print(f"  Hour {hour:4.1f}: Max vorticity = {max_vort:.2e}")
                max_vorticity.append(max_vort)
        
        total_time = time.time() - start_time
        eniac_speedup = (24 * 3600) / total_time  # ENIAC took 24 hours
        
        return {
            'computation_time': total_time,
            'eniac_speedup': eniac_speedup,
            'final_max_vorticity': max_vorticity[-1] if max_vorticity else 0
        }

def main():
    print("VON NEUMANN WEATHER MODELING - 1950 ENIAC BREAKTHROUGH")
    print("=" * 60)
    
    # Historical context
    print("\nHistorical Achievement:")
    print("• 1950: First computer weather forecast")
    print("• ENIAC computer at Princeton") 
    print("• 24 hours computation for 24-hour forecast")
    print("• Barotropic vorticity equation")
    print("• Founded computational meteorology")
    
    # Run model
    model = VonNeumannWeatherModel()
    results = model.forecast(24)
    
    print(f"\nResults:")
    print(f"✓ Computation Time: {results['computation_time']:.2f} seconds")
    print(f"✓ ENIAC Speedup: {results['eniac_speedup']:.0f}x faster")
    print(f"✓ Final Vorticity: {results['final_max_vorticity']:.2e}")
    
    print(f"\n" + "=" * 60)
    print("VON NEUMANN'S WEATHER MODELING PRINCIPLES:")
    print("=" * 60)
    print("1. Mathematical Rigor: Differential equations → Finite differences")
    print("2. Computational Approach: Numerical integration of physics")  
    print("3. Grid Discretization: Continuous atmosphere → Discrete points")
    print("4. Time Stepping: Evolution through numerical iteration")
    print("5. Verification: Energy conservation and stability checks")
    
    print(f"\nLegacy Impact:")
    print("• Modern weather forecasting")
    print("• Climate modeling") 
    print("• Computational fluid dynamics")
    print("• Numerical methods in science")
    print("• Supercomputing applications")
    
    print(f"\nVon Neumann's Vision: 'Weather prediction is fundamentally")
    print(f"a computational problem that can be solved with sufficient")
    print(f"mathematical rigor and computing power.'")

if __name__ == "__main__":
    main()