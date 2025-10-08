#!/usr/bin/env python3
"""
PyTorch-based Catalytic Lattice GPU Test
Testing GPU acceleration with our newly installed PyTorch CUDA support
Pirate mode: ENGAGED! Arrr!
"""

import torch
import numpy as np
import time
from typing import Tuple


class CatalyticLatticeGPU:
    """GPU-accelerated catalytic lattice using PyTorch"""

    def __init__(self, dimensions: int, size: int, device: str = 'cuda'):
        """
        Initialize the lattice on the GPU

        Args:
            dimensions: Number of dimensions (2 or 3)
            size: Size of each dimension
            device: 'cuda' for GPU or 'cpu' for comparison
        """
        self.dimensions = dimensions
        self.size = size
        self.device = torch.device(device if torch.cuda.is_available() else 'cpu')

        print(f"[ANCHOR] Ahoy! Initializing {dimensions}D lattice of size {size} on {self.device}")

        # Initialize lattice state on GPU
        shape = [size] * dimensions
        self.lattice = torch.rand(*shape, device=self.device)
        self.energy = torch.zeros(*shape, device=self.device)

        # Catalytic parameters
        self.diffusion_rate = 0.1
        self.reaction_rate = 0.05
        self.catalytic_strength = 0.8

        print(f"[PIRATE FLAG] Lattice initialized! Memory allocated: {self.get_memory_usage():.2f} MB")

    def get_memory_usage(self) -> float:
        """Get GPU memory usage in MB"""
        if self.device.type == 'cuda':
            return torch.cuda.memory_allocated() / (1024 * 1024)
        return 0

    def compute_laplacian(self, field: torch.Tensor) -> torch.Tensor:
        """Compute Laplacian using convolution (arrr, smooth sailing!)"""
        if self.dimensions == 2:
            # 2D Laplacian kernel
            kernel = torch.tensor([
                [0, 1, 0],
                [1, -4, 1],
                [0, 1, 0]
            ], device=self.device, dtype=field.dtype).unsqueeze(0).unsqueeze(0)

            field_4d = field.unsqueeze(0).unsqueeze(0)
            laplacian = torch.nn.functional.conv2d(field_4d, kernel, padding=1)
            return laplacian.squeeze()

        elif self.dimensions == 3:
            # 3D Laplacian - more treasure dimensions!
            kernel = torch.zeros(3, 3, 3, device=self.device)
            kernel[1, 1, 0] = kernel[1, 1, 2] = 1
            kernel[1, 0, 1] = kernel[1, 2, 1] = 1
            kernel[0, 1, 1] = kernel[2, 1, 1] = 1
            kernel[1, 1, 1] = -6

            kernel = kernel.unsqueeze(0).unsqueeze(0)
            field_5d = field.unsqueeze(0).unsqueeze(0)
            laplacian = torch.nn.functional.conv3d(field_5d, kernel, padding=1)
            return laplacian.squeeze()

    def evolve_step(self) -> None:
        """Single evolution step of the catalytic reaction-diffusion system"""
        # Diffusion term (Laplacian)
        laplacian = self.compute_laplacian(self.lattice)

        # Reaction term (nonlinear dynamics, arrr!)
        reaction = self.reaction_rate * self.lattice * (1 - self.lattice) * (self.lattice - 0.3)

        # Catalytic enhancement at active sites
        catalyst_mask = (self.energy > 0.5)
        reaction = torch.where(catalyst_mask, reaction * self.catalytic_strength, reaction)

        # Update lattice state
        self.lattice += self.diffusion_rate * laplacian + reaction
        self.lattice = torch.clamp(self.lattice, 0, 1)

        # Update energy field
        self.energy = 0.9 * self.energy + 0.1 * torch.abs(laplacian)

    def run_simulation(self, steps: int) -> Tuple[float, float]:
        """
        Run the simulation for multiple steps

        Returns:
            Tuple of (simulation_time, throughput_steps_per_second)
        """
        print(f"[SWORDS] Running {steps} evolution steps on the high seas of computation!")

        # Warmup the GPU (prime the cannons!)
        for _ in range(10):
            self.evolve_step()

        if self.device.type == 'cuda':
            torch.cuda.synchronize()

        start_time = time.perf_counter()

        for step in range(steps):
            self.evolve_step()
            if step % 100 == 0:
                print(f"  [SAIL] Step {step}/{steps} - Energy: {self.energy.mean().item():.4f}")

        if self.device.type == 'cuda':
            torch.cuda.synchronize()

        elapsed = time.perf_counter() - start_time
        throughput = steps / elapsed

        return elapsed, throughput

    def get_state_snapshot(self) -> np.ndarray:
        """Get current state as numpy array"""
        return self.lattice.cpu().numpy()


def benchmark_comparison():
    """Compare CPU vs GPU performance like comparing sailing ships!"""
    print("\n" + "="*60)
    print("[PIRATE] CATALYTIC LATTICE GPU BENCHMARK - FULL SAIL AHEAD!")
    print("="*60 + "\n")

    # Test configurations
    configs = [
        (2, 128, 100),   # 2D small
        (2, 256, 100),   # 2D medium
        (2, 512, 50),    # 2D large
        (3, 64, 50),     # 3D small
        (3, 128, 30),    # 3D medium
    ]

    results = []

    for dims, size, steps in configs:
        print(f"\n[MAP] Testing {dims}D lattice, size={size}, steps={steps}")
        print("-" * 40)

        # GPU test (if available)
        if torch.cuda.is_available():
            lattice_gpu = CatalyticLatticeGPU(dims, size, 'cuda')
            gpu_time, gpu_throughput = lattice_gpu.run_simulation(steps)
            gpu_memory = lattice_gpu.get_memory_usage()
            print(f"  [ROCKET] GPU Time: {gpu_time:.3f}s, Throughput: {gpu_throughput:.1f} steps/s")
            print(f"  [DISK] GPU Memory: {gpu_memory:.2f} MB")
        else:
            gpu_time = gpu_throughput = gpu_memory = None
            print("  [X] No GPU available, ye landlubber!")

        # CPU test
        lattice_cpu = CatalyticLatticeGPU(dims, size, 'cpu')
        cpu_time, cpu_throughput = lattice_cpu.run_simulation(steps)
        print(f"  [SNAIL] CPU Time: {cpu_time:.3f}s, Throughput: {cpu_throughput:.1f} steps/s")

        # Calculate speedup
        if gpu_time:
            speedup = cpu_time / gpu_time
            print(f"  [LIGHTNING] GPU Speedup: {speedup:.2f}x faster, arrr!")
            results.append({
                'config': f"{dims}D-{size}",
                'gpu_time': gpu_time,
                'cpu_time': cpu_time,
                'speedup': speedup,
                'gpu_memory': gpu_memory
            })

        # Clean up GPU memory
        if torch.cuda.is_available():
            del lattice_gpu
            torch.cuda.empty_cache()

    # Summary
    print("\n" + "="*60)
    print("[TROPHY] BENCHMARK SUMMARY - TREASURE FOUND!")
    print("="*60)

    if results:
        avg_speedup = np.mean([r['speedup'] for r in results])
        max_speedup = max(r['speedup'] for r in results)

        print(f"\n  [ANCHOR] Average GPU Speedup: {avg_speedup:.2f}x")
        print(f"  [TARGET] Maximum GPU Speedup: {max_speedup:.2f}x")
        print(f"  [PIRATE] GTX 1080 Total Memory: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.1f} GB")

        print("\n  Detailed Results:")
        for r in results:
            print(f"    {r['config']:10s} - Speedup: {r['speedup']:5.2f}x, "
                  f"GPU: {r['gpu_time']:6.3f}s, CPU: {r['cpu_time']:6.3f}s")


def main():
    """Main entry point for our GPU adventure!"""
    print("[PIRATE] Ahoy! Welcome to the GPU-Accelerated Catalytic Lattice Test!")
    print(f"   Using PyTorch {torch.__version__}")

    if torch.cuda.is_available():
        print(f"   GPU: {torch.cuda.get_device_name(0)}")
        print(f"   CUDA Version: {torch.version.cuda}")
        print(f"   Compute Capability: {torch.cuda.get_device_capability(0)}")
    else:
        print("   [WARNING] No GPU detected - running in CPU mode only")

    # Run the benchmark
    benchmark_comparison()

    print("\n[FINISH] All hands on deck! Benchmark complete! May the winds be at yer back!")


if __name__ == "__main__":
    main()
