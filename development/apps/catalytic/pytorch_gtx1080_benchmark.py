#!/usr/bin/env python3
"""
GTX 1080 GPU Benchmark - PyTorch Catalytic Lattice
Testing local NVIDIA GeForce GTX 1080 with 8GB memory
Pirate mode: ENGAGED! Running on yer local system!
"""

import torch
import numpy as np
import time
from typing import Tuple, Dict
import sys


class GPUBenchmark:
    """GTX 1080 GPU Benchmark Suite"""

    def __init__(self):
        """Initialize benchmark for GTX 1080"""
        if not torch.cuda.is_available():
            print("[ERROR] No CUDA GPU detected!")
            sys.exit(1)

        self.device = torch.device('cuda')
        self.gpu_properties = torch.cuda.get_device_properties(0)

        print("="*70)
        print("[PIRATE] GTX 1080 GPU BENCHMARK - LOCAL SYSTEM")
        print("="*70)
        print(f"[GPU] {self.gpu_properties.name}")
        print(f"[MEMORY] {self.gpu_properties.total_memory / (1024**3):.1f} GB total")
        print(f"[CUDA CORES] {self.gpu_properties.multi_processor_count * 128} (estimated)")
        print(f"[COMPUTE] {self.gpu_properties.major}.{self.gpu_properties.minor}")
        print(f"[PYTORCH] {torch.__version__}")
        print(f"[CUDA] {torch.version.cuda}")
        print("="*70 + "\n")

    def memory_stress_test(self) -> Dict:
        """Test maximum memory allocation"""
        print("[TEST 1] Memory Stress Test - Finding maximum allocation")
        print("-" * 50)

        results = {}
        test_sizes = [1, 2, 3, 4, 5, 6, 7]  # GB

        for size_gb in test_sizes:
            try:
                # Clear cache first
                torch.cuda.empty_cache()

                # Calculate tensor size for desired GB
                elements = int((size_gb * 1024**3) / 4)  # float32 = 4 bytes
                sqrt_elements = int(np.sqrt(elements))

                # Allocate tensor
                print(f"  Attempting {size_gb}GB allocation...", end=" ")
                tensor = torch.zeros(sqrt_elements, sqrt_elements, device=self.device)
                allocated = torch.cuda.memory_allocated() / (1024**3)

                print(f"SUCCESS! Allocated {allocated:.2f}GB")
                results[f"{size_gb}GB"] = "PASS"

                del tensor
                torch.cuda.empty_cache()

            except RuntimeError:
                print("FAILED - Out of memory")
                results[f"{size_gb}GB"] = "FAIL"
                break

        return results

    def compute_benchmark(self) -> Dict:
        """Benchmark compute performance"""
        print("\n[TEST 2] Compute Performance Benchmark")
        print("-" * 50)

        results = {}

        # Matrix multiplication benchmark
        sizes = [1024, 2048, 4096, 8192]

        for size in sizes:
            try:
                # Create random matrices
                A = torch.randn(size, size, device=self.device)
                B = torch.randn(size, size, device=self.device)

                # Warmup
                for _ in range(3):
                    C = torch.matmul(A, B)
                torch.cuda.synchronize()

                # Benchmark
                start = time.perf_counter()
                iterations = 10
                for _ in range(iterations):
                    C = torch.matmul(A, B)
                torch.cuda.synchronize()
                elapsed = time.perf_counter() - start

                avg_time = (elapsed / iterations) * 1000  # ms
                tflops = (2 * size**3) / (avg_time / 1000) / 1e12

                print(f"  Matrix {size}x{size}: {avg_time:.1f}ms, {tflops:.2f} TFLOPS")
                results[f"matmul_{size}"] = {"time_ms": avg_time, "tflops": tflops}

                # Cleanup
                del A, B, C
                torch.cuda.empty_cache()

            except RuntimeError:
                print(f"  Matrix {size}x{size}: Out of memory")
                results[f"matmul_{size}"] = {"time_ms": None, "tflops": None}

        return results

    def parallel_kernel_test(self) -> Dict:
        """Test parallel kernel execution"""
        print("\n[TEST 3] Parallel Kernel Execution")
        print("-" * 50)

        size = 10000
        iterations = 100

        # Create test data
        data = torch.randn(size, size, device=self.device)

        operations = {
            "exp": lambda x: torch.exp(x),
            "sin": lambda x: torch.sin(x),
            "sqrt": lambda x: torch.sqrt(torch.abs(x)),
            "tanh": lambda x: torch.tanh(x)
        }

        results = {}

        for op_name, op_func in operations.items():
            # Warmup
            for _ in range(5):
                _ = op_func(data)
            torch.cuda.synchronize()

            # Benchmark
            start = time.perf_counter()
            for _ in range(iterations):
                op_func(data)
            torch.cuda.synchronize()
            elapsed = time.perf_counter() - start

            throughput = (size * size * iterations) / elapsed / 1e9  # Giga-ops/sec
            print(f"  {op_name:6s}: {elapsed*1000:.1f}ms total, {throughput:.1f} Gops/s")
            results[op_name] = throughput

        return results

    def catalytic_lattice_3d(self, size: int = 128, steps: int = 50) -> Tuple[float, float]:
        """Run 3D catalytic lattice simulation"""
        print("\n[TEST 4] 3D Catalytic Lattice Simulation")
        print("-" * 50)
        print(f"  Lattice size: {size}x{size}x{size}")
        print(f"  Evolution steps: {steps}")

        # Initialize 3D lattice
        lattice = torch.rand(size, size, size, device=self.device)

        # 3D Laplacian kernel
        kernel = torch.zeros(1, 1, 3, 3, 3, device=self.device)
        kernel[0, 0, 1, 1, 0] = 1
        kernel[0, 0, 1, 1, 2] = 1
        kernel[0, 0, 1, 0, 1] = 1
        kernel[0, 0, 1, 2, 1] = 1
        kernel[0, 0, 0, 1, 1] = 1
        kernel[0, 0, 2, 1, 1] = 1
        kernel[0, 0, 1, 1, 1] = -6

        # Warmup
        for _ in range(10):
            lattice_batch = lattice.unsqueeze(0).unsqueeze(0)
            laplacian = torch.nn.functional.conv3d(lattice_batch, kernel, padding=1)
            lattice = lattice + 0.1 * laplacian.squeeze()
            lattice = torch.clamp(lattice, 0, 1)
        torch.cuda.synchronize()

        # Benchmark
        start = time.perf_counter()
        for step in range(steps):
            lattice_batch = lattice.unsqueeze(0).unsqueeze(0)
            laplacian = torch.nn.functional.conv3d(lattice_batch, kernel, padding=1)
            reaction = 0.05 * lattice * (1 - lattice) * (lattice - 0.3)
            lattice = lattice + 0.1 * laplacian.squeeze() + reaction
            lattice = torch.clamp(lattice, 0, 1)
        torch.cuda.synchronize()
        elapsed = time.perf_counter() - start

        throughput = steps / elapsed
        memory_mb = torch.cuda.memory_allocated() / (1024**2)

        print(f"  Time: {elapsed:.3f}s")
        print(f"  Throughput: {throughput:.1f} steps/second")
        print(f"  Memory used: {memory_mb:.1f} MB")

        return elapsed, throughput

    def run_full_benchmark(self):
        """Run complete benchmark suite"""
        print("[STARTING] Full GTX 1080 Benchmark Suite\n")

        # Memory test
        memory_results = self.memory_stress_test()

        # Compute test
        compute_results = self.compute_benchmark()

        # Parallel kernels
        kernel_results = self.parallel_kernel_test()

        # 3D Lattice
        lattice_time, lattice_throughput = self.catalytic_lattice_3d()

        # Summary
        print("\n" + "="*70)
        print("[SUMMARY] GTX 1080 Benchmark Results")
        print("="*70)

        print("\n[MEMORY] Maximum stable allocation:")
        for size, status in memory_results.items():
            if status == "PASS":
                print(f"  {size}: {status}")

        print("\n[COMPUTE] Peak performance:")
        max_tflops = max(
            r["tflops"] for r in compute_results.values()
            if r["tflops"] is not None
        )
        print(f"  Peak TFLOPS: {max_tflops:.2f}")

        print("\n[KERNELS] Throughput:")
        for op, gops in kernel_results.items():
            print(f"  {op}: {gops:.1f} Gops/s")

        print("\n[3D LATTICE] Performance:")
        print(f"  Throughput: {lattice_throughput:.1f} steps/s")

        print("\n[COMPLETE] Benchmark finished! Arrr!")


def main():
    """Main entry point"""
    benchmark = GPUBenchmark()
    benchmark.run_full_benchmark()


if __name__ == "__main__":
    main()
